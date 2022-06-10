/* ncap_dns.c - DNS filters for NCAP
 *
 * By: Paul Vixie, ISC, September 2007
 */

#ifndef lint
static const char rcsid[] = "$Id$";
static const char copyright[] =
	"Copyright (c) 2007 by Internet Systems Consortium, Inc. (\"ISC\")";
#endif

/*
 * Copyright (c) 2007 by Internet Systems Consortium, Inc. ("ISC")
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* Import. */

#include "ncap_pvt.h"
#include "ncap_port.h"
#include "ncap_port_net.h"

#include <sys/uio.h>

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <pcap.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ncap_list.h"

#ifdef DMALLOC
# include <dmalloc.h>
#endif

/* Data structures. */

typedef int (*sym_match_ptr)(unsigned, ncap_msg_ct);

typedef enum { ncap_initiator = 0, ncap_target = 1 } ncap_it_e;

struct symbol {
	const char *	sym;
	unsigned	val;
};

struct symtab {
	size_t		uni;
	sym_match_ptr	mat;
	struct symbol	tab[ZERO_LENGTH_ARRAY];
};

struct address {
	ISC_LINK(struct address)	link;
	ncap_np_e			type;
	union {
		struct in_addr		ip4;
		struct in6_addr		ip6;
	} ip;
};

struct address_list_selection {
	int		wanted;
	ncap_it_e	it;
	ISC_LIST(struct address) list;
};

struct myregex {
	int		not;
	regex_t		reg;
};

struct dns_param {
	const char *	text;
	const char *	bpf;
	unsigned	flag;
	unsigned	value;
};

struct dns_type {
	const char *	name;
	int		value;
};

/* Forward. */

static char *		lookup(ncap_t, const struct symtab *,
			       char, const char *);
static char *		bpf_match_hostlist(const char *, ncap_it_e, int);
static char *		bpf_match_param(unsigned, const struct dns_param *);
static int		match_dns(ncap_rule_ptr, ncap_msg_ct);
static int		match_initiator_target(ncap_rule_ptr, ncap_msg_ct);
static int		match_opcode(ncap_rule_ptr, ncap_msg_ct);
static int		match_qname(ncap_rule_ptr, ncap_msg_ct);
static int		match_qtype(ncap_rule_ptr, ncap_msg_ct);
static int		match_rcode(ncap_rule_ptr, ncap_msg_ct);
static int		match_sym(ncap_rule_ptr, ncap_msg_ct);
static int		sym_match_flags(unsigned, ncap_msg_ct);
#ifdef HAVE_LIBBIND
static int		match_regex(ncap_rule_ptr, ncap_msg_ct);
#endif

/* Macros. */

#ifndef MIN
#define MIN(a,b) ((a)<(b)?(a):(b))
#endif

#define	NCAP_DNS_NEG	0x80000000

#define NCAP_DNS_QR	0x00008000
#define NCAP_DNS_AA	0x00000400
#define NCAP_DNS_TC	0x00000200
#define NCAP_DNS_RD	0x00000100
#define NCAP_DNS_RA	0x00000080
#define NCAP_DNS_AD	0x00000020
#define NCAP_DNS_CD	0x00000010
#define	NCAP_DNS_FLAGS	(NCAP_DNS_QR|NCAP_DNS_AA|NCAP_DNS_TC|\
			 NCAP_DNS_RD|NCAP_DNS_RA|\
			 NCAP_DNS_AD|NCAP_DNS_CD)

#define NCAP_DNS_O_MASK	0x00007800
#define NCAP_DNS_O_SHIFT	11

#define NCAP_DNS_R_MASK		0xf

#define NCAP_DNS_O_QUERY	(1 << ns_o_query)
#define NCAP_DNS_O_NOTIFY	(1 << ns_o_notify)
#define NCAP_DNS_O_UPDATE	(1 << ns_o_update)

#define NCAP_DNS_R_NOERROR	(1 << ns_r_noerror)
#define NCAP_DNS_R_FORMERR	(1 << ns_r_formerr)
#define NCAP_DNS_R_SERVFAIL	(1 << ns_r_servfail)
#define NCAP_DNS_R_NXDOMAIN	(1 << ns_r_nxdomain)
#define NCAP_DNS_R_NOTIMPL	(1 << ns_r_notimpl)
#define NCAP_DNS_R_REFUSED	(1 << ns_r_refused)

#define REGEX_CFLAGS	(REG_EXTENDED | REG_NOSUB | REG_NEWLINE)

/* Private data. */

static struct symtab sym_flags = { 2, sym_match_flags, {
	{ "qr", NCAP_DNS_QR },
	{ "aa", NCAP_DNS_AA },
	{ "tc", NCAP_DNS_TC },
	{ "rd", NCAP_DNS_RD },
	{ "ra", NCAP_DNS_RA },
	{ "ad", NCAP_DNS_AD },
	{ "cd", NCAP_DNS_CD },
	{ NULL, 0 } } };

static struct dns_param param_opcodes[] = {
	{
		.text  = "query",
		.bpf   = "((udp[10] >> 3) & 0xf = 0)",
		.flag  = NCAP_DNS_O_QUERY,
		.value = ns_o_query
	},
	{
		.text  = "notify",
		.bpf   = "((udp[10] >> 3) & 0xf = 4)",
		.flag  = NCAP_DNS_O_NOTIFY,
		.value = ns_o_notify
	},
	{
		.text  = "update",
		.bpf   = "((udp[10] >> 3) & 0xf = 5)",
		.flag  = NCAP_DNS_O_UPDATE,
		.value = ns_o_update
	},
	{ NULL, NULL, 0, 0 }
};

static struct dns_param param_rcodes[] = {
	{
		.text  = "noerror",
		.bpf   = "((udp[11] & 0xf) = 0)",
		.flag  = NCAP_DNS_R_NOERROR,
		.value = ns_r_noerror
	},
	{
		.text  = "formerr",
		.bpf   = "((udp[11] & 0xf) = 1)",
		.flag  = NCAP_DNS_R_FORMERR,
		.value = ns_r_formerr
	},
	{
		.text  = "servfail",
		.bpf   = "((udp[11] & 0xf) = 2)",
		.flag  = NCAP_DNS_R_SERVFAIL,
		.value = ns_r_servfail
	},
	{
		.text  = "nxdomain",
		.bpf   = "((udp[11] & 0xf) = 3)",
		.flag  = NCAP_DNS_R_NXDOMAIN,
		.value = ns_r_nxdomain
	},
	{
		.text  = "notimpl",
		.bpf   = "((udp[11] & 0xf) = 4)",
		.flag  = NCAP_DNS_R_NOTIMPL,
		.value = ns_r_notimpl
	},
	{
		.text  = "refused",
		.bpf   = "((udp[11] & 0xf) = 5)",
		.flag  = NCAP_DNS_R_REFUSED,
		.value = ns_r_refused
	},
	{ NULL, NULL, 0, 0 }
};

static struct dns_type dns_types[] = {
	{ "A",			1 },
	{ "NS",			2 },
	{ "MD",			3 },
	{ "MF",			4 },
	{ "CNAME",		5 },
	{ "SOA",		6 },
	{ "MB",			7 },
	{ "MG",			8 },
	{ "MR",			9 },
	{ "NULL",		10 },
	{ "WKS",		11 },
	{ "PTR",		12 },
	{ "HINFO",		13 },
	{ "MINFO",		14 },
	{ "MX",			15 },
	{ "TXT",		16 },
	{ "RP",			17 },
	{ "AFSDB",		18 },
	{ "X25",		19 },
	{ "ISDN",		20 },
	{ "RT",			21 },
	{ "NSAP",		22 },
	{ "NSAP-PTR",		23 },
	{ "SIG",		24 },
	{ "KEY",		25 },
	{ "PX",			26 },
	{ "GPOS",		27 },
	{ "AAAA",		28 },
	{ "LOC",		29 },
	{ "NXT",		30 },
	{ "EID",		31 },
	{ "NIMLOC",		32 },
	{ "SRV",		33 },
	{ "ATMA",		34 },
	{ "NAPTR",		35 },
	{ "KX",			36 },
	{ "CERT",		37 },
	{ "A6",			38 },
	{ "DNAME",		39 },
	{ "SINK",		40 },
	{ "OPT",		41 },
	{ "APL",		42 },
	{ "DS",			43 },
	{ "SSHFP",		44 },
	{ "IPSECKEY",		45 },
	{ "RRSIG",		46 },
	{ "NSEC",		47 },
	{ "DNSKEY",		48 },
	{ "DHCID",		49 },
	{ "NSEC3",		50 },
	{ "NSEC3PARAM",		51 },
	{ "HIP",		55 },
	{ "NINFO",		56 },
	{ "RKEY",		57 },
	{ "SPF",		99 },
	{ "UINFO",		100 },
	{ "UID",		101 },
	{ "GID",		102 },
	{ "UNSPEC",		103 },
	{ "TKEY",		249 },
	{ "TSIG",		250 },
	{ "IXFR",		251 },
	{ "AXFR",		252 },
	{ "MAILB",		253 },
	{ "MAILA",		254 },
	{ NULL,			0 }
};

/* Export. */

/* Process a DNS filter term.
 *
 * Returns the BPF used to preselect such packets, "" if none, NULL if error.
 */
char *
ncap_filter_dns(ncap_t ncap, const char *term, char sep, const char *arg) {
	struct dns_param *dp;
	char *saveptr = NULL;
	char *word;
	char *tmp;
	size_t n;

	if (term == NULL || sep == '\0' || arg == NULL) {
		ncap_addrule(ncap, match_dns, NULL, 0U);
		return (strdup("udp port (53 or 5353)"
			       /*XXX"or tcp port (53 or 5353)"XXX*/));
	}

	n = strlen(term);

	if (strncmp(term, "flags", n) == 0)
		return (lookup(ncap, &sym_flags, sep, arg));

	else if (strncmp(term, "initiator", n) == 0 ||
		 strncmp(term, "target", n) == 0)
	{
		struct address_list_selection *als = malloc(sizeof *als);

		assert(als != NULL);
		memset(als, 0, sizeof *als);
		ISC_LIST_INIT(als->list);

		tmp = strdup(arg);
		als->wanted = (sep == '=');
		for (word = strtok_r(tmp, ",", &saveptr);
		     word != NULL;
		     word = strtok_r(NULL, ",", &saveptr))
		{
			struct address *addr = malloc(sizeof *addr);

			assert(addr != NULL);
			ISC_LINK_INIT(addr, link);
			ISC_LIST_APPEND(als->list, addr, link);
			if (inet_pton(AF_INET, word, &addr->ip.ip4) > 0) {
				addr->type = ncap_ip4;
			} else if (inet_pton(AF_INET6, word, &addr->ip.ip6)
				   > 0)
			{
				addr->type = ncap_ip6;
			} else {
				free(tmp);
				NCAP_SETERR("unparseable address");
				return (NULL);
			}
		}

		if (strncmp(term, "initiator", n) == 0) {
			als->it = ncap_initiator;
			ncap_addrule(ncap, match_initiator_target, als, 0U);
			return (bpf_match_hostlist(arg, ncap_initiator,
						   (sep == '#')));
		}
		if (strncmp(term, "target", n) == 0) {
			als->it = ncap_target;
			ncap_addrule(ncap, match_initiator_target, als, 0U);
			return (bpf_match_hostlist(arg, ncap_target,
						   (sep == '#')));
		}
	}

	else if (strncmp(term, "opcode", n) == 0) {
		unsigned *flags = malloc(sizeof *flags);

		assert(flags != NULL);
		*flags = 0;

		tmp = strdup(arg);
		if (sep == '#')
			*flags |= NCAP_DNS_NEG;
		for (word = strtok_r(tmp, ",", &saveptr);
		     word != NULL;
		     word = strtok_r(NULL, ",", &saveptr))
		{
			int recog = false;

			n = strlen(word);
			for (dp = param_opcodes; dp->text != NULL; dp++) {
				if (strncmp(word, dp->text, n) == 0) {
					*flags |= dp->flag;
					recog = true;
				}
			}
			if (!recog) {
				NCAP_SETERR("unrecognized opcode");
				free(tmp);
				return (NULL);
			}
		}
		free(tmp);
		ncap_addrule(ncap, match_opcode, flags, 0U);
		return (bpf_match_param(*flags, param_opcodes));
	}

	else if (strncmp(term, "rcode", n) == 0) {
		unsigned *flags = malloc(sizeof *flags);

		assert(flags != NULL);
		*flags = 0;

		tmp = strdup(arg);
		if (sep == '#')
			*flags |= NCAP_DNS_NEG;
		for (word = strtok_r(tmp, ",", &saveptr);
		     word != NULL;
		     word = strtok_r(NULL, ",", &saveptr))
		{
			int recog = false;

			if (isdigit(word[0])) {
				char *endptr;
				long rcode = strtoul(word, &endptr, 10);
				if (endptr[0] != '\0') {
					NCAP_SETERR("illegal numeric rcode");
					free(tmp);
					return (NULL);
				}
				if (rcode < 0 || rcode > 15) {
					NCAP_SETERR("invalid numeric rcode");
					free(tmp);
					return (NULL);
				}
				*flags |= (1 << rcode);
				recog = true;
			}

			if (recog) {
				continue;
			}

			n = strlen(word);
			for (dp = param_rcodes; dp->text != NULL; ++dp) {
				if (strncmp(word, dp->text, n) == 0) {
					*flags |= dp->flag;
					recog = true;
				}
			}
			if (!recog) {
				NCAP_SETERR("unrecognized rcode");
				free(tmp);
				return (NULL);
			}
		}
		free(tmp);
		ncap_addrule(ncap, match_rcode, flags, 0U);
		return (bpf_match_param(*flags, param_rcodes));
	}

	else if (strncmp(term, "regex", n) == 0) {
#ifdef HAVE_LIBBIND
		int flags = REGEX_CFLAGS;
		struct myregex *mr;
		char errbuf[128];
		char *expr;
		int i;

		mr = malloc(sizeof *mr);
		assert(mr != NULL);
		memset(mr, 0, sizeof *mr);
		mr->not = (sep == '#');

		tmp = strdup(arg);

		expr = strtok_r(tmp, "/", &saveptr);
		tmp = strtok_r(NULL, "/", &saveptr);
		while (tmp && *tmp != '\0') {
			if (*tmp++ == 'i')
				flags |= REG_ICASE;
			/* more? */
		}

		i = regcomp(&mr->reg, expr, flags);
		if (i != 0) {
			regerror(i, &mr->reg, errbuf, sizeof errbuf);
			NCAP_SETERR(errbuf);
			return (NULL);
		}

		ncap_addrule(ncap, match_regex, mr, 0U);
#else
		NCAP_SETERR("regex filtering disabled due to lack of libbind");
		return (NULL);
#endif
	}

	else if (strncmp(term, "qname", n) == 0) {
		char *qname;

		qname = strdup(arg);
		assert(qname != NULL);

		ncap_addrule(ncap, match_qname, qname, 0U);
	}

	else if (strncmp(term, "qtype", n) == 0) {
		struct dns_type *dt;
		unsigned *qtype;

		qtype = NULL;

		for (dt = dns_types; dt->name != NULL; dt++) {
			if (strcasecmp(dt->name, arg) == 0) {
				qtype = malloc(sizeof *qtype);
				assert(qtype != NULL);
				*qtype = dt->value;
			}
		}
		if (qtype == NULL) {
			NCAP_SETERR("unknown qtype");
			return (NULL);
		}

		ncap_addrule(ncap, match_qtype, qtype, 0U);
	}

	return (strdup(""));
}

/* Private. */

static char *
bpf_match_hostlist(const char *arg, ncap_it_e it, int invert) {
	char *word, *bpf, *tmp;
	char *saveptr = NULL;

	if (arg == NULL)
		return (strdup(""));

	tmp = strdup(arg);
	word = strtok_r(tmp, ",", &saveptr);
	ncap_asprintf(&bpf,
		      "%s%shost (%s",
		      invert ? "not " : "",
		      (it == ncap_target) ? "dst " : "src ",
		      word);
	while ((word = strtok_r(NULL, ",", &saveptr))) {
		char *t;

		ncap_asprintf(&t, " or %s", word);
		bpf = realloc(bpf, strlen(bpf) + strlen(t) + 1);
		strcat(bpf, t);
	}
	bpf = realloc(bpf, strlen(bpf) + 2);
	strcat(bpf, ")");
	return (bpf);
}

static char *
bpf_match_param(unsigned flags, const struct dns_param *params) {
	const struct dns_param *dp;
	char *bpf = strdup("");
	int n, len;

	assert(bpf != NULL);
	len = 1 + strlen(bpf);
	n = 0;

	if (flags & NCAP_DNS_NEG) {
		len += strlen("not (");
		bpf = realloc(bpf, len);
		strcat(bpf, "not (");
	} else {
		len += strlen("(");
		bpf = realloc(bpf, len);
		strcat(bpf, "(");
	}

	for (dp = params; dp->bpf != NULL; dp++) {
		if ((flags & dp->flag) != 0) {
			len += strlen(dp->bpf);
			len += n > 0 ? strlen(" or ") : 0;
			bpf = realloc(bpf, len);
			if (n > 0)
				strcat(bpf, " or ");
			strcat(bpf, dp->bpf);
			n++;
		}
	}

	len += strlen(")");
	bpf = realloc(bpf, len);
	strcat(bpf, ")");

	return (bpf);
}

static char *
lookup(ncap_t ncap, const struct symtab *table, char sep, const char *arg) {
	char *word, *tmp;
	char *saveptr = NULL;
	sym_match_ptr *payload;
	unsigned argument;

	tmp = strdup(arg);
	argument = 0U;

	for (word = strtok_r(tmp, ",", &saveptr);
	     word != NULL;
	     word = strtok_r(NULL, ",", &saveptr))
	{
		int i;

		for (i = 0; table->tab[i].sym != NULL; i++) {
			size_t n = strlen(table->tab[i].sym);

			if (n < table->uni)
				n = table->uni;
			if (strncmp(word, table->tab[i].sym, n) == 0)
				break;
		}
		if (table->tab[i].sym == NULL) {
			NCAP_SETERR("unrecognized filter");
			free(tmp);
			return (NULL);
		}
		argument |= table->tab[i].val;
	}
	if (argument == 0U) {
		NCAP_SETERR("no filter arguments");
		free(tmp);
		return (NULL);
	}
	if (sep == '#')
		argument |= NCAP_DNS_NEG;
	free(tmp);
	payload = malloc(sizeof *payload);
	*payload = table->mat;
	ncap_addrule(ncap, match_sym, payload, argument);
	return (strdup(""));	/* XXX could be more specific here */
}

static int
match_dns(ncap_rule_ptr rule __attribute__((unused)), ncap_msg_ct msg) {
	return ((msg->np == ncap_ip4 || msg->np == ncap_ip6) &&
		((msg->tp == ncap_udp &&
		  (msg->tpu.udp.sport == 53 || msg->tpu.udp.sport == 5353 ||
		   msg->tpu.udp.dport == 53 || msg->tpu.udp.dport == 5353))
	/*XXX||  (msg->tp == ncap_tcp &&
		  (msg->tpu.tcp.sport == 53 || msg->tpu.tcp.sport == 5353 ||
		   msg->tpu.tcp.dport == 53 || msg->tpu.tcp.dport == 5353))
	  XXX*/
		 ));
}

static int
match_initiator_target(ncap_rule_ptr rule, ncap_msg_ct msg) {
	struct address_list_selection *als = rule->payload;
	struct address *addr;
	
	/* XXX this runs in O(n) */
	for (addr = ISC_LIST_HEAD(als->list);
	     addr != NULL;
	     addr = ISC_LIST_NEXT(addr, link))
	{
		if (addr->type == msg->np) {
			if (addr->type == ncap_ip4) {
				if (memcmp(&addr->ip.ip4,
					   als->it == ncap_target ?
						&msg->npu.ip4.dst :
						&msg->npu.ip4.src,
					   IN4SZ) == 0)
					return (als->wanted);
			} else if (addr->type == ncap_ip6) {
				if (memcmp(&addr->ip.ip6,
					   als->it == ncap_target ?
						&msg->npu.ip6.dst :
						&msg->npu.ip6.src,
					   IN6SZ) == 0)
					return (als->wanted);
			} else {
				assert(0);
			}
		}
	}
	
	return (!als->wanted);
}

static int
match_opcode(ncap_rule_ptr rule, ncap_msg_ct msg) {
	const u_char *pkt = msg->payload;
	unsigned f = *((int *) rule->payload);
	unsigned op;
	
	pkt += 2;	/* Skip the message ID. */
	NCAP_GET16(op, pkt);

	op &= NCAP_DNS_O_MASK;
	op >>= NCAP_DNS_O_SHIFT;

	return ((f & NCAP_DNS_NEG) != 0) ^
		((f & NCAP_DNS_O_QUERY  && op == ns_o_query)  ||
		 (f & NCAP_DNS_O_UPDATE && op == ns_o_update) ||
		 (f & NCAP_DNS_O_NOTIFY && op == ns_o_notify));
}

static int
match_qname(ncap_rule_ptr rule, ncap_msg_ct nmsg) {
	char *qname = rule->payload;
	const u_char *pkt = nmsg->payload;
	ns_msg msg;
	ns_rr rr;

	if (ns_initparse(pkt, nmsg->paylen, &msg) < 0)
		return (0);
	if (ns_parserr(&msg, ns_s_qd, 0, &rr) < 0)
		return (0);
	if (strcasecmp(qname, ns_rr_name(rr)) == 0)
		return (1);

	return (0);
}

static int
match_qtype(ncap_rule_ptr rule, ncap_msg_ct nmsg) {
	const u_char *pkt = nmsg->payload;
	unsigned qtype = *((unsigned *) rule->payload);
	ns_msg msg;
	ns_rr rr;

	if (ns_initparse(pkt, nmsg->paylen, &msg) < 0)
		return (0);
	if (ns_parserr(&msg, ns_s_qd, 0, &rr) < 0)
		return (0);
	if (ns_rr_type(rr) == qtype)
		return (1);

	return (0);
}

static int
match_rcode(ncap_rule_ptr rule, ncap_msg_ct msg) {
	unsigned f = *((int *) rule->payload);
	const u_char *pkt = msg->payload;
	unsigned r;

	pkt += 2;	/* Skip the message ID. */
	NCAP_GET16(r, pkt);

	if ((r & NCAP_DNS_QR) == 0)
		return (0);

	r &= NCAP_DNS_R_MASK;

	return ((f & NCAP_DNS_NEG) != 0) ^
		((f & NCAP_DNS_R_NOERROR  && r == ns_r_noerror)  ||
		 (f & NCAP_DNS_R_FORMERR  && r == ns_r_formerr)  ||
		 (f & NCAP_DNS_R_SERVFAIL && r == ns_r_servfail) ||
		 (f & NCAP_DNS_R_NXDOMAIN && r == ns_r_nxdomain) ||
		 (f & NCAP_DNS_R_NOTIMPL  && r == ns_r_notimpl)  ||
		 (f & NCAP_DNS_R_REFUSED  && r == ns_r_refused));
}

#ifdef HAVE_LIBBIND
static int
match_regex(ncap_rule_ptr rule, ncap_msg_ct nmsg) {
	struct myregex *mr = rule->payload;
	const u_char *pkt = nmsg->payload;
	ns_msg msg;
	char *pres;
	ns_sect s;
	int matches = 0;

	if (ns_initparse(pkt, nmsg->paylen, &msg) < 0)
		return (0);
	
	for (s = ns_s_qd; s < ns_s_max; ++s) {
		const char *look;
		int n;
		ns_rr rr;

		pres = alloca(nmsg->paylen * 4);
		assert(pres != NULL);

		for (n = 0; n < ns_msg_count(msg, s); ++n) {
			if (ns_parserr(&msg, s, n, &rr) < 0)
				continue;
			if (s == ns_s_qd)
				look = ns_rr_name(rr);
			else {
				if (ns_sprintrr(&msg, &rr, NULL, ".",
					        pres, nmsg->paylen * 4) < 0)
					continue;
				look = pres;
			}
			if (regexec(&mr->reg, look, 0, NULL, 0) == 0)
				matches += 1;
		}
	}
	if (mr->not)
		return (matches == 0);
	else
		return (matches > 0);
}
#endif

static int
match_sym(ncap_rule_ptr rule, ncap_msg_ct msg) {
	sym_match_ptr *mat = rule->payload;

	return ((**mat)(rule->argument, msg));
}

static int
sym_match_flags(unsigned argument, ncap_msg_ct msg) {
	const u_char *pkt = msg->payload;
	unsigned flags;

	pkt += 2;	/* Skip the message ID. */
	NCAP_GET16(flags, pkt);

	flags &= NCAP_DNS_FLAGS;
	if ((argument & NCAP_DNS_NEG) != 0)
		return ((flags & (argument & ~NCAP_DNS_NEG)) == 0);
	else
		return ((flags & argument) != 0);
}
