/* ncap_icmp.c - ICMP filters for NCAP
 */

#ifndef lint
static const char rcsid[] = "$Id$";
static const char copyright[] =
	"Copyright (c) 2008 by Internet Systems Consortium, Inc. (\"ISC\")";
#endif

/*
 * Copyright (c) 2008 by Internet Systems Consortium, Inc. ("ISC")
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
#include <errno.h>
#include <fcntl.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef DMALLOC
# include <dmalloc.h>
#endif

#include "ncap_list.h"

/* Data structures. */

struct icmp_param {
	const char *	text;
	const char *	bpf;
	unsigned	value;
};

/* Forward. */

static int	match_icmp(ncap_rule_ptr, ncap_msg_ct); 
static int	match_icmptype(ncap_rule_ptr, ncap_msg_ct msg);
static int	match_icmptype_num(ncap_rule_ptr, ncap_msg_ct msg);
static int	match_icmpcode(ncap_rule_ptr, ncap_msg_ct msg);
static char *	bpf_match_param(unsigned, const struct icmp_param *);
static char *	bpf_match_icmptype(unsigned, int);
static char *	bpf_match_icmpcode(unsigned, int);

/* Constants. */

#ifndef MIN
#define MIN(a,b) ((a)<(b)?(a):(b))
#endif

/* Macros. */

#define	NCAP_ICMP_NEG	0x80000000

/* Private data. */

static struct icmp_param param_types[] = {
	{
		.text  = "echoreply",
		.bpf   = "(icmp[icmptype] = icmp-echoreply)",
		.value = 0
	},
	{
		.text  = "unreach",
		.bpf   = "(icmp[icmptype] = icmp-unreach)",
		.value = 3
	},
	{
		.text  = "sourcequench",
		.bpf   = "(icmp[icmptype] = icmp-sourcequench)",
		.value = 4
	},
	{
		.text  = "redirect",
		.bpf   = "(icmp[icmptype] = icmp-redirect)",
		.value = 5
	},
	{
		.text  = "echorequest",
		.bpf   = "(icmp[icmptype] = icmp-echo)",
		.value = 8
	},
	{
		.text  = "routeradvert",
		.bpf   = "(icmp[icmptype] = icmp-routeradvert)",
		.value = 9
	},
	{
		.text  = "routersolicit",
		.bpf   = "(icmp[icmptype] = icmp-routersolicit)",
		.value = 10
	},
	{
		.text  = "timxceed",
		.bpf   = "(icmp[icmptype] = icmp-timxceed)",
		.value = 11
	},
	{
		.text  = "paramproblem",
		.bpf   = "(icmp[icmptype] = icmp-paramprob)",
		.value = 12
	},
	{
		.text  = "tstamprequest",
		.bpf   = "(icmp[icmptype] = icmp-tstamp)",
		.value = 13
	},
	{
		.text  = "tstampreply",
		.bpf   = "(icmp[icmptype] = icmp-tstampreply)",
		.value = 14
	},
	{
		.text  = "inforeq",
		.bpf   = "(icmp[icmptype] = icmp-ireq)",
		.value = 15
	},
	{
		.text  = "inforeply",
		.bpf   = "(icmp[icmptype] = icmp-ireqreply)",
		.value = 16
	},
	{
		.text  = "maskreq",
		.bpf   = "(icmp[icmptype] = icmp-maskreq)",
		.value = 17
	},
	{
		.text  = "maskreply",
		.bpf   = "(icmp[icmptype] = icmp-maskreply)",
		.value = 18
	},
	{
		.text  = "traceroute",
		.bpf   = "(icmp[icmptype] = 30)",
		.value = 30
	},
	/* XXX more types require a wider flags field */
	{ NULL, NULL, 0 }
};

/* Export. */

/* Process an ICMP filter term.
 *
 * Returns the BPF used to preselect such packets, "" if none, NULL if error.
 */
char *
ncap_filter_icmp(ncap_t ncap, const char *term, char sep, const char *arg) {
	struct icmp_param *ip;
	char *saveptr = NULL;
	char *word;
	char *tmp;
	size_t n;

	if (term == NULL || sep == '\0' || arg == NULL) {
		ncap_addrule(ncap, match_icmp, NULL, 0U);
		return (strdup("icmp"));
	}

	n = strlen(term);

	if (strncmp(term, "type", n) == 0) {
		unsigned type;
		unsigned *flags = calloc(1, sizeof *flags);
		assert(flags != NULL);

		type = strtoul(arg, &tmp, 0);
		if (*tmp != '\0') {
			/* symbolic icmp type */
			tmp = strdup(arg);
			if (sep == '#')
				*flags |= NCAP_ICMP_NEG;
			for (word = strtok_r(tmp, ",", &saveptr);
			     word != NULL;
			     word = strtok_r(NULL, ",", &saveptr))
			{
				int recog = false;
				n = strlen(word);
				for (ip = param_types; ip->text != NULL; ip++) {
					if (strncmp(word, ip->text, n) == 0) {
						*flags |= 1 << ip->value;
						recog = true;
					}
				}
				if (!recog) {
					NCAP_SETERR("unrecognized icmp type");
					free(tmp);
					return (NULL);
				}
			}
			free(tmp);
			ncap_addrule(ncap, match_icmptype, flags, 0U);
			return (bpf_match_param(*flags, param_types));
		} else {
			/* numeric icmp type */
			unsigned *ptype = malloc(sizeof *ptype);
			assert(ptype != NULL);
			*ptype = type;
			ncap_addrule(ncap, match_icmptype_num, ptype, sep == '#');
			return (bpf_match_icmptype(type, sep == '#'));

		}
	} else if (strncmp(term, "code", n) == 0) {
		unsigned *code = calloc(1, sizeof *code);
		assert(code != NULL);
		*code = strtoul(arg, &tmp, 0);
		if (*tmp != '\0') {
			NCAP_SETERR("invalid icmp code");
			free(code);
			return (NULL);
		}
		ncap_addrule(ncap, match_icmpcode, code, sep == '#');
		return (bpf_match_icmpcode(*code, sep == '#'));
	}

	return (strdup(""));
}

/* Private. */

static int
match_icmp(ncap_rule_ptr rule __attribute__((unused)), ncap_msg_ct msg) {
	return ((msg->np == ncap_ip4 || msg->np == ncap_ip6) &&
		(msg->tp == ncap_icmp));
}

static int
match_icmptype(ncap_rule_ptr rule, ncap_msg_ct msg) {
	struct icmp_param *ip;
	int res = false;
	unsigned flags = *((int *) rule->payload);
	
	for (ip = param_types; ip->text != NULL; ip++) {
		if (flags & (1 << ip->value) &&
		    msg->tpu.icmp.type == ip->value)
		{
			res = true;
			break;
		}
	}
	return (((flags & NCAP_ICMP_NEG) != 0) ^ res);
}

static int
match_icmptype_num(ncap_rule_ptr rule, ncap_msg_ct msg) {
	unsigned type = *((unsigned *) rule->payload);
	if (rule->argument == true) /* invert */
		return (type != msg->tpu.icmp.type);
	else
		return (type == msg->tpu.icmp.type);
}

static int
match_icmpcode(ncap_rule_ptr rule, ncap_msg_ct msg) {
	unsigned code = *((unsigned *) rule->payload);
	if (rule->argument == true) /* invert */
		return (code != msg->tpu.icmp.code);
	else
		return (code == msg->tpu.icmp.code);
}

static char *
bpf_match_icmptype(unsigned type, int invert) {
	char *bpf;
	ncap_asprintf(&bpf, "(icmp[icmptype] %s= %u)", invert ? "!" : "", type);
	assert(bpf != NULL);
	return (bpf);
}

static char *
bpf_match_icmpcode(unsigned code, int invert) {
	char *bpf;
	ncap_asprintf(&bpf, "(icmp[icmpcode] %s= %u)", invert ? "!" : "", code);
	assert(bpf != NULL);
	return (bpf);
}

/* XXX code mostly duplicated from ncap_dns */
static char *
bpf_match_param(unsigned flags, const struct icmp_param *params) {
	const struct icmp_param *ip;
	char *bpf = strdup("");
	int n, len;

	assert(bpf != NULL);
	len = 1 + strlen(bpf);
	n = 0;

	if (flags & NCAP_ICMP_NEG) {
		len += strlen("not (");
		bpf = realloc(bpf, len);
		strcat(bpf, "not (");
	} else {
		len += strlen("(");
		bpf = realloc(bpf, len);
		strcat(bpf, "(");
	}

	for (ip = params; ip->bpf != NULL; ip++) {
		if ((flags & (1 << ip->value)) != 0) {
			len += strlen(ip->bpf);
			len += n > 0 ? strlen(" or ") : 0;
			bpf = realloc(bpf, len);
			if (n > 0)
				strcat(bpf, " or ");
			strcat(bpf, ip->bpf);
			n++;
		}
	}

	len += strlen(")");
	bpf = realloc(bpf, len);
	strcat(bpf, ")");

	return (bpf);
}
