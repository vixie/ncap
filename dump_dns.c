/* dump_dns.c - library function to emit decoded dns message on a FILE.
 *
 * By: Paul Vixie, ISC, October 2007
 */

#ifndef lint
static const char rcsid[] = "$Id$";
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

#include "ncap_port.h"
#include "ncap_port_net.h"

#include <sys/time.h>

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "ncap.h"
#include "dump_dns.h"

#ifndef HAVE_LIBBIND
void
dump_dns(const u_char *payload __attribute__((unused)),
	 size_t paylen __attribute__((unused)),
	  FILE *trace, const char *endline)
{
	fprintf(trace, " %sNO LIBBIND", endline);
}

void
dump_icmpdns(const u_char *payload __attribute__((unused)),
	     size_t paylen __attribute__((unused)),
	     FILE *trace, const char *endline)
{
	fprintf(trace, " %sNO LIBBIND", endline);
}
#else

static const char *_res_opcodes[] = {
	"QUERY",
	"IQUERY",
	"CQUERYM",
	"CQUERYU",
	"NOTIFY",
	"UPDATE",
	"6",
	"7",
	"8",
	"9",
	"10",
	"11",
	"12",
	"13",
	"ZONEINIT",
	"ZONEREF",
};

void
dump_dns(const u_char *payload, size_t paylen,
	 FILE *trace, const char *endline)
{
	unsigned opcode, rcode, id;
	const char *sep, *rcp;
	char rct[100];
	ns_msg msg;

	fprintf(trace, " %sdns ", endline);
	if (ns_initparse(payload, paylen, &msg) < 0) {
		fputs(strerror(errno), trace);
		return;
	}
	opcode = ns_msg_getflag(msg, ns_f_opcode);
	rcode = ns_msg_getflag(msg, ns_f_rcode);
	id = ns_msg_id(msg);
	if ((rcp = dump_dns_rcode(rcode)) == NULL) {
		sprintf(rct, "CODE%u", rcode);
		rcp = rct;
	}
	fprintf(trace, "%s,%s,%u", _res_opcodes[opcode], rcp, id);
	sep = ",";
#define FLAG(t,f) if (ns_msg_getflag(msg, f)) { \
			fprintf(trace, "%s%s", sep, t); \
			sep = "|"; \
		  }
	FLAG("qr", ns_f_qr);
	FLAG("aa", ns_f_aa);
	FLAG("tc", ns_f_tc);
	FLAG("rd", ns_f_rd);
	FLAG("ra", ns_f_ra);
	FLAG("z", ns_f_z);
	FLAG("ad", ns_f_ad);
	FLAG("cd", ns_f_cd);
#undef FLAG
	dump_dns_sect(&msg, ns_s_qd, trace, endline);
	dump_dns_sect(&msg, ns_s_an, trace, endline);
	dump_dns_sect(&msg, ns_s_ns, trace, endline);
	dump_dns_sect(&msg, ns_s_ar, trace, endline);
}

void
dump_icmpdns(const u_char *payload, size_t paylen, FILE *trace,
	     const char *endline)
{
	char saddr[INET_ADDRSTRLEN], daddr[INET_ADDRSTRLEN];
	const struct ip *ih;
	const struct tcphdr *th;
	const struct udphdr *uh;
	const u_char *pkt;
	size_t len, dns_len;
	u_char *dns_pkt;
	unsigned short sport, dport;

	len = paylen;
	pkt = payload;

	/* icmp */
	if (len >= 4) {
		pkt += 4;
		len -= 4;
	}

	/* ip header */
	if (len >= sizeof *ih)
		ih = (const struct ip *) pkt;
	else
		return;

	/* ipv4? XXX handle ipv6/icmpv6? */
	if (ih->ip_v != 4U)
		return;

	if (len >= 4U * ih->ip_hl) {
		pkt += 4U * ih->ip_hl;
		len -= 4U * ih->ip_hl;
	} else
		return;

	inet_ntop(AF_INET, &ih->ip_src, saddr, sizeof saddr);
	inet_ntop(AF_INET, &ih->ip_dst, daddr, sizeof daddr);

	if (ih->ip_p == IPPROTO_UDP) {
		/* udp header */
		if (len >= sizeof *uh) {
			uh = (const struct udphdr *) pkt;
			pkt += sizeof *uh;
			len -= sizeof *uh;
		} else
			return;

		sport = ntohs(uh->uh_sport);
		dport = ntohs(uh->uh_dport);

		fprintf(trace, " %s[%s].%d [%s].%d udp",
			endline, saddr, sport, daddr, dport);

		/* dns? */
		if (sport != 53 && dport != 53)
			return;

		/* enough for a complete dns header? */
		if (len >= NS_HFIXEDSZ) {
			/* the dns portion of the icmp payload may be truncated.
			 * pad it out to fool ns_initparse(). */
			dns_len = ntohs(ih->ip_len) - 4U * ih->ip_hl -
					sizeof *uh;
			dns_pkt = calloc(1, dns_len);
			assert(dns_pkt != NULL);
			memcpy(dns_pkt, pkt, dns_len);
			dump_dns(dns_pkt, dns_len, trace, endline);
			free(dns_pkt);
		}
	} else if (ih->ip_p == IPPROTO_TCP) {
		if (len >= sizeof *th) {
			th = (const struct tcphdr *) pkt;
			pkt += sizeof *th;
			len -= sizeof *th;
		} else
			return;

		sport = ntohs(th->th_sport);
		dport = ntohs(th->th_dport);

		fprintf(trace, " %s[%s].%d [%s].%d tcp [%s%s%s%s%s%s]",
			endline, saddr, sport, daddr, dport,
			th->th_flags & TH_FIN ? "F" : "",
			th->th_flags & TH_SYN ? "S" : "",
			th->th_flags & TH_RST ? "R" : "",
			th->th_flags & TH_PUSH ? "P" : "",
			th->th_flags & TH_ACK ? "A" : "",
			th->th_flags & TH_URG ? "U" : "");
	}
}

void
dump_dns_sect(ns_msg *msg, ns_sect sect, FILE *trace, const char *endline) {
	int rrnum, rrmax;
	const char *sep;
	ns_rr rr;

	rrmax = ns_msg_count(*msg, sect);
	if (rrmax == 0) {
		fputs(" 0", trace);
		return;
	}
	fprintf(trace, " %s%d", endline, rrmax);
	sep = "";
	for (rrnum = 0; rrnum < rrmax; rrnum++) {
		if (ns_parserr(msg, sect, rrnum, &rr)) {
			fputs(strerror(errno), trace);
			return;
		}
		fprintf(trace, " %s", sep);
		dump_dns_rr(msg, &rr, sect, trace);
		sep = endline;
	}
}

void
dump_dns_rr(ns_msg *msg, ns_rr *rr, ns_sect sect, FILE *trace) {
	char ct[100], tt[100];
	const char *cp, *tp;
	unsigned class, type;

	class = ns_rr_class(*rr);
	type = ns_rr_type(*rr);
	if ((cp = dump_dns_class(class)) == NULL) {
		sprintf(ct, "CLASS%u", class);
		cp = ct;
	}
	if ((tp = dump_dns_type(type)) == NULL) {
		sprintf(tt, "TYPE%u", type);
		tp = tt;
	}
	fprintf(trace, "%s,%s,%s", ns_rr_name(*rr), cp, tp);
	if (sect == ns_s_qd)
		return;
	fprintf(trace, ",%lu", (u_long)ns_rr_ttl(*rr));
	dump_dns_rd(ns_msg_base(*msg), ns_msg_end(*msg), type,
		    ns_rr_rdata(*rr), ns_rr_rdlen(*rr),
		    trace);
}

void
dump_dns_rd(const u_char *msg, const u_char *eom, unsigned type,
	    const u_char *rdata, unsigned rdlen,
	    FILE *trace)
{
	const char uncompress_error[] = "..name.error..";
	char buf[NS_MAXDNAME];
	const char *sep;
	uint32_t soa[5];
	uint16_t mx;
	int n;

	switch (type) {
	case ns_t_soa:
		n = ns_name_uncompress(msg, eom, rdata, buf, sizeof buf);
		if (n < 0)
			strcpy(buf, uncompress_error);
		putc(',', trace);
		fputs(buf, trace);
		rdata += n;
		n = ns_name_uncompress(msg, eom, rdata, buf, sizeof buf);
		if (n < 0)
			strcpy(buf, uncompress_error);
		putc(',', trace);
		fputs(buf, trace);
		rdata += n;
		if (eom - rdata < 5*NS_INT32SZ)
			goto error;
		for (n = 0; n < 5; n++)
			NCAP_GET32(soa[n], rdata);
		sprintf(buf, "%u,%u,%u,%u,%u",
			soa[0], soa[1], soa[2], soa[3], soa[4]);
		break;
	case ns_t_a:
		inet_ntop(AF_INET, rdata, buf, sizeof buf);
		break;
	case ns_t_aaaa:
		inet_ntop(AF_INET6, rdata, buf, sizeof buf);
		break;
	case ns_t_txt:
		fputs(",[", trace);
		sep = "";
		while (rdlen > 0) {
			unsigned txtl = *rdata++;

			rdlen--;
			if (txtl > rdlen) {
				putc('?', trace);
				break;
			}
			fputs(sep, trace);
			sep = ",";
			putc('"', trace);
			while (txtl-- > 0) {
				int ch = *rdata++;

				rdlen--;
				if (isascii(ch) && isprint(ch)) {
					if (strchr("],\\\"\040", ch) != NULL)
						putc('\\', trace);
					putc(ch, trace);
				} else {
					fprintf(trace, "\\%03o", ch);
				}
			}
			putc('"', trace);
		}
		putc(']', trace);
		buf[0] = '\0';
		break;
	case ns_t_mx:
		NCAP_GET16(mx, rdata);
		fprintf(trace, ",%u", mx);
		/* FALLTHROUGH */
	case ns_t_ns:
	case ns_t_ptr:
	case ns_t_cname:
		n = ns_name_uncompress(msg, eom, rdata, buf, sizeof buf);
		if (n < 0)
			strcpy(buf, uncompress_error);
		break;
	default:
 error:
		sprintf(buf, "[%u]", rdlen);
	}
	if (buf[0] != '\0') {
		putc(',', trace);
		fputs(buf, trace);
	}
}

const char *
dump_dns_rcode(unsigned rcode) {
	switch (rcode) {
	case ns_r_noerror:	return "NOERROR";
	case ns_r_formerr:	return "FORMERR";
	case ns_r_servfail:	return "SERVFAIL";
	case ns_r_nxdomain:	return "NXDOMAIN";
	case ns_r_notimpl:	return "NOTIMPL";
	case ns_r_refused:	return "REFUSED";
	case ns_r_yxdomain:	return "YXDOMAIN";
	case ns_r_yxrrset:	return "YXRRSET";
	case ns_r_nxrrset:	return "NXRRSET";
	case ns_r_notauth:	return "NOTAUTH";
	case ns_r_notzone:	return "NOTZONE";
	default:		break;
	}
	return (NULL);
}

const char *
dump_dns_type(unsigned type) {
	switch (type) {
	case ns_t_a:		return "A";
	case ns_t_ns:		return "NS";
	case ns_t_cname:	return "CNAME";
	case ns_t_soa:		return "SOA";
	case ns_t_mb:		return "MB";
	case ns_t_mg:		return "MG";
	case ns_t_mr:		return "MR";
	case ns_t_null:		return "NULL";
	case ns_t_wks:		return "WKS";
	case ns_t_ptr:		return "PTR";
	case ns_t_hinfo:	return "HINFO";
	case ns_t_minfo:	return "MINFO";
	case ns_t_mx:		return "MX";
	case ns_t_txt:		return "TXT";
	case ns_t_rp:		return "RP";
	case ns_t_afsdb:	return "AFSDB";
	case ns_t_x25:		return "X25";
	case ns_t_isdn:		return "ISDN";
	case ns_t_rt:		return "RT";
	case ns_t_nsap:		return "NSAP";
	case ns_t_nsap_ptr:	return "NSAP_PTR";
	case ns_t_sig:		return "SIG";
	case ns_t_key:		return "KEY";
	case ns_t_px:		return "PX";
	case ns_t_gpos:		return "GPOS";
	case ns_t_aaaa:		return "AAAA";
	case ns_t_loc:		return "LOC";
	case ns_t_axfr:		return "AXFR";
	case ns_t_mailb:	return "MAILB";
	case ns_t_maila:	return "MAILA";
	case ns_t_any:		return "ANY";
	default:		break;
	}
	return NULL;
}

const char *
dump_dns_class(unsigned class) {
	switch (class) {
	case ns_c_in:		return "IN";
	case ns_c_hs:		return "HS";
	case ns_c_any:		return "ANY";
	default:		break;
	}
	return NULL;
}

#endif /*HAVE_LIBBIND*/
