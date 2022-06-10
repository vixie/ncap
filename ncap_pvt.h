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

#ifndef __ncap_pvt_h
#define __ncap_pvt_h 1

#define ISC_CHECK_NONE 1

#include "asprintf.h"
#include "ncap_port.h"
#include "ncap.h"
#include "ipreasm.h"

#include <sys/types.h>

#include <pcap.h>

#include "ncap_list.h"

#define	IN4SZ		4
#define	IN6SZ		16
#define	BUFSZ		4096

struct ncap_if {
	ISC_LINK(struct ncap_if)  link;
	ncap_t			ncap;
	pcap_t *		pcap;
	int			dlt;
	int			fdes;
	int *			vlans;
	int			nvlan;
	char *			label;
};
typedef struct ncap_if *ncap_if_ptr;
typedef ISC_LIST(struct ncap_if) ncap_if_list;

struct ncap_nf {
	ISC_LINK(struct ncap_nf)  link;
	ncap_t			ncap;
	int			fdes;
	char *			label;
	unsigned		vers;
	u_char			fb[BUFSZ];
	size_t			fblen;
	unsigned		fbcur;
	u_char			fixedbuf[NCAP_MSGHDR];
	u_char *		varbuf;
	size_t			varsiz, siz;
	size_t			len, netlen, tplen;
	int			saving;
	struct ncap_msg		msg;
};
typedef struct ncap_nf *ncap_nf_ptr;
typedef ISC_LIST(struct ncap_nf) ncap_nf_list;

struct ncap_pf {
	ISC_LINK(struct ncap_pf)  link;
	ncap_t			ncap;
	FILE *			fp;
	char *			label;
	pcap_t *		pcap;
	int			fdes;
	int			dlt;
};
typedef struct ncap_pf *ncap_pf_ptr;
typedef ISC_LIST(struct ncap_pf) ncap_pf_list;

struct ncap_dg {
	ISC_LINK(struct ncap_dg)  link;
	ncap_t			ncap;
	int			fdes;
	unsigned		vers;
	char *			label;
};
typedef struct ncap_dg *ncap_dg_ptr;
typedef ISC_LIST(struct ncap_dg) ncap_dg_list;

struct ncap_rule;
typedef struct ncap_rule *ncap_rule_ptr;
typedef ISC_LIST(struct ncap_rule) ncap_rule_list;
typedef int (*ncap_match_ptr)(ncap_rule_ptr, ncap_msg_ct);
struct ncap_rule {
	ISC_LINK(struct ncap_rule)  link;
	ncap_match_ptr		match;
	void *			payload;
	unsigned		argument;
};

struct ncap_filter;
typedef struct ncap_filter *ncap_filter_ptr;
typedef ISC_LIST(struct ncap_filter) ncap_filter_list;
struct ncap_filter {
	ISC_LINK(struct ncap_filter)  link;
	ncap_rule_list		rules;
	char *			bpf;
};

struct ncap_filtermaker;
typedef struct ncap_filtermaker *ncap_filtermaker_ptr;
typedef	char *(*ncap_rulemaker_ptr)(ncap_t, const char *, char, const char *);
struct ncap_filtermaker {
	const char *		name;
	ncap_rulemaker_ptr	rulemaker;
};

struct ncap_pvt {
	int			maxmsg;
	u_char *		msgbuf;
	ncap_if_list		ifs;
	ncap_nf_list		nfs;
	ncap_pf_list		pfs;
	ncap_dg_list		dgs;
	fd_set			fdset;
	int			highest_fd;
	int			flags;
	struct reasm_ip *	reasm_ip;
	ncap_filter_list	filters;
};

#define	NCAP_STOPPING	0x0001
#define	NCAP_FAILURE	0x0002

struct ncap_if_closure {
	ncap_callback_t	callback;
	void *		closure;
	ncap_if_ptr	ifp;
};
typedef struct ncap_if_closure *ncap_if_closure_t;

struct ncap_nf_closure {
	ncap_callback_t	callback;
	void *		closure;
	ncap_nf_ptr	nfp;
};
typedef struct ncap_nf_closure *ncap_nf_closure_t;

struct ncap_pf_closure {
	ncap_callback_t	callback;
	void *		closure;
	ncap_pf_ptr	pfp;
};
typedef struct ncap_pf_closure *ncap_pf_closure_t;

#define NCAP_SETERR(m) do { \
	if (ncap->errstr != NULL) \
		free(ncap->errstr); \
	ncap->errstr = strdup(m); \
	ncap->pvt->flags |= NCAP_FAILURE; \
} while (0)

char *		ncap_filter_dns(ncap_t, const char *, char, const char *);
char *		ncap_filter_icmp(ncap_t, const char *, char, const char *);
void		ncap_addrule(ncap_t, ncap_match_ptr, void *, unsigned);

#endif
