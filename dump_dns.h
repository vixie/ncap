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

void
dump_dns(const u_char *payload, size_t paylen,
	 FILE *trace, const char *endline);

void
dump_icmpdns(const u_char *payload, size_t paylen,
	     FILE *trace, const char *endline);

#include "ncap_port.h"
#ifdef HAVE_LIBBIND

void
dump_dns_sect(ns_msg *msg, ns_sect sect, FILE *trace, const char *endline);

void
dump_dns_rr(ns_msg *msg, ns_rr *rr, ns_sect sect, FILE *trace);

void
dump_dns_rd(const u_char *msg, const u_char *eom, unsigned type,
	    const u_char *rdata, unsigned rdlen,
	    FILE *trace);

const char *
dump_dns_rcode(unsigned rcode);

const char *
dump_dns_class(unsigned class);

const char *
dump_dns_type(unsigned type);

#endif /*HAVE_LIBBIND*/
