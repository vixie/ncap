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

#ifndef __ncap_h
#define __ncap_h 1

#include <sys/time.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <stdio.h>

#define	ncap_magic	{'N','C','A','P'}
#define	ncap_version	42

typedef enum { ncap_ip4 = 0, ncap_ip6 } ncap_np_e;

union ncap_np;
typedef union ncap_np *ncap_np_t;
typedef const union ncap_np *ncap_np_ct;

union ncap_np {
	struct {
		struct in_addr src, dst;
	} ip4;
	struct {
		struct in6_addr src, dst;
		/* XXX do we care about flow label, interface id, etc? */
	} ip6;
};

typedef enum { ncap_udp = 0, ncap_tcp, ncap_icmp } ncap_tp_e;

#define	ncap_tcp_syn	0x0001		/* first segment */
#define	ncap_tcp_fin	0x0002		/* last segment */
#define	ncap_tcp_rst	0x0004		/* session reset */
#define	ncap_tcp_sum	0x0008		/* checksum failed */

union ncap_tp;
typedef union ncap_tp *ncap_tp_t;
typedef const union ncap_tp *ncap_tp_ct;

union ncap_tp {
	struct {
		unsigned	sport, dport;
	} udp;
	struct {
		unsigned	sport, dport;
		unsigned	offset;
		unsigned	flags;
	} tcp;
	struct {
		u_char		type, code;
	} icmp;
};

struct ncap_msg;
typedef struct ncap_msg *ncap_msg_t;
typedef const struct ncap_msg *ncap_msg_ct;

/* In-memory message format.
 */
struct ncap_msg {
	/* Fixed part. */
	struct timespec	ts;
	unsigned	user1, user2;
	ncap_np_e	np;
	ncap_tp_e	tp;
	size_t		paylen;
	/* Variable part. */
	union ncap_np	npu;
	union ncap_tp	tpu;
	const u_char *	payload;
};

/* Pickled message format is as follows.  All multibyte integers are in
 * "network byte order" (most significant byte first; opposite of VAX/Intel.)
 *
 * Fixed part (size is 28):
 *	uint32_t	overall message length	includes self, padding
 *	uint32_t	sec, nsec
 *	uint32_t	user1, user2
 *	uint16_t	network union type
 *	uint16_t	transport union type
 *	uint32_t	payload length		doesn't include padding
 *
 * Variable part (size is always evenly divisible by 4):
 *	u_char []	network union		has known size and padding
 *	u_char []	transport union		has known size and padding
 *	u_char []	payload
 */

#define	NCAP_FILEHDR	8
#define	NCAP_MSGHDR	28	/* depends on content of struct ncap_msg */
#define	NCAP_NETHDR	32	/* depends on content of union ncap_np */
#define	NCAP_TPHDR	12	/* depends on content of union ncap_tp */
#define	NCAP_PADFACTOR	4

typedef enum { ncap_success = 0, ncap_failure } ncap_result_e;

struct ncap_pvt;
typedef struct ncap_pvt *ncap_pvt_t;

struct ncap;
typedef struct ncap *ncap_t;

typedef void (*ncap_callback_t)(ncap_t, void *, struct ncap_msg *,
				const char *);

struct ncap {
	ncap_pvt_t	pvt;
	char *		errstr;
	ncap_result_e	(*add_if)(ncap_t, const char *name,
				  const char *bpf, int promisc,
				  const int vlans[], int nvlan,
				  int *fdes);
	ncap_result_e	(*drop_if)(ncap_t, int fdes);
	ncap_result_e	(*add_nf)(ncap_t, int fdes, const char *);
	ncap_result_e	(*drop_nf)(ncap_t, int fdes);
	ncap_result_e	(*add_pf)(ncap_t, FILE *, const char *);
	ncap_result_e	(*drop_pf)(ncap_t, FILE *);
	ncap_result_e	(*add_dg)(ncap_t, int fdes, const char *);
	ncap_result_e	(*drop_dg)(ncap_t, int fdes);
	ncap_result_e	(*filter)(ncap_t, const char *);
	ncap_result_e	(*collect)(ncap_t, int polling, ncap_callback_t,
				   void *closure);
	void		(*stop)(ncap_t);
	struct ncap_msg	(*cons)(ncap_t, struct timespec,
				unsigned, unsigned,
				ncap_np_e, ncap_np_ct,
				ncap_tp_e, ncap_tp_ct,
				size_t, const u_char *);
	int		(*match)(ncap_t, ncap_msg_ct);
	ncap_result_e	(*write)(ncap_t, ncap_msg_ct, int fdes);
	ncap_result_e	(*fwrite)(ncap_t, ncap_msg_ct, FILE *);
	ncap_result_e	(*send)(ncap_t, ncap_msg_ct, int fdes, int flags);
	void		(*destroy)(ncap_t);
};

ncap_t		ncap_create(int maxmsg);

/* Buffer manipulation macros.*/

#define NCAP_SETERR(m) do { \
	if (ncap->errstr != NULL) \
		free(ncap->errstr); \
	ncap->errstr = strdup(m); \
	ncap->pvt->flags |= NCAP_FAILURE; \
} while (0)

#define	NCAP_PUTBUF(b, l, cp) do { \
	register size_t t_l = (size_t)(l); \
	memcpy((cp), (b), t_l); \
	(cp) += t_l; \
} while (0)

#define NCAP_PUT16(s, cp) do { \
	register uint16_t t_s = (uint16_t)(s); \
	register u_char *t_cp = (u_char *)(cp); \
	*t_cp++ = t_s >> 8; \
	*t_cp   = t_s; \
	(cp) += sizeof(uint16_t); \
} while (0)

#define NCAP_PUT32(l, cp) do { \
	register uint32_t t_l = (uint32_t)(l); \
	register u_char *t_cp = (u_char *)(cp); \
	*t_cp++ = t_l >> 24; \
	*t_cp++ = t_l >> 16; \
	*t_cp++ = t_l >> 8; \
	*t_cp   = t_l; \
	(cp) += sizeof(uint32_t); \
} while (0)

#define	NCAP_GETBUF(b, l, cp) do { \
	register size_t t_l = (size_t)(l); \
	memcpy((b), (cp), t_l); \
	(cp) += t_l; \
} while (0)

#define NCAP_GET16(s, cp) do { \
	register const u_char *t_cp = (const u_char *)(cp); \
	(s) = ((uint16_t)t_cp[0] << 8) \
	    | ((uint16_t)t_cp[1]) \
	    ; \
	(cp) += sizeof(uint16_t); \
} while (0)

#define NCAP_GET32(l, cp) do { \
	register const u_char *t_cp = (const u_char *)(cp); \
	(l) = ((uint32_t)t_cp[0] << 24) \
	    | ((uint32_t)t_cp[1] << 16) \
	    | ((uint32_t)t_cp[2] << 8) \
	    | ((uint32_t)t_cp[3]) \
	    ; \
	(cp) += sizeof(uint32_t); \
} while (0)

#endif /*__ncap_h*/
