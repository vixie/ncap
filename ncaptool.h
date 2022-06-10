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

#ifndef _ncaptool_h
#define _ncaptool_h

/* Externals. */

#ifdef __linux__
# define _GNU_SOURCE
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <stdio.h>
#include <time.h>

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <ncap.h>

#include <ncap_list.h>

/* Macros. */

#define NCAPTOOL_MSGMOD_VERSION	1

#ifdef HAVE_SA_LEN
#define NCAPTOOL_SA_LEN(sa) ((sa).sa_len)
#else
#define	NCAPTOOL_SA_LEN(sa) ((sa).sa_family == AF_INET ? \
			     sizeof(struct sockaddr_in) :\
			     (sa).sa_family == AF_INET6 ? \
			     sizeof(struct sockaddr_in6) : 0)
#endif

#define	NCAPTOOL_SINK_ENABLED(sink) ((sink)->st != st_none)
#define	NCAPTOOL_SINK_ACTIVE(sink) ((sink)->fp != NULL)

/* Data structures. */

enum ncaptool_uvaltyp { ut_none = 0, ut_repl, ut_set, ut_clear };
struct ncaptool_uval {
	enum ncaptool_uvaltyp	ut;
	unsigned		val;
};

enum ncaptool_sinktyp { st_none = 0, st_stdout, st_file };

struct ncaptool_fpsink {
	enum ncaptool_sinktyp	st;
	char *			basename;
	char *			tmpname;
	char *			curname;
	FILE *			fp;
};

struct ncaptool_dgsink {
	ISC_LINK(struct ncaptool_dgsink)  link;
	int			dg;
	unsigned		count;
	time_t			embargo;
	struct timespec		last_fh;
};

union ncaptool_sockaddr {
	struct sockaddr		sa;
	struct sockaddr_in	s4;
	struct sockaddr_in6	s6;
};
typedef union ncaptool_sockaddr ncaptool_sockaddr;

struct ncaptool_ctx;
typedef void (ncaptool_sendfails_func)(ncap_t, struct ncaptool_ctx *,
				       struct ncaptool_dgsink *,
				       struct timespec, int);

struct ncaptool_ctx {
	int			sinks;
	int			opened_sink;
	unsigned		freq;
	struct timespec		now;
	struct ncaptool_fpsink	trace, dump;
	unsigned		count_limit, time_limit;
	unsigned		dlev, mlev, flush, remote, wall, stripe;
	unsigned		count, msgs;
	struct ncaptool_uval	user1, user2;
	struct {
		unsigned	count, limit, rate;
		struct timespec	start, ipg;
	}			quant;
	size_t			octets;
	const char *		kicker;
	const char *		endline;

	ISC_LIST(struct ncaptool_dgsink)  dgsinks;
	struct ncaptool_dgsink *  dgnext;
	ISC_LIST(struct module)	msgmods;
	int (*getsock)(union ncaptool_sockaddr *, const char *, unsigned *,
		       unsigned *);
	int (*getsink)(const char *, struct ncaptool_fpsink *);
	int (*samesink)(const struct ncaptool_fpsink *,
			const struct ncaptool_fpsink *);
	int (*opensink)(struct ncaptool_fpsink *, struct timespec,
			const char *);
	void (*closesink)(struct ncaptool_fpsink *,
			  const struct ncaptool_ctx *);
	void (*disablesink)(struct ncaptool_fpsink *,
			    const struct ncaptool_ctx *);
	void (*drainsink)(struct ncaptool_fpsink *,
			  const struct ncaptool_ctx *);
	void (*dgsend)(ncap_t, ncap_msg_ct, struct ncaptool_ctx *,
		       struct ncaptool_dgsink *, struct timespec,
		       ncaptool_sendfails_func);
	void (*sendfails)(ncap_t, struct ncaptool_ctx *,
			  struct ncaptool_dgsink *, struct timespec, int);
};

/* Message processing plugin interface. */

typedef int (*ncaptool_msgmod_init)(struct ncaptool_ctx *, int, char **);
typedef int (*ncaptool_msgmod_fini)(void);
typedef int (*ncaptool_msgmod_proc)(ncap_t, void *, ncap_msg_ct, const char *);
typedef int (*ncaptool_msgmod_sinks_open)(void);
typedef int (*ncaptool_msgmod_sinks_enab)(void);
typedef void (*ncaptool_msgmod_drainsinks)(void);

struct ncaptool_msgmod {
	int			mver;
	const char *		name;
	ncaptool_msgmod_init	init;
	ncaptool_msgmod_fini	fini;
	ncaptool_msgmod_proc	proc;
	ncaptool_msgmod_sinks_open  sinks_open;
	ncaptool_msgmod_sinks_enab  sinks_enab;
	ncaptool_msgmod_drainsinks  drainsinks;
};

#endif
