#ifndef _ncaptool_mod_h
#define _ncaptool_mod_h

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

#include "ncap.h"
#include "ncaptool.h"

enum module_type { mt_msg = 0 };

struct module {
	ISC_LINK(struct module)	link;
	char *			path;
	char *			args;
	void *			dlhandle;
	enum module_type	type;
	union {
		struct ncaptool_msgmod *  msg;
	} ctx;
};

int scan_moddescr(struct module *, const char *);
int module_load(struct module *);
int module_init(struct module *, struct ncaptool_ctx *);
int module_fini(struct module *);
char **synth_args(const char *, const char *, int *);
void reset_getopt(void);

#endif
