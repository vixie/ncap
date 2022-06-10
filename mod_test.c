/* mod_test - example ncaptool message processing plugin */

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

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "ncaptool.h"

#define SEED "/dev/urandom"

static int test_init(struct ncaptool_ctx *, int, char **);
static int test_fini(void);
static int test_proc(ncap_t, void *, ncap_msg_ct, const char *);
static void usage(const char *msg);

struct ncaptool_msgmod ncaptool_msgmod_ctx =
{
	.mver = NCAPTOOL_MSGMOD_VERSION,
	.name = "mod_test",
	.init = &test_init,
	.fini = &test_fini,
	.proc = &test_proc
};

static struct ncaptool_ctx *ctx;
static int mode_random;
static int mode_skip;

static int count;

static int
test_init(struct ncaptool_ctx *my_ctx, int argc, char **argv) {
	int ch;
	int fd;
	char *t;
	unsigned seed;
	ctx = my_ctx;

	while ((ch = getopt(argc, argv, "rs:")) != -1) {
		switch (ch) {
		case 'r':
			mode_random = 1;
			if ((fd = open(SEED, O_RDONLY)) != -1) {
				if (read(fd, &seed, sizeof seed)
				    == sizeof seed)
				{
					srandom(seed);
					close(fd);
				} else {
					perror("read");
					close(fd);
					return (-1);
				}
			} else {
				perror("open");
				return (-1);
			}
			break;
		case 's':
			mode_skip = strtoul(optarg, &t, 0);
			if (*t != '\0') {
				usage("bad -s number");
				return (-1);
			}
			if(mode_skip < 1) {
				usage("-s must be > 0");
				return (-1);
			}
			break;
		default:
			usage("unrecognized argument");
			return (-1);
		}
	}

	if (mode_random == 0 && mode_skip == 0) {
		usage("must set -r or -s");
		return (-1);
	}

	return (0);
}

static int
test_fini(void) {
	return (0);
}

static int
test_proc(ncap_t n		__attribute__((unused)),
	   void *user		__attribute__((unused)),
	   ncap_msg_ct msg	__attribute__((unused)),
	   const char *label	__attribute__((unused)))
{
	if (mode_skip != 0) {
		count++;
		if(count % mode_skip == 0) {
			return (1);
		} else {
			return (0);
		}
	} else if (random() & 1) {
		return (1);
	}

	return (0);
}

static void
usage(const char *msg) {
	const char *name = ncaptool_msgmod_ctx.name;
	fprintf(stderr, "%s] usage error (%s)\n", name, msg);
	fprintf(stderr, "%s] options are:\n", name);
	fprintf(stderr, "%s]\t-r        random mode\n", name);
	fprintf(stderr, "%s]\t-s n      skip n frames at a time\n", name);
}
