/* dynamic module loader */

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

#include "asprintf.h"
#include "ncaptool.h"

#include <assert.h>
#include <ctype.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ncap_port.h"
#include "ncaptool_mod.h"

/**
 * scan the command-line argument module args and prepare a corresponding
 * struct module for loading.
 *
 * @return 0 on success, nonzero otherwise
 */
int
scan_moddescr (struct module *mod, const char *arg) {
	char *tmp, *p;
	char *saveptr = NULL;

	if (mod == NULL || arg == NULL)
		return (-1);

	tmp = strdup(arg);
	p = strchr(tmp, ',');

	if (p != NULL)
		mod->args = strdup(p + 1);
	else
		mod->args = strdup("");

	strtok_r(tmp, ",", &saveptr);
	mod->path = strdup(tmp);
	free(tmp);

	return (0);
}

/**
 * load the DSO specified by the filesystem path mod->path
 *
 * @return 0 on success, nonzero otherwise
 */
int
module_load (struct module *mod) {
	const char *error;

	if (mod == NULL)
		return (-1);

	if (isalnum((unsigned char) mod->path[0])) {
		char *tmp;

		ncap_asprintf(&tmp, "./%s", mod->path);
		assert(tmp != NULL);
		free(mod->path);
		mod->path = tmp;
	}

	mod->dlhandle = dlopen(mod->path, RTLD_NOW);
	if (mod->dlhandle == NULL) {
		fprintf(stderr, "module_load: dlopen() failed: %s\n", dlerror());
		return (-1);
	}

	dlerror(); /* clear */

	if (mod->type == mt_msg) {
		mod->ctx.msg = dlsym(mod->dlhandle, "ncaptool_msgmod_ctx");
		if (mod->ctx.msg->mver != NCAPTOOL_MSGMOD_VERSION) {
			fprintf(stderr, "module_load: wrong message module interface version "
				"%d != %d\n", mod->ctx.msg->mver, NCAPTOOL_MSGMOD_VERSION);
			return (-1);
		}
	} else {
		fprintf(stderr, "module_load: unsupported module type %d\n", mod->type);
		return (-1);
	}
	if ((error = dlerror()) != NULL) {
		fprintf(stderr, "module_load: dlsym() failed: %s\n", error);
		return (-1);
	}

	return (0);
}

/**
 * initialize the loaded module
 * @return 0 on success, nonzero otherwise
 */
int
module_init (struct module *mod, struct ncaptool_ctx *ctx) {
	char **argv;
	int argc, rc;

	if (mod == NULL || mod->ctx.msg == NULL || mod->ctx.msg->init == NULL)
		return (-1);

	argv = synth_args(mod->ctx.msg->name, mod->args, &argc);
	assert(argv != NULL);
	reset_getopt();
	rc = mod->ctx.msg->init(ctx, argc, argv);
	free(argv[0]);
	free(argv);

	return (rc);
}

/**
 * finalize an initialized module
 * @return 0 on success, nonzero otherwise
 */
int
module_fini (struct module *mod) {
	int rc;

	if (mod == NULL || mod->ctx.msg == NULL || mod->ctx.msg->fini == NULL)
		return (-1);

	rc = mod->ctx.msg->fini();
	free(mod->args);
	free(mod->path);

	if (dlclose(mod->dlhandle) != 0) {
		fprintf(stderr, "module_fini: dlclose() failed: %s\n",
			dlerror());
		return (-1);
	}
	
	return (rc);
}

/**
 * synthesize an argc / argv vector from a string
 * @param name argv[0] content
 * @param args argument string (tokenized on spaces)
 * @param argc argc parameter-result
 * @return argument vector on success, NULL on failure
 */
char **
synth_args (const char *name, const char *args, int *argc) {
	char **argv;
	char *copy;

	if (name == NULL || args == NULL || argc == NULL)
		return NULL;
	
	argv = malloc(2 * sizeof(char *));
	assert(argv != NULL);

	argv[0] = strdup(name);
	copy = strdup(args);
	argv[1] = copy;
	*argc = 2;

	while (*copy != '\0') {
		if (*copy == ' ') {
			*copy++ = '\0';
			argv = realloc(argv, ++(*argc) * sizeof(char *));
			assert(argv != NULL);
			argv[*argc - 1] = copy;
		}
		copy++;
	}

	return (argv);
}

/**
 * from http://lists.debian.org/debian-glibc/2004/10/msg00086.html
 * reset the internal state of getopt()
 */
void
reset_getopt (void) {
#ifdef __GLIBC__
	optind = 0;
#else
	optind = 1;
#endif
#ifdef HAVE_OPTRESET
	optreset = 1; /* Makes BSD getopt happy */
#endif
}
