/* ncaptool - tool shell around ncap(3) library
 *
 * By: Paul Vixie, ISC, August 2007
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

/* Externals. */

#include "asprintf.h"
#include "ncap_port.h"
#include "ncap_port_net.h"

#include <sys/time.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <resolv.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "ncap.h"
#include "ncaptool.h"
#include "ncaptool_mod.h"
#include "dump_dns.h"
#include "ncap_list.h"

#ifdef DMALLOC
# include <dmalloc.h>
#endif

/* Macros. */

#define FILEHDR_SECS	5
#define EVERY_SO_OFTEN	100
#define SEND_BACKOFF	5
#define THOUSAND	1000
#define MILLION		(THOUSAND*THOUSAND)
#define BILLION		(THOUSAND*MILLION)
#define FBILLION	(BILLION + 0.0)

#define HIDE_SRCADDR	0x0001
#define HIDE_DSTADDR	0x0002

/* note-- in a macro actual argument, ";" is just another text character. */

#define NCAP_OK(n,e,a) do { \
        if (n->e != ncap_success) { \
                fprintf(stderr, #e ": %s\n", n->errstr); \
                a; \
        } \
} while (0)

/* From FreeBSD sys/time.h "timespecsub" */
#define TS_SUBTRACT(vvp, uvp)                                           \
	do {                                                            \
		(vvp)->tv_sec -= (uvp)->tv_sec;                         \
		(vvp)->tv_nsec -= (uvp)->tv_nsec;                       \
		if ((vvp)->tv_nsec < 0) {                               \
			(vvp)->tv_sec--;                                \
			(vvp)->tv_nsec += 1000000000;                   \
		}                                                       \
	} while (0)

/* Forwards. */

static void usage(const char *msg) __attribute__((noreturn));
static void help(void);
static void setsig(int, int);
static void sighand(int);
static void ncapmsg(ncap_t, void *, struct ncap_msg *, const char *);
static int getuval(const char *, struct ncaptool_uval *);
static void uvalexec(unsigned *, const struct ncaptool_uval *);
static void nanonano(struct timespec);
static void nanotime(struct timespec *);
static void dump_hex(const u_char *, size_t, FILE *, const char *);

/* exported via struct ncaptool_func */
static int getsock(ncaptool_sockaddr *, const char *, unsigned *, unsigned *);
static int getsink(const char *, struct ncaptool_fpsink *);
static int samesink(const struct ncaptool_fpsink *, const struct ncaptool_fpsink *);
static int opensink(struct ncaptool_fpsink *, struct timespec, const char *);
static void closesink(struct ncaptool_fpsink *, const struct ncaptool_ctx *);
static void disablesink(struct ncaptool_fpsink *, const struct ncaptool_ctx *);
static void drainsink(struct ncaptool_fpsink *, const struct ncaptool_ctx *);
static void dgsend(ncap_t, ncap_msg_ct, struct ncaptool_ctx *, struct ncaptool_dgsink *,
		   struct timespec, ncaptool_sendfails_func);
static void sendfails(ncap_t, struct ncaptool_ctx *, struct ncaptool_dgsink *,
		      struct timespec, int);

/* Globals. */

static const char *ProgramName = "amnesia";
static int SignalledBreak;
static int AlarmRunning;
static ncap_t NC;
static struct ncaptool_ctx ctx;
static unsigned hide_addr = 0U;

/* Program entry point.
 */
int
main(int argc, char **argv) {
	struct ife { ISC_LINK(struct ife) link; char *name; int promisc; };
	int ch, pf, s, len, listener, sources, pcapfiles, verbose, fd;
	int pa, pz, pn, pl;
	char *t, *r, *bpf, *filtspec, **arg;
	struct timespec start, finish;
	ISC_LIST(struct ife) iflist;
	static const int on = 1;
	struct ncaptool_dgsink *dgsink;
	ncaptool_sockaddr su;
	struct ife *ifp;
	struct module *mod;
	FILE *fp;

	/* Get the program name, for messages. */
	if ((ProgramName = strrchr(argv[0], '/')) != NULL)
		ProgramName++;
	else
		ProgramName = argv[0];

	/* Initialize other stuff. */
	ISC_LIST_INIT(iflist);
	NC = ncap_create(70000);
	if (NC == NULL) {
		perror("ncap_create");
		exit(1);
	}
	ISC_LIST_INIT(ctx.dgsinks);
	sources = pcapfiles = 0;
	bpf = NULL;
	verbose = false;
	ctx.endline = "\\\n\t";
	ctx.freq = 100;

	/* Exported for use by modules. */
	ctx.getsock	= &getsock;
	ctx.getsink	= &getsink;
	ctx.samesink	= &samesink;
	ctx.opensink	= &opensink;
	ctx.closesink	= &closesink;
	ctx.disablesink	= &disablesink;
	ctx.drainsink	= &drainsink;
	ctx.dgsend	= &dgsend;
	ctx.sendfails	= &sendfails;

	/* Crack the argument vector. */
	while ((ch = getopt(argc, argv,
			    "hdmfrwvSe:1:2:b:g:i:p:n:o:c:t:s:l:k:D:H:")) != -1)
	{
		switch (ch) {
		case 'h':
			help();
			exit(0);
		case 'd':
			ctx.dlev++;
			break;
		case 'm':
			ctx.mlev++;
			break;
		case 'f':
			ctx.flush = true;
			break;
		case 'r':
			ctx.remote = true;
			break;
		case 'w':
			ctx.wall = true;
			break;
		case 'v':
			verbose = true;
			break;
		case 'S':
			ctx.stripe = true;
			break;
		case 'e':
			ctx.endline = optarg;
			break;
		case '1':
			if (!getuval(optarg, &ctx.user1))
				usage("bad -1 uval");
			break;
		case '2':
			if (!getuval(optarg, &ctx.user2))
				usage("bad -2 uval");
			break;
		case 'b':
			if (bpf != NULL)
				usage("you can't say -b more than once");
			bpf = optarg;
			break;
		case 'g':
			if (!getsink(optarg, &ctx.trace))
				usage("bad -g sink");
			ctx.sinks++;
			break;
		case 'i':
			ifp = malloc(sizeof *ifp);
			assert(ifp != NULL);
			ISC_LINK_INIT(ifp, link);
			ifp->name = strdup(optarg);
			assert(ifp->name != NULL);
			ifp->promisc = false;
			t = strchr(ifp->name, '+');
			if (t != NULL) {
				*t = '\0';
				ifp->promisc = true;
			}
			ISC_LIST_APPEND(iflist, ifp, link);
			sources++;
			break;
		case 'p':
			pcapfiles++;
			if (strcmp(optarg, "-") == 0)
				fp = stdin;
			else
				fp = fopen(optarg, "r");
			if (fp == NULL) {
				perror(optarg);
				exit(1);
			}
			NCAP_OK(NC, add_pf(NC, fp, optarg), exit(1));
			sources++;
			break;
		case 'n':
			if (strcmp(optarg, "-") == 0)
				fd = STDIN_FILENO;
			else
				fd = open(optarg, O_RDONLY);
			if (fd < 0) {
				perror(optarg);
				exit(1);
			}
			NCAP_OK(NC, add_nf(NC, fd, optarg), exit(1));
			sources++;
			break;
		case 'o':
			if (!getsink(optarg, &ctx.dump))
				usage("bad -o sink");
			ctx.sinks++;
			break;
		case 'c':
			ctx.count_limit = strtoul(optarg, &t, 0);
			if (*t != '\0')
				usage("bad -c number");
			break;
		case 't':
			ctx.time_limit = strtoul(optarg, &t, 0);
			if (*t != '\0')
				usage("bad -t number");
			break;
		case 's':
			t = strchr(optarg, '/');
			r = strchr(optarg, ',');
			if (t == NULL)
				usage("argument to -s needs a /");
			if (sscanf(t + 1, "%d..%d", &pa, &pz) == 2) {
				if (pa > pz || pz - pa > 20)
					usage("bad port range in -s argument");
			} else if (sscanf(t + 1, "%d", &pa) == 1) {
				pz = pa;
			} else {
				usage("need a port number or range after /");
			}
			pl = t - optarg;
			for (pn = pa; pn <= pz; pn++) {
				char *spec;

				ncap_asprintf(&spec, "%*.*s/%d%s",
					      pl, pl, optarg, pn,
					      r != NULL ? r : "");
				pf = getsock(&su, spec, &ctx.quant.rate,
					     &ctx.freq);
				free(spec);
				if (pf < 0)
					usage("bad -s socket");
				s = socket(pf, SOCK_DGRAM, 0);
				if (s < 0) {
					perror("socket");
					exit(1);
				}
				if (setsockopt(s, SOL_SOCKET, SO_BROADCAST,
					       &on, sizeof on) < 0)
				{
					perror("setsockopt(SO_BROADCAST)");
					exit(1);
				}
				len = 32 * 1024;
				if (setsockopt(s, SOL_SOCKET, SO_SNDBUF,
					       &len, sizeof len) < 0)
				{
					perror("setsockopt(SO_SNDBUF)");
					exit(1);
				}
				if (connect(s, &su.sa,
					    NCAPTOOL_SA_LEN(su.sa)) < 0)
				{
					perror("connect");
					exit(1);
				}
				dgsink = malloc(sizeof *dgsink);
				assert(dgsink != NULL);
				memset(dgsink, 0, sizeof *dgsink);
				ISC_LINK_INIT(dgsink, link);
				dgsink->dg = s;
				ISC_LIST_APPEND(ctx.dgsinks, dgsink, link);
				ctx.sinks++;
			}
			break;
		case 'l':
			t = strchr(optarg, '/');
			if (t == NULL)
				usage("argument to -l needs a /");
			if (sscanf(t + 1, "%d..%d", &pa, &pz) == 2) {
				if (pa > pz || pz - pa > 20)
					usage("bad port range in -l argument");
			} else if (sscanf(t + 1, "%d", &pa) == 1) {
				pz = pa;
			} else {
				usage("need a port number or range after /");
			}
			pl = t - optarg;
			for (pn = pa; pn <= pz; pn++) {
				char *spec;

				ncap_asprintf(&spec, "%*.*s/%d",
					      pl, pl, optarg, pn);
				pf = getsock(&su, spec, NULL, NULL);
				if (pf < 0)
					usage("bad -l socket");
				listener = socket(pf, SOCK_DGRAM, 0);
				if (listener < 0) {
					perror("socket");
					exit(1);
				}

				/*
				 * SO_REUSEADDR is needed on non-BSD systems
				 * which lack SO_REUSEPORT in order to allow
				 * multiple listeners to reopen the same
				 * broadcast socket.  SO_REUSEADDR +
				 * SO_REUSEPORT on freebsd appears to
				 * approximate most closely SO_REUSEADDR on
				 * other systems.
				 */
				if (setsockopt(listener, SOL_SOCKET,
					       SO_REUSEADDR, &on, sizeof on)
				    < 0)
				{
					perror("setsockopt(SO_REUSEADDR)");
					exit(1);
				}
#ifdef SO_REUSEPORT
				if (setsockopt(listener, SOL_SOCKET,
					       SO_REUSEPORT, &on, sizeof on)
				    < 0)
				{
					perror("setsockopt(SO_REUSEPORT)");
					exit(1);
				}
#endif
				len = 32 * 1024;
				if (setsockopt(listener, SOL_SOCKET, SO_RCVBUF,
					       &len, sizeof len) < 0)
				{
					perror("setsockopt(SO_RCVBUF)");
					exit(1);
				}
				if (bind(listener, &su.sa,
					 NCAPTOOL_SA_LEN(su.sa)) < 0)
				{
					perror("bind");
					exit(1);
				}
				NCAP_OK(NC, add_dg(NC, listener, spec),
					exit(1));
				free(spec);
				sources++;
			}
			break;
		case 'k':
			ctx.kicker = optarg;
			break;
		case 'D':
			mod = malloc(sizeof *mod);
			assert(mod != NULL);
			memset(mod, 0, sizeof *mod);
			mod->type = mt_msg;
			ISC_LINK_INIT(mod, link);
			scan_moddescr(mod, optarg);
			ISC_LIST_APPEND(ctx.msgmods, mod, link);
			break;
		case 'H':
			for (t = optarg; *t; t++)
				switch (*t) {
				case 's': hide_addr |= HIDE_SRCADDR; break;
				case 'd': hide_addr |= HIDE_DSTADDR; break;
				default: usage("-H takes only [sd]");
				}
			break;
		default:
			usage("unrecognized argument");
		}
	}
	argc -= optind;
	argv += optind;
	if (sources == 0)
		usage("no data sources were specified");
	if (samesink(&ctx.trace, &ctx.dump))
		usage("-g and -o can't be the same");
	if (ctx.kicker != NULL &&
	    (ctx.dump.st == st_stdout || ctx.trace.st == st_stdout) &&
	    (ctx.dump.st == st_none || ctx.trace.st == st_none))
		usage("-k makes no sense if the only data sink is stdout");
	if (bpf != NULL && ISC_LIST_EMPTY(iflist) && pcapfiles == 0)
		usage("-b makes no sense if there are no -i or -p options");

	/* Gather filter spec if present. */
	filtspec = NULL;
	len = 0;
	for (arg = argv; *arg != NULL; arg++)
		len += strlen(*arg) + 1;
	if (len != 0) {
		filtspec = malloc(len);
		assert(filtspec != NULL);
		*filtspec = '\0';
		for (arg = argv; *arg != NULL; arg++) {
			strcat(filtspec, *arg);
			if (arg[1] != NULL)
				strcat(filtspec, " ");
		}
	}
	if (filtspec != NULL) {
		if (bpf != NULL)
			usage("when using a filter spec, -b is disallowed");
		NCAP_OK(NC, filter(NC, filtspec), exit(1));
	}

	/* Process interface list and destroy it. */
	while ((ifp = ISC_LIST_HEAD(iflist)) != NULL) {
		NCAP_OK(NC, add_if(NC, ifp->name, bpf, ifp->promisc,
				   NULL, 0, NULL),
			exit(1));
		ISC_LIST_UNLINK(iflist, ifp, link);
		free(ifp->name);
		free(ifp);
	}

	/* Load and initialize modules */
	for (mod = ISC_LIST_HEAD(ctx.msgmods);
	     mod != NULL;
	     mod = ISC_LIST_NEXT(mod, link))
	{
		if (verbose)
			fprintf(stderr, "%s: loading module %s\n",
				ProgramName, mod->path);
		if (module_load(mod) != 0) {
			fprintf(stderr, "%s: unable to load module %s\n",
				ProgramName, mod->path);
			exit(1);
		}
		if (module_init(mod, &ctx) != 0) {
			fprintf(stderr, "%s: unable to initialize module %s\n",
				ProgramName, mod->path);
			exit(1);
		}
	}

	if (ctx.sinks == 0)
		usage("no data sinks were specified");

	/* Do, and die. */
	setsig(SIGHUP, true);
	setsig(SIGINT, true);
	setsig(SIGALRM, false);
	setsig(SIGTERM, true);
	nanotime(&start);
	ctx.quant.start = start;
	ctx.quant.ipg.tv_nsec = BILLION / ctx.freq;
	ctx.quant.limit = ((ctx.quant.rate / ctx.freq) * 100) / 90;
	do {
		SignalledBreak = 0;
		NCAP_OK(NC, collect(NC, 0, ncapmsg, &ctx), exit(1));
		if (SignalledBreak == SIGALRM) {
			drainsink(&ctx.trace, &ctx);
			drainsink(&ctx.dump, &ctx);
		}
		for (mod = ISC_LIST_HEAD(ctx.msgmods);
		     mod != NULL;
		     mod = ISC_LIST_NEXT(mod, link))
		{
			if (mod->ctx.msg->drainsinks != NULL)
				mod->ctx.msg->drainsinks();
		}
	} while (SignalledBreak == SIGALRM);
	nanotime(&finish);
	NC->destroy(NC);
	disablesink(&ctx.trace, &ctx);
	disablesink(&ctx.dump, &ctx);
	while ((dgsink = ISC_LIST_HEAD(ctx.dgsinks)) != NULL) {
		ISC_LIST_UNLINK(ctx.dgsinks, dgsink, link);
		free(dgsink);
	}

	/* Finalize modules */
	while ((mod = ISC_LIST_HEAD(ctx.msgmods)) != NULL) {
		if (module_fini(mod) != 0) {
			fprintf(stderr, "%s: unable to finalize module %s\n",
				ProgramName, mod->path);
			exit(1);
		}
		ISC_LIST_UNLINK(ctx.msgmods, mod, link);
		free(mod);
	}

	if (verbose) {
		struct timespec ts = finish;
		double d;

		TS_SUBTRACT(&ts, &start);
		d = ts.tv_sec + (((double) ts.tv_nsec) / FBILLION);
		fprintf(stderr,
			"size %lu/%lu time %lu.%03lu rate %lu/%lu\n",
			(u_long) ctx.msgs, (u_long) ctx.octets,
			(u_long) ts.tv_sec, (u_long) ts.tv_nsec / 1000000,
			(u_long) (ctx.msgs / d), (u_long) (ctx.octets / d));
	}
	if (SignalledBreak != 0) {
		signal(SignalledBreak, SIG_DFL);
		fprintf(stderr, "%s: signalled break\n", ProgramName);
		kill(getpid(), SignalledBreak);
	}
	return(0);
}

/* Display usage error message, and die.
 */
static void
usage(const char *msg) {
	fprintf(stderr, "%s: usage error (%s)\n\n", ProgramName, msg);
	fprintf(stderr, "usage: %s [options] [filter spec]\n", ProgramName);
	fprintf(stderr, "\t(note: use -h to get help)\n");
	exit(1);
}

/* Display help message.
 */
static void
help(void) {
	fprintf(stderr, "options are:\n"
	"\t-h            display this help text and exit\n"
	"\t-d            increment debugging level\n"
	"\t-m            increment message trace level\n"
	"\t-f            flush outputs after every bufferable write\n"
	"\t-r            destination of -s can be a remote (off-LAN) address\n"
	"\t-w            use wallclock time not NCAP timestamp for -o files\n"
	"\t-v            emit a traffic summary to stderr on exit\n"
	"\t-S            stripe across all -s datasinks, round robin style\n"
	"\t-e endline    specify continuation separator (def = \\\\\\n\\t)\n"
	"\t-i ifname[+]  add interface as a datasource ('+' = promiscuous)\n"
	"\t-b bpf        use this bpf pattern for any -i or -p datasources\n"
	"\t-p file       add pcap file as a datasource ('-' = stdin)\n"
	"\t-n file       add ncap file as a datasource ('-' = stdin)\n"
	"\t-l socket     add datagram socket as a datasource (addr/port)\n"
	"\t-g file       write msg trace to this file ('-' = stdout)\n"
	"\t-o file       write ncap data to this file ('-' = stdout)\n"
	"\t-s so[,r[,f]] add this datagram socket as a datasink (addr/port)\n"
	"\t              (optional ,r is the transmit rate in messages/sec)\n"
	"\t              (optional ,f is schedule frequency, default is 100)\n"
	"\t-c count      stop or reopen after this many msgs are processed\n"
	"\t-t interval   stop or reopen after this amount of time has passed\n"
	"\t-1 [+-]value  replace, set (+), or clear (-) user1 to this value\n"
	"\t-2 [+-]value  replace, set (+), or clear (-) user1 to this value\n"
	"\t-k cmd        make -c, -t continuous; run cmd on each new file\n"
	"\t              (cmd can be empty if you just want the continuity)\n"
	"\t-Dmod[,args]  add module\n"
	"\t-H [sd]       hide source and/or destination IP addresses\n"
	"\n"
	"\targument to -l and -s can be addr/port or addr/port..port (range)\n"
		);
}

/* Set up a signal vector.
 */
static void
setsig(int sig, int oneshot) {
	struct sigaction sa;

	memset(&sa, 0, sizeof sa);
	sa.sa_handler = sighand;
	if (oneshot)
		sa.sa_flags = SA_RESETHAND;
	else
		sa.sa_flags = SA_RESTART;
	if (sigaction(sig, &sa, NULL) < 0) {
		perror("sigaction");
		exit(1);
	}
}

/* Signal handler.
 */
static void
sighand(int signum) {
	SignalledBreak = signum;
	if (SignalledBreak == SIGALRM)
		AlarmRunning = false;
	NC->stop(NC);
}

/* Callback from ncap::collect().
 */
static void
ncapmsg(ncap_t ncap, void *uap, struct ncap_msg *omsg, const char *label) {
	struct ncaptool_ctx *clos = (struct ncaptool_ctx *) uap;
	struct ncaptool_dgsink *dgsink, *dgnext;
	int sport = 0, dport = 0;
	int mod_sinks_open, mod_sinks_enab;
	struct ncap_msg *msg = omsg;
	struct ncap_msg tmsg;
	struct module *mod;

	ctx.opened_sink = false;

	/* Crack the network and transport headers.
	 * Make sure this is a message we can handle.
	 */
	switch (msg->np) {
	case ncap_ip4:
		break;
	case ncap_ip6:
		break;
	default:
		return;
	}
	switch (msg->tp) {
	case ncap_udp:
		sport = msg->tpu.udp.sport;
		dport = msg->tpu.udp.dport;
		break;
	case ncap_tcp:
		/* XXX need TCP support */
		return;
	case ncap_icmp:
		break;
	default:
		return;
	}

	/* Possibly make a copy and modify it to change user1/user2. */
	if (clos->user1.ut != ut_none || clos->user2.ut != ut_none) {
		tmsg = *omsg;
		msg = &tmsg;
		uvalexec(&tmsg.user1, &clos->user1);
		uvalexec(&tmsg.user2, &clos->user2);
	}

	/* Hide srcaddr/dstaddr if requested. */
	if ((hide_addr & HIDE_SRCADDR) != 0) {
		switch (msg->np) {
		case ncap_ip4:
			memset(&msg->npu.ip4.src, 0, sizeof(msg->npu.ip4.src));
			break;
		case ncap_ip6:
			memset(&msg->npu.ip6.src, 0, sizeof(msg->npu.ip6.src));
			break;
		}
	}
	if ((hide_addr & HIDE_DSTADDR) != 0) {
		switch (msg->np) {
		case ncap_ip4:
			memset(&msg->npu.ip4.dst, 0, sizeof(msg->npu.ip4.dst));
			break;
		case ncap_ip6:
			memset(&msg->npu.ip6.dst, 0, sizeof(msg->npu.ip6.dst));
			break;
		}
	}

	/* Accurate current time will be needed, get it only once. */
	nanotime(&ctx.now);

	/* Filter module verdicts. */
	for (mod = ISC_LIST_HEAD(clos->msgmods);
	     mod != NULL;
	     mod = ISC_LIST_NEXT(mod, link))
	{
		if (mod->ctx.msg->proc != NULL &&
		    mod->ctx.msg->proc(ncap, NULL, omsg, label) == 0)
			return;
	}

	/* Now that we know we're going to process it, count it. */
	clos->msgs++;
	clos->octets += msg->paylen;

	/* Close and/or open output sinks as necessary. */
	if (NCAPTOOL_SINK_ENABLED(&clos->trace) && !NCAPTOOL_SINK_ACTIVE(&clos->trace)) {
		if (!opensink(&clos->trace, ctx.now,
			      clos->kicker != NULL ? "trace" : NULL))
			disablesink(&clos->trace, clos);
		else
			ctx.opened_sink = true;
	}
	if (NCAPTOOL_SINK_ENABLED(&clos->dump) && !NCAPTOOL_SINK_ACTIVE(&clos->dump)) {
		if (!opensink(&clos->dump, ctx.now,
			      clos->kicker != NULL ? "ncap" : NULL))
			disablesink(&clos->dump, clos);
		else
			ctx.opened_sink = true;
	}
	if (ctx.opened_sink) {
		clos->count = 0U;
		if (clos->time_limit != 0U && !AlarmRunning) {
			unsigned seconds;
			time_t targ;

			targ = (((ctx.now.tv_sec + (clos->time_limit / 2))
				 / clos->time_limit) + 1)
				* clos->time_limit;
			assert(targ > ctx.now.tv_sec);
			seconds = targ - ctx.now.tv_sec;
			alarm(seconds);
			AlarmRunning = true;
		}
	}

	/* Output trace data if enabled. */
	if (NCAPTOOL_SINK_ENABLED(&clos->trace)) {
		FILE *trace = clos->trace.fp;
		char saddr[100], daddr[100];
		const struct timespec *ts;
		const struct tm *tm;
		char when[100];
		time_t t;

		switch (msg->np) {
		case ncap_ip4:
			inet_ntop(AF_INET, &msg->npu.ip4.src,
				  saddr, sizeof saddr);
			inet_ntop(AF_INET, &msg->npu.ip4.dst,
				  daddr, sizeof daddr);
			break;
		case ncap_ip6:
			inet_ntop(AF_INET6, &msg->npu.ip6.src,
				  saddr, sizeof saddr);
			inet_ntop(AF_INET6, &msg->npu.ip6.dst,
				  daddr, sizeof daddr);
			break;
		default:
			return;
		}
		if (clos->wall) {
			ts = &ctx.now;
		} else {
			ts = &msg->ts;
		}
		t = (time_t) ts->tv_sec;
		tm = gmtime(&t);
		strftime(when, sizeof when, "%Y-%m-%d %T", tm);
		if (msg->tp == ncap_udp) {
			fprintf(trace,
				"[%lu %s] %s.%09lu [%08x %08x] %s[%s].%d [%s].%d udp",
				(u_long)msg->paylen, label, when,
				(u_long)ts->tv_nsec, msg->user1, msg->user2,
				clos->endline, saddr, sport, daddr, dport);
		} else if (msg->tp == ncap_icmp) {
			fprintf(trace,
				"[%lu %s] %s.%09lu [%08x %08x] %s[%s] [%s] icmp [%d:%d]",
				(u_long)msg->paylen, label, when,
				(u_long)ts->tv_nsec, msg->user1, msg->user2,
				clos->endline, saddr, daddr,
				msg->tpu.icmp.type, msg->tpu.icmp.code);
		}
		if (clos->mlev >= 2)
			dump_hex(msg->payload, msg->paylen,
				 trace, clos->endline);
		if (clos->mlev >= 1 && msg->tp == ncap_udp) {
			if (sport == 53 || dport == 53 ||
			    sport == 5353 || dport == 5353)
				dump_dns(msg->payload, msg->paylen, trace,
					 clos->endline);
		}
		if (clos->mlev >= 1 && msg->tp == ncap_icmp) {
			dump_icmpdns(msg->payload, msg->paylen, trace,
				     clos->endline);
		}
		putc('\n', trace);
		if (clos->flush)
			fflush(trace);
		if (ferror(trace))
			disablesink(&clos->trace, clos);
	}

	/* Output dump data if enabled. */
	if (NCAPTOOL_SINK_ENABLED(&clos->dump)) {
		FILE *dump = clos->dump.fp;

		if (clos->count == 0)
			NCAP_OK(ncap, fwrite(ncap, NULL, dump),
				disablesink(&clos->dump, clos));
		if (NCAPTOOL_SINK_ENABLED(&clos->dump))
			NCAP_OK(ncap, fwrite(ncap, msg, dump),
				disablesink(&clos->dump, clos));
		if (NCAPTOOL_SINK_ENABLED(&clos->dump) && clos->flush)
			fflush(dump);
		if (ferror(dump))
			disablesink(&clos->dump, clos);
	}

	/* Output datagram data if enabled. */
	if (clos->stripe) {
		if (clos->dgnext == NULL)
			clos->dgnext = ISC_LIST_HEAD(clos->dgsinks);
		dgnext = ISC_LIST_NEXT(clos->dgnext, link);
		dgsend(ncap, msg, clos, clos->dgnext, ctx.now, sendfails);
		clos->dgnext = dgnext;
	} else {
		for (dgsink = ISC_LIST_HEAD(clos->dgsinks);
		     dgsink != NULL;
		     dgsink = dgnext)
		{
			dgnext = ISC_LIST_NEXT(dgsink, link);
			dgsend(ncap, msg, clos, dgsink, ctx.now, sendfails);
		}
	}

	/* Possibly sleep a bit if we've exceeded our rate for this quantum. */
	mod_sinks_open = 0;
	for (mod = ISC_LIST_HEAD(clos->msgmods);
	     mod != NULL;
	     mod = ISC_LIST_NEXT(mod, link))
	{
		if (mod->ctx.msg->sinks_open != NULL)
			mod_sinks_open += mod->ctx.msg->sinks_open();
	}
	if (clos->quant.limit != 0 &&
		(!ISC_LIST_EMPTY(clos->dgsinks) || mod_sinks_open))
	{
		if (++clos->quant.count >= clos->quant.limit) {
			struct timespec ival;

			nanonano(clos->quant.ipg);
			nanotime(&ctx.now);
			ival = ctx.now;
			TS_SUBTRACT(&ival, &clos->quant.start);
			if (ival.tv_sec == 0) {
				unsigned qrate =
					(clos->quant.count * MILLION) /
					(ival.tv_nsec / THOUSAND);

				clos->quant.limit *= clos->quant.rate;
				clos->quant.limit /= qrate;
			}
			clos->quant.start = ctx.now;
			clos->quant.count = 1;
		}
	}

	/* Possibly close the output sinks. */
	if (++clos->count == clos->count_limit) {
		assert(clos->count_limit != 0U);
		if (NCAPTOOL_SINK_ENABLED(&clos->trace))
			drainsink(&clos->trace, clos);
		if (NCAPTOOL_SINK_ENABLED(&clos->dump))
			drainsink(&clos->dump, clos);
		for (mod = ISC_LIST_HEAD(clos->msgmods);
		     mod != NULL;
		     mod = ISC_LIST_NEXT(mod, link))
		{
			if (mod->ctx.msg->drainsinks != NULL)
				mod->ctx.msg->drainsinks();
		}
		clos->count = 0U;
	}

	/* If we're out of sinks, we're out of beer. */
	mod_sinks_enab = 0;
	for (mod = ISC_LIST_HEAD(clos->msgmods);
	     mod != NULL;
	     mod = ISC_LIST_NEXT(mod, link))
	{
		if (mod->ctx.msg->sinks_enab != NULL)
			mod_sinks_open += mod->ctx.msg->sinks_enab();
	}
	if (!NCAPTOOL_SINK_ENABLED(&clos->trace) &&
	    !NCAPTOOL_SINK_ENABLED(&clos->dump) &&
	    ISC_LIST_EMPTY(clos->dgsinks) &&
	    mod_sinks_open == 0 && mod_sinks_enab == 0)
		ncap->stop(ncap);
}

/* Send a message to all dgsinks in a list.
 */
static void
dgsend(ncap_t ncap, ncap_msg_ct msg, struct ncaptool_ctx *fctx, struct ncaptool_dgsink *dgsink,
       struct timespec now, ncaptool_sendfails_func sff)
{
	int sendflags = MSG_DONTROUTE;
	int s = dgsink->dg;

	if (dgsink->embargo != 0 && dgsink->embargo > now.tv_sec)
		return;
	if (fctx->remote)
		sendflags &= ~MSG_DONTROUTE;
	if (dgsink->count == 0) {
		NCAP_OK(ncap, send(ncap, NULL, s, sendflags),
			sff(ncap, fctx, dgsink, now, errno);
			dgsink = NULL);
		nanotime(&dgsink->last_fh);
	}
	if (dgsink != NULL)
		NCAP_OK(ncap, send(ncap, msg, s, sendflags),
			sff(ncap, fctx, dgsink, now, errno);
			dgsink = NULL);
	if (dgsink != NULL) {
		time_t fh_ago = fctx->now.tv_sec - dgsink->last_fh.tv_sec;
		if (++dgsink->count == EVERY_SO_OFTEN
		    || fh_ago >= FILEHDR_SECS)
			dgsink->count = 0;
		dgsink->embargo = 0;
	}
}

/* Called when a DG send() fails, usually due to an asynchly received ICMP msg.
 */
static void
sendfails(ncap_t ncap, struct ncaptool_ctx *fctx,
	  struct ncaptool_dgsink *dgsink, struct timespec now, int syserrno)
{
	switch (syserrno) {
	case ENETDOWN:
	case ENETUNREACH:
	case ENOBUFS:
	case ETIMEDOUT:
	case ECONNREFUSED:
	case EHOSTDOWN:
	case EHOSTUNREACH:
		fprintf(stderr, "%s: DG output error, silencing for %d\n",
			ProgramName, SEND_BACKOFF);
		dgsink->embargo = now.tv_sec + SEND_BACKOFF;
		dgsink->count = 0;
		break;
	default:
		ncap->drop_dg(ncap, dgsink->dg);
		ISC_LIST_UNLINK(fctx->dgsinks, dgsink, link);
		free(dgsink);
	}
}

/* Crack a socket descriptor (addr/port).
 */
static int
getsock(ncaptool_sockaddr *su, const char *addr, unsigned *rate,
	unsigned *freq)
{
	char *tmp = strdup(addr);
	char *p = strchr(tmp, '/');
	unsigned port, pf;
	char *t;

	memset(su, 0, sizeof *su);
	if (p == NULL) {
		fprintf(stderr, "getsock: no slash found\n");
		free(tmp);
		return (-1);
	}
	*p++ = '\0';
	port = strtoul(p, &t, 0);
	if (*t == ',' && rate != NULL && freq != NULL) {
		u_long t_rate, t_freq;

		t_rate = strtoul(t+1, &t, 0);
		if (*t == ',') {
			t_freq = strtoul(t+1, &t, 0);
			if (*t != '\0') {
				fprintf(stderr, "getsock: bad frequency (%s)\n",
					addr);
				free(tmp);
				return (-1);
			}
			*freq = t_freq;
		} else if (*t != '\0') {
			fprintf(stderr, "getsock: invalid packet rate (%s)\n",
				addr);
			free(tmp);
			return (-1);
		}
		*rate = t_rate;
	}
	if (*t != '\0' || port == 0) {
		fprintf(stderr, "getsock: invalid port number\n");
		free(tmp);
		return (-1);
	}
	if (inet_pton(AF_INET6, tmp, &su->s6.sin6_addr)) {
#if HAVE_SA_LEN
		su->s6.sin6_len = sizeof su->s6;
#endif
		su->s6.sin6_family = AF_INET6;
		su->s6.sin6_port = htons(port);
		pf = PF_INET6;
	} else if (inet_pton(AF_INET, tmp, &su->s4.sin_addr)) {
#if HAVE_SA_LEN
		su->s4.sin_len = sizeof su->s4;
#endif
		su->s4.sin_family = AF_INET;
		su->s4.sin_port = htons(port);
		pf = PF_INET;
	} else {
		fprintf(stderr, "getsock: addr is not valid inet or inet6\n");
		free(tmp);
		return (-1);
	}
	return (pf);
}

/* Crack a uval.  Returns a boolean ("success").
 */
static int
getuval(const char *spec, struct ncaptool_uval *uval) {
	char *t;

	memset(uval, 0, sizeof *uval);
	switch (*spec) {
	case '+':
		uval->ut = ut_set;
		spec++;
		break;
	case '-':
		uval->ut = ut_clear;
		spec++;
		break;
	default:
		uval->ut = ut_repl;
		break;
	}
	uval->val = strtoul(spec, &t, 0);
	return (*t == '\0');
}

/* Execute a uval expression against a uval.
 */
static void
uvalexec(unsigned *val, const struct ncaptool_uval *uval) {
	switch (uval->ut) {
	case ut_none:
		break;
	case ut_repl:
		*val = uval->val;
		break;
	case ut_set:
		*val |= uval->val;
		break;
	case ut_clear:
		*val &= ~uval->val;
		break;
	default:
		abort();
	}
}

/* Crack a sink.  Returns a boolean ("success").
 */
static int
getsink(const char *spec, struct ncaptool_fpsink *sink) {
	memset(sink, 0, sizeof *sink);
	if (strcmp(spec, "-") == 0) {
		sink->st = st_stdout;
	} else {
		sink->st = st_file;
		sink->basename = strdup(spec);
	}
	return (true);
}

/* Compare two sinks.  Returns a boolean ("same").
 */
static int
samesink(const struct ncaptool_fpsink *s1, const struct ncaptool_fpsink *s2) {
	return (s1->st == s2->st &&
		(s1->st == st_stdout ||
		 (s1->st == st_file &&
		  strcmp(s1->basename, s2->basename) == 0)));
}

/* Open a sink.  Returns a boolean ("success").
 */
static int
opensink(struct ncaptool_fpsink *sink, struct timespec now, const char *ext) {
	switch (sink->st) {
	case st_none:
		break;
	case st_stdout:
		sink->fp = stdout;
		return (true);
	case st_file:
		assert(sink->tmpname == NULL);
		assert(sink->curname == NULL);
		if (ext == NULL)
			sink->curname = strdup(sink->basename);
		else
			ncap_asprintf(&sink->curname, "%s.%lu.%09lu.%s",
				      sink->basename,
				      (u_long)now.tv_sec,
				      (u_long)now.tv_nsec,
				      ext);
		assert(sink->curname != NULL);
		ncap_asprintf(&sink->tmpname, "%s.part", sink->curname);
		assert(sink->tmpname != NULL);
		sink->fp = fopen(sink->tmpname, "w");
		if (sink->fp == NULL) {
			free(sink->tmpname);
			sink->tmpname = NULL;
			free(sink->curname);
			sink->curname = NULL;
			return (false);
		}
		return (true);
	}
	abort();
}

/* Close a sink.
 */
static void
closesink(struct ncaptool_fpsink *sink, const struct ncaptool_ctx *fctx) {
	if (sink->fp != NULL) {
		fclose(sink->fp);
		sink->fp = NULL;
		if (sink->st == st_file) {
			if (rename(sink->tmpname, sink->curname) < 0) {
				perror("rename");
				unlink(sink->tmpname);
			} else if (fctx->kicker != NULL &&
				   *fctx->kicker != '\0')
			{
				char *cmd;
				int rc;

				ncap_asprintf(&cmd, "%s %s &",
					      fctx->kicker,
					      sink->curname);
				rc = system(cmd);
				if (rc != 0)
					fprintf(stderr,
						"WARNING: system() failed\n");
				free(cmd);
			}
			if (fctx->dlev >= 1)
				fprintf(stderr,
					"%s: completed %s (%u msg%s)\n",
					ProgramName,
					sink->curname,
					fctx->count,
					fctx->count == 1 ? "" : "s");
			free(sink->tmpname);
			sink->tmpname = NULL;
			free(sink->curname);
			sink->curname = NULL;
		}
	}
}

/* Disable a sink.
 */
static void
disablesink(struct ncaptool_fpsink *sink, const struct ncaptool_ctx *fctx) {
	if (NCAPTOOL_SINK_ACTIVE(sink))
		closesink(sink, fctx);
	if (sink->st == st_file) {
		free(sink->basename);
		sink->basename = NULL;
	}
	sink->st = st_none;
}

/* Close and possibly disable a sink.
 */
static void
drainsink(struct ncaptool_fpsink *sink, const struct ncaptool_ctx *fctx) {
	if (NCAPTOOL_SINK_ACTIVE(sink)) {
		closesink(sink, fctx);
		if (sink->st != st_file || fctx->kicker == NULL)
			disablesink(sink, fctx);
	}
}

/* Do the nanosleep dance.  Note that sleeping for less than the scheduler
 * granularity results in a sleep of at least the scheduler granularity, since
 * we won't be seen as runnable until the next "tick".  Good for load average,
 * bad for accuracy of realtime operations.
 */
static void
nanonano(struct timespec ts) {
	struct timespec rqt, rmt;

	for (rqt = ts; nanosleep(&rqt, &rmt) < 0 && errno == EINTR; rqt = rmt)
		;
}

/* Get nanosecond time from the kernel if it's supported, otherwise get the
 * microsecond time and scale it up, losing resolution.
 */
static void
nanotime(struct timespec *now) {
#ifdef CLOCK_REALTIME
	(void) clock_gettime(CLOCK_REALTIME, now);
#else
	struct timeval tv;
	(void) gettimeofday(&tv, NULL);
	now->tv_sec = tv.tv_sec;
	now->tv_nsec = tv.tv_usec * 1000;
#endif
}

/* Output a loose hex dump of packet payload.
 */
static void
dump_hex(const u_char *buf, size_t len, FILE *trace, const char *endline) {
	fprintf(trace, " %s", endline);
	while (len-- > 0)
		fprintf(trace, " %02x", *buf++);
}
