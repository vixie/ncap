/* ncap_create.c - wrapper around libpcap to provide higher level abstraction
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

/* Import. */

#include "ncap_port.h"
#include "ncap_port_net.h"
#include "ncap_pvt.h"

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

/* Typedefs. */

#ifdef HAVE_BPF_TIMEVAL
typedef struct bpf_timeval my_bpftimeval;
#else
typedef struct timeval my_bpftimeval;
#endif

/* Forward. */

static ncap_result_e	add_if(ncap_t, const char *netif,
			       const char *bpf, int,
			       const int vlans[], int nvlan,
			       int *fdes);
static ncap_result_e	drop_if(ncap_t, int fdes);
static ncap_result_e	add_nf(ncap_t, int fdes, const char *);
static ncap_result_e	drop_nf(ncap_t, int fdes);
static void		deactivate_nf(ncap_nf_ptr nfp);
static ncap_result_e	add_pf(ncap_t, FILE *fp, const char *);
static ncap_result_e	drop_pf(ncap_t, FILE *fp);
static ncap_result_e	add_dg(ncap_t, int fdes, const char *);
static ncap_result_e	drop_dg(ncap_t, int fdes);
static ncap_result_e	filter(ncap_t, const char *);
static ncap_result_e	collect(ncap_t, int, ncap_callback_t, void *);
static void		stop(ncap_t);
static struct ncap_msg	cons(ncap_t, struct timespec,
			     unsigned, unsigned,
			     ncap_np_e, ncap_np_ct,
			     ncap_tp_e, ncap_tp_ct,
			     size_t, const u_char *);
static int		match(ncap_t, ncap_msg_ct);
static ncap_result_e	ncap_write(ncap_t, ncap_msg_ct, int fdes);
static ncap_result_e	ncap_fwrite(ncap_t, ncap_msg_ct, FILE *fp);
static ncap_result_e	ncap_send(ncap_t, ncap_msg_ct, int fdes, int flags);
static void		destroy(ncap_t);

static void		ncap_pcap_if(u_char *, const struct pcap_pkthdr *,
				     const u_char *);
static void		ncap_pcap_pf(u_char *, const struct pcap_pkthdr *,
				     const u_char *);
static void		ncap_pcap_dl(ncap_t, int, const char *,
				     const int *, int,
				     ncap_callback_t, void *,
				     const struct pcap_pkthdr *,
				     const u_char *);
static void		ncap_pcap_np(ncap_t, const char *,
				     ncap_callback_t, void *,
				     my_bpftimeval, unsigned,
				     const u_char *, size_t);
static void		ncap_pcap_tp(ncap_t, const char *,
				     ncap_callback_t, void *,
				     my_bpftimeval, ncap_np_e, ncap_np_t,
				     unsigned, const u_char *, size_t);
static int		my_getc_refill(ncap_nf_ptr nfp);
static int		ncap_read_dgmsg(ncap_dg_ptr, ncap_callback_t, void *);
static int		ncap_read_nfmsg(ncap_nf_ptr, ncap_callback_t, void *);
static ssize_t		import_mh1(const u_char msghdr[], size_t len,
				   ncap_msg_t, size_t *, size_t *, size_t *);
static ssize_t		import_mh2(const u_char msghdr[], size_t len,
				   size_t netlen, size_t tplen, ncap_msg_t);
static size_t		export_hdr(ncap_t, u_char filehdr[]);
static ssize_t		export_msg(ncap_t, ncap_msg_ct msg, u_char msghdr[]);
static void		free_filters(ncap_t);
static void		free_filter(ncap_t, ncap_filter_ptr);

/* Constants. */

#ifndef IPV6_VERSION
# define IPV6_VERSION		0x60
#endif
#ifndef IPV6_VERSION_MASK
# define IPV6_VERSION_MASK	0xf0
#endif

#define MAX_VLAN	4095
#define TO_MS		50
#define	GRANULARITY	10
#define SNAPLEN		65536
#define	THOUSAND	1000
#define	MILLION		(THOUSAND*THOUSAND)

/* Macros. */

#define	FAILURE(m) do { \
	NCAP_SETERR(m); \
	return (ncap_failure); \
} while (0)

#define	FAILZERO(m) do { \
	NCAP_SETERR(m); \
	return (0); \
} while (0)

#define	FAILVOID(m) do { \
	NCAP_SETERR(m); \
	return; \
} while (0)

#define	MY_GETC(nfp) \
	((nfp->fbcur < nfp->fblen) \
	 ? nfp->fb[nfp->fbcur++] \
	 : my_getc_refill(nfp))

/* Private data. */

static struct ncap_filtermaker filtermakers[] = {
	{ "dns", ncap_filter_dns },
	{ "icmp", ncap_filter_icmp },
	{ NULL, NULL }
};

/* Export. */

/* Create an NCAP object and return it or return NULL on failure.
 */
ncap_t
ncap_create(int maxmsg) {
	ncap_t ncap;

	ncap = malloc(sizeof *ncap);
	if (ncap == NULL)
		return (NULL);
	memset(ncap, 0, sizeof *ncap);
	ncap->errstr = strdup("");
	if (ncap->errstr == NULL) {
		free(ncap);
		return (NULL);
	}
	ncap->pvt = malloc(sizeof *ncap->pvt);
	if (ncap->pvt == NULL) {
		free(ncap->errstr);
		free(ncap);
		return (NULL);
	}
	memset(ncap->pvt, 0, sizeof *ncap->pvt);
	ncap->pvt->reasm_ip = reasm_ip_new ();
	if (ncap->pvt->reasm_ip == NULL) {
		free(ncap->pvt);
		free(ncap->errstr);
		free(ncap);
		return (NULL);
	}
	reasm_ip_set_timeout(ncap->pvt->reasm_ip, 60);
	ncap->pvt->maxmsg = maxmsg;
	ISC_LIST_INIT(ncap->pvt->ifs);
	ISC_LIST_INIT(ncap->pvt->nfs);
	ISC_LIST_INIT(ncap->pvt->pfs);
	ISC_LIST_INIT(ncap->pvt->dgs);
	FD_ZERO(&ncap->pvt->fdset);
	ncap->add_if = add_if;
	ncap->drop_if = drop_if;
	ncap->add_nf = add_nf;
	ncap->drop_nf = drop_nf;
	ncap->add_pf = add_pf;
	ncap->drop_pf = drop_pf;
	ncap->add_dg = add_dg;
	ncap->drop_dg = drop_dg;
	ncap->filter = filter;
	ncap->collect = collect;
	ncap->stop = stop;
	ncap->cons = cons;
	ncap->match = match;
	ncap->write = ncap_write;
	ncap->fwrite = ncap_fwrite;
	ncap->send = ncap_send;
	ncap->destroy = destroy;
	return (ncap);
}

/* Methods. */

/* Add an interface to an NCAP object.
 */
static ncap_result_e
add_if(ncap_t ncap, const char *name,
       const char *bpf, int promisc,
       const int vlans[], int nvlan,
       int *ret_fdes)
{
#ifdef __APPLE__
	unsigned int ioarg = 1;
#endif
	char errbuf[PCAP_ERRBUF_SIZE];
	ncap_if_ptr ifp;
	pcap_t *pcap;
	char *dynbpf;

	/* Get the pcap open and condition it. */
	pcap = pcap_open_live(name, SNAPLEN, promisc, TO_MS, errbuf);
	if (pcap == NULL)
		FAILURE(errbuf);
	if (pcap_setnonblock(pcap, true, errbuf) < 0) {
		pcap_close(pcap);
		FAILURE(errbuf);
	}

	/* If we've got filters, gang the BPF's out of them. */
	dynbpf = NULL;
	if (!ISC_LIST_EMPTY(ncap->pvt->filters)) {
		ncap_filter_ptr filt;

		if (bpf != NULL) {
			pcap_close(pcap);
			FAILURE("add_if(BPF) incompatible with filter()");
		}
		for (filt = ISC_LIST_HEAD(ncap->pvt->filters);
		     filt != NULL;
		     filt = ISC_LIST_NEXT(filt, link))
		{
			if (filt->bpf == NULL || *filt->bpf == '\0')
				continue;
			if (dynbpf == NULL) {
				dynbpf = strdup(filt->bpf);
				assert(dynbpf != NULL);
			} else {
				char *new;

				ncap_asprintf(&new, "(%s) or (%s)",
					      dynbpf, filt->bpf);
				assert(new != NULL);
				free(dynbpf);
				dynbpf = new;
			}
		}
		bpf = dynbpf;
	}

	if (bpf != NULL) {
		struct bpf_program bpfp;
		char *bpft;

		/* Ask for fragments in addition to the caller's prefs.
		 */
		if (ncap_asprintf(&bpft, "(%s) or (%s) or (%s)",
				  "ip[6:2] & 0x1fff != 0",
				  "ip6",
				  bpf) < 0)
		{
			pcap_close(pcap);
			FAILURE("asprintf failed");
		}

		/* Ask for VLANs if nec'y. */
		if (nvlan != 0) {
			char *new;

			if (ncap_asprintf(&new, "vlan and (%s)", bpft) < 0) {
				free(bpft);
				pcap_close(pcap);
				FAILURE("asprintf failed");
			}
			free(bpft);
			bpft = new;
		}

		if (pcap_compile(pcap, &bpfp, bpft, true, 0) < 0 ||
		    pcap_setfilter(pcap, &bpfp) < 0)
		{
			strcpy(errbuf, pcap_geterr(pcap));
			pcap_close(pcap);
			FAILURE(errbuf);
		}
		pcap_freecode(&bpfp);
		free(bpft);
	}
	if (dynbpf != NULL)
		free(dynbpf);

	/* Save it. */
	ifp = malloc(sizeof *ifp);
	if (ifp == NULL) {
		pcap_close(pcap);
		FAILURE("malloc failed");
	}
	memset(ifp, 0, sizeof *ifp);
	ISC_LINK_INIT(ifp, link);
	ifp->ncap = ncap;
	ifp->pcap = pcap;
	ifp->dlt = pcap_datalink(pcap);
	ifp->fdes = pcap_get_selectable_fd(pcap);
#ifdef __APPLE__
	ioctl(ifp->fdes, BIOCIMMEDIATE, &ioarg);
#endif
	if (nvlan != 0) {
		ifp->vlans = malloc(nvlan * sizeof vlans[0]);
		if (ifp->vlans == NULL) {
			pcap_close(pcap);
			free(ifp);
			FAILURE("malloc failed");
		}
		memcpy(ifp->vlans, vlans, nvlan * sizeof vlans[0]);
		ifp->nvlan = nvlan;
	}
	ncap_asprintf(&ifp->label, "pcap if %s", name);
	if (ifp->label == NULL) {
		pcap_close(pcap);
		free(ifp->vlans);
		free(ifp);
		FAILURE("asprintf failed");
	}
	ISC_LIST_APPEND(ncap->pvt->ifs, ifp, link);

	/* Side effects. */
	assert(!FD_ISSET(ifp->fdes, &ncap->pvt->fdset));
	FD_SET(ifp->fdes, &ncap->pvt->fdset);
	if (ret_fdes != NULL)
		*ret_fdes = ifp->fdes;
	if (ifp->fdes > ncap->pvt->highest_fd)
		ncap->pvt->highest_fd = ifp->fdes;

	return (ncap_success);
}

/* Drop an interface from an NCAP object.
 */
static ncap_result_e
drop_if(ncap_t ncap, int fdes) {
	ncap_if_ptr ifp;

	for (ifp = ISC_LIST_HEAD(ncap->pvt->ifs);
	     ifp != NULL;
	     ifp = ISC_LIST_NEXT(ifp, link))
		if (pcap_get_selectable_fd(ifp->pcap) == fdes)
			break;
	if (ifp == NULL)
		FAILURE("no matching fdes");
	ISC_LIST_UNLINK(ncap->pvt->ifs, ifp, link);
	assert(FD_ISSET(fdes, &ncap->pvt->fdset));
	FD_CLR(fdes, &ncap->pvt->fdset);
	if (ifp->vlans != NULL)
		free(ifp->vlans);
	free(ifp->label);
	free(ifp);
	return (ncap_success);

}

/* Add an NCAP input file to an NCAP object.
 */
static ncap_result_e
add_nf(ncap_t ncap, int fdes, const char *nf_label) {
	ncap_nf_ptr nfp;

	/* Check it. */
	if (FD_ISSET(fdes, &ncap->pvt->fdset))
		FAILURE("fdes already selected");

	/* Save it. */
	nfp = malloc(sizeof *nfp);
	if (nfp == NULL)
		FAILURE("malloc failed");
	memset(nfp, 0, sizeof *nfp);
	ISC_LINK_INIT(nfp, link);
	ISC_LIST_APPEND(ncap->pvt->nfs, nfp, link);
	nfp->ncap = ncap;
	nfp->fdes = fdes;
	ncap_asprintf(&nfp->label, "nf %s", nf_label);
	if (nfp->label == NULL)
		FAILURE("asprintf failed");

	/* Side effects. */
	FD_SET(nfp->fdes, &ncap->pvt->fdset);
	if (nfp->fdes > ncap->pvt->highest_fd)
		ncap->pvt->highest_fd = nfp->fdes;
	fcntl(nfp->fdes, F_SETFL, fcntl(nfp->fdes, F_GETFL) | O_NONBLOCK);

	return (ncap_success);
}

/* Drop an NCAP input file from an NCAP object.
 */
static ncap_result_e
drop_nf(ncap_t ncap, int fdes) {
	ncap_nf_ptr nfp;

	for (nfp = ISC_LIST_HEAD(ncap->pvt->nfs);
	     nfp != NULL;
	     nfp = ISC_LIST_NEXT(nfp, link))
		if (nfp->fdes == fdes)
			break;
	if (nfp == NULL)
		FAILURE("no matching nf");
	ISC_LIST_UNLINK(ncap->pvt->nfs, nfp, link);
	if (nfp->label != NULL)
		deactivate_nf(nfp);
	free(nfp);
	return (ncap_success);
}

/* Remove an NCAP input file from consideration by select().
 */
static void
deactivate_nf(ncap_nf_ptr nfp) {
	assert(FD_ISSET(nfp->fdes, &nfp->ncap->pvt->fdset));
	FD_CLR(nfp->fdes, &nfp->ncap->pvt->fdset);
	if (nfp->varbuf != NULL) {
		free(nfp->varbuf);
		nfp->varbuf = NULL;
		nfp->varsiz = 0;
	}
	free(nfp->label);
	nfp->label = NULL;
}

/* Add a PCAP input file to an NCAP object.
 */
static ncap_result_e
add_pf(ncap_t ncap, FILE *fp, const char *pf_label) {
	char errbuf[PCAP_ERRBUF_SIZE];
	ncap_pf_ptr pfp;
	pcap_t *pcap;

	pcap = pcap_fopen_offline(fp, errbuf);
	if (pcap == NULL)
		FAILURE(errbuf);

	/* Save it. */
	pfp = malloc(sizeof *pfp);
	if (pfp == NULL) {
		if (pcap != NULL)
			pcap_close(pcap);
		FAILURE("malloc failed");
	}
	ISC_LINK_INIT(pfp, link);
	ISC_LIST_APPEND(ncap->pvt->pfs, pfp, link);
	pfp->ncap = ncap;
	pfp->fp = fp;
	ncap_asprintf(&pfp->label, "pf %s", pf_label);
	if (pfp->label == NULL) {
		pcap_close(pcap);
		FAILURE("asprintf failed");
	}
	pfp->pcap = pcap;
	pfp->fdes = pcap_get_selectable_fd(pcap);
	pfp->dlt = pcap_datalink(pcap);

	/* Side effects. */
	assert(!FD_ISSET(pfp->fdes, &ncap->pvt->fdset));
	FD_SET(pfp->fdes, &ncap->pvt->fdset);
	if (pfp->fdes > ncap->pvt->highest_fd)
		ncap->pvt->highest_fd = pfp->fdes;

	return (ncap_success);
}

/* Drop a PCAP input file from an NCAP object.
 */
static ncap_result_e
drop_pf(ncap_t ncap, FILE *fp) {
	ncap_pf_ptr pfp;

	for (pfp = ISC_LIST_HEAD(ncap->pvt->pfs);
	     pfp != NULL;
	     pfp = ISC_LIST_NEXT(pfp, link))
		if (pfp->fp == fp)
			break;
	if (pfp == NULL)
		FAILURE("no matching pfes");
	ISC_LIST_UNLINK(ncap->pvt->pfs, pfp, link);
	assert(FD_ISSET(pfp->fdes, &ncap->pvt->fdset));
	FD_CLR(pfp->fdes, &ncap->pvt->fdset);
	pcap_close(pfp->pcap);
	free(pfp->label);
	free(pfp);
	return (ncap_success);
}

static ncap_result_e
add_dg(ncap_t ncap, int fdes, const char *dg_label) {
	ncap_dg_ptr dgp;

	/* Check it. */
	if (FD_ISSET(fdes, &ncap->pvt->fdset))
		FAILURE("fdes already selected");

	/* Save it. */
	dgp = malloc(sizeof *dgp);
	if (dgp == NULL)
		FAILURE("malloc failed");
	ISC_LINK_INIT(dgp, link);
	ISC_LIST_APPEND(ncap->pvt->dgs, dgp, link);
	dgp->ncap = ncap;
	dgp->fdes = fdes;
	ncap_asprintf(&dgp->label, "dg %s", dg_label);
	if (dgp->label == NULL) {
		free(dgp);
		FAILURE("asprintf failed");
	}

	/* Side effects. */
	FD_SET(dgp->fdes, &ncap->pvt->fdset);
	if (dgp->fdes > ncap->pvt->highest_fd)
		ncap->pvt->highest_fd = dgp->fdes;
	fcntl(dgp->fdes, F_SETFL, fcntl(dgp->fdes, F_GETFL) | O_NONBLOCK);

	return (ncap_success);
}

static ncap_result_e
drop_dg(ncap_t ncap, int fdes) {
	ncap_dg_ptr dgp;

	for (dgp = ISC_LIST_HEAD(ncap->pvt->dgs);
	     dgp != NULL;
	     dgp = ISC_LIST_NEXT(dgp, link))
		if (dgp->fdes == fdes)
			break;
	if (dgp == NULL)
		FAILURE("no matching fdes");
	ISC_LIST_UNLINK(ncap->pvt->dgs, dgp, link);
	assert(FD_ISSET(fdes, &ncap->pvt->fdset));
	FD_CLR(fdes, &ncap->pvt->fdset);
	free(dgp->label);
	free(dgp);
	return (ncap_success);
}

/* Install an NCAP filter, specified in ASCII text.
 */
static ncap_result_e
filter(ncap_t ncap, const char *ospec) {
	char *spec = strdup(ospec);
	ncap_filtermaker_ptr fmp;
	ncap_filter_ptr filt;
	char *word;

	free_filters(ncap);
	filt = NULL;
	fmp = NULL;
	for (word = strtok(spec, "\040\t");
	     word != NULL;
	     word = strtok(NULL, "\040\t"))
	{
		char *arg;

		arg = strchr(word, '=');
		if (arg == NULL)
			arg = strchr(word, '#');
		if (arg == NULL) {
			for (fmp = filtermakers; fmp->name != NULL; fmp++)
				if (strcasecmp(word, fmp->name) == 0)
					break;
			if (fmp->name == NULL) {
				NCAP_SETERR("filter family name not recognized");
				goto failure;
			}
			filt = malloc(sizeof *filt);
			assert(filt != NULL);
			memset(filt, 0, sizeof *filt);
			ISC_LINK_INIT(filt, link);
			ISC_LIST_INIT(filt->rules);
			ISC_LIST_APPEND(ncap->pvt->filters, filt, link);
			filt->bpf = (*fmp->rulemaker)(ncap, NULL, '\0', NULL);
			assert(filt->bpf != NULL);
		} else {
			char sep, *add;

			if (fmp == NULL) {
				NCAP_SETERR("filter term without a family");
				goto failure;
			}
			sep = *arg;
			*arg++ = '\0';
			add = (*fmp->rulemaker)(ncap, word, sep, arg);
			if (add == NULL)
				goto failure;
			if (add[0] != '\0') {
				char *new;

				ncap_asprintf(&new, "%s and (%s)",
					      filt->bpf, add);
				assert(new != NULL);
				free(filt->bpf);
				filt->bpf = new;
			}
			free(add);
		}
	}
	free(spec);
	return (ncap_success);
 failure:
	if (filt != NULL)
		free_filter(ncap, filt);
	free(spec);
	return (ncap_failure);
}

/* Collect and process packets from an NCAP's data sources.
 */
static ncap_result_e
collect(ncap_t ncap, int polling, ncap_callback_t callback, void *closure) {
	ncap->pvt->flags &= ~(NCAP_STOPPING|NCAP_FAILURE);
	do {
		ncap_if_ptr ifp, ifpn;
		ncap_nf_ptr nfp, nfpn;
		ncap_pf_ptr pfp, pfpn;
		ncap_dg_ptr dgp, dgpn;
		fd_set readfds;
		int n, i;

		do {
			static struct timeval tv_zero;

			if (ISC_LIST_EMPTY(ncap->pvt->ifs) &&
			    ISC_LIST_EMPTY(ncap->pvt->nfs) &&
			    ISC_LIST_EMPTY(ncap->pvt->pfs) &&
			    ISC_LIST_EMPTY(ncap->pvt->dgs))
				return (ncap_success);
			memcpy(&readfds, &ncap->pvt->fdset, sizeof(fd_set));
			n = select(ncap->pvt->highest_fd + 1,
				   &readfds, NULL, NULL,
				   polling ? &tv_zero : NULL);
			if ((ncap->pvt->flags & NCAP_STOPPING) != 0)
				return (ncap_success);
		} while (n < 0 && errno == EINTR);
		if (n < 0)
			FAILURE("select failed");

		for (ifp = ISC_LIST_HEAD(ncap->pvt->ifs);
		     ifp != NULL;
		     ifp = ifpn)
		{
			ifpn = ISC_LIST_NEXT(ifp, link);
			if (FD_ISSET(ifp->fdes, &readfds)) {
				struct ncap_if_closure ic;

				ic.callback = callback;
				ic.closure = closure;
				ic.ifp = ifp;
				n = pcap_dispatch(ifp->pcap, -1,
						  ncap_pcap_if,
						  (u_char *)&ic);
				if (n == -1 && errno != EAGAIN) {
					char tmp[99];

					strcpy(tmp, "pcap_dispatch");
					pcap_perror(ifp->pcap, tmp);
					drop_if(ncap, ifp->fdes);
				}
				if ((ncap->pvt->flags & NCAP_STOPPING) != 0)
					return (ncap_success);
				if ((ncap->pvt->flags & NCAP_FAILURE) != 0)
					return (ncap_failure);
			}
		}

		for (nfp = ISC_LIST_HEAD(ncap->pvt->nfs);
		     nfp != NULL;
		     nfp = nfpn)
		{
			nfpn = ISC_LIST_NEXT(nfp, link);
			if (FD_ISSET(nfp->fdes, &readfds)) {
				for (i = 0; i < GRANULARITY; i++) {
					n = ncap_read_nfmsg(nfp,
							    callback,
							    closure);
					if (n == -1) {
						drop_nf(ncap, nfp->fdes);
						break;
					} else if (n == -2) {
						if (errno == EAGAIN)
							break;
						return (ncap_failure);
					}
				}
				if ((ncap->pvt->flags & NCAP_STOPPING) != 0)
					return (ncap_success);
				if ((ncap->pvt->flags & NCAP_FAILURE) != 0)
					return (ncap_failure);
			}
		}

		for (pfp = ISC_LIST_HEAD(ncap->pvt->pfs);
		     pfp != NULL;
		     pfp = pfpn)
		{
			pfpn = ISC_LIST_NEXT(pfp, link);
			if (FD_ISSET(pfp->fdes, &readfds)) {
				struct ncap_pf_closure fc;

				fc.callback = callback;
				fc.closure = closure;
				fc.pfp = pfp;
				/* Do the whole file at once, since stdio
				 * and select() have an impedence mismatch.
				 */
				n = pcap_dispatch(pfp->pcap, -1,
						  ncap_pcap_pf,
						  (u_char *)&fc);
				if (n == -1) {
					char tmp[99];

					strcpy(tmp, "pcap_dispatch");
					pcap_perror(pfp->pcap, tmp);
				}
				drop_pf(ncap, pfp->fp);
				if ((ncap->pvt->flags & NCAP_STOPPING) != 0)
					return (ncap_success);
				if ((ncap->pvt->flags & NCAP_FAILURE) != 0)
					return (ncap_failure);
			}
		}

		for (dgp = ISC_LIST_HEAD(ncap->pvt->dgs);
		     dgp != NULL;
		     dgp = dgpn)
		{
			dgpn = ISC_LIST_NEXT(dgp, link);
			if (FD_ISSET(dgp->fdes, &readfds)) {
				for (i = 0; i < GRANULARITY; i++) {
					if (ncap_read_dgmsg(dgp, callback,
							    closure) == 0)
						break;
					if ((ncap->pvt->flags &
					     NCAP_STOPPING) != 0)
						return (ncap_success);
					if ((ncap->pvt->flags &
					     NCAP_FAILURE) != 0)
						return (ncap_failure);
				}
			}
		}
	} while (!polling);
	return (ncap_success);
}

static struct ncap_msg
cons(ncap_t ncap __attribute__((unused)), struct timespec ts,
     unsigned user1, unsigned user2,
     ncap_np_e np, ncap_np_ct npu,
     ncap_tp_e tp, ncap_tp_ct tpu,
     size_t paylen, const u_char *payload)
{
	struct ncap_msg msg;

	memset(&msg, 0, sizeof msg);
	msg.ts = ts;
	msg.user1 = user1;
	msg.user2 = user2;
	msg.np = np;
	msg.tp = tp;
	msg.paylen = paylen;
	msg.npu = *npu;
	msg.tpu = *tpu;
	msg.payload = payload;
	return (msg);
}

/* Stop a collect() if one is running.
 *
 * Note: can be called from a signal handler or from a collect callback.
 */
static void
stop(ncap_t ncap) {
	ncap->pvt->flags |= NCAP_STOPPING;
}

/* Test a message against an installed filter (if any).
 *
 * Every rule in some filter has to match.
 */
static int
match(ncap_t ncap, ncap_msg_ct msg) {
	ncap_filter_ptr filt;

	/* If there are no filters, then all msgs are considered matching. */
	if (ISC_LIST_EMPTY(ncap->pvt->filters))
		return (true);

	/* Test every filter. */
	for (filt = ISC_LIST_HEAD(ncap->pvt->filters);
	     filt != NULL;
	     filt = ISC_LIST_NEXT(filt, link))
	{
		ncap_rule_ptr rule;

		assert(!ISC_LIST_EMPTY(filt->rules));

		/* Test every rule. */
		for (rule = ISC_LIST_HEAD(filt->rules);
		     rule != NULL;
		     rule = ISC_LIST_NEXT(rule, link))
			if (!(*rule->match)(rule, msg))
				break;

		/* Did all rules in the filter match? */
		if (rule == NULL)
			return (true);
	}

	/* No filter matched. */
	return (false);
}

/* Write an NCAP MSG to an output file in export format.
 */
static ncap_result_e
ncap_write(ncap_t ncap, ncap_msg_ct msg, int fdes) {
	static u_char padding[NCAP_PADFACTOR];
	u_char fixedbuf[NCAP_MSGHDR + NCAP_NETHDR + NCAP_TPHDR], *p;
	ssize_t fixedlen, msglen, msgpad, writ;
	struct iovec iov[3];
	int iovlen;

	/* If there is no message, we're writing a file header. */
	if (msg == NULL) {
		u_char filebuf[NCAP_FILEHDR];
		ssize_t len;

		len = export_hdr(ncap, filebuf);
		assert(len == NCAP_FILEHDR);
		writ = write(fdes, filebuf, len);
		if (writ < 0)
			FAILURE(strerror(errno));
		if (writ < len) {
			errno = 0;
			FAILURE("short write()");
		}
		return (ncap_success);
	}

	/* Make a header, then fix overall length. */
	fixedlen = export_msg(ncap, msg, fixedbuf);
	if (fixedlen < 0) {
		errno = 0;
		return (ncap_failure);
	}
	msglen = fixedlen + msg->paylen;
	msgpad = (msglen % NCAP_PADFACTOR);
	if (msgpad != 0) {
		msgpad = NCAP_PADFACTOR - msgpad;
		msglen += msgpad;
	}
	p = fixedbuf;
	NCAP_PUT32(msglen, p);

	iovlen = 0;
	iov[iovlen].iov_base = (void *) fixedbuf;
	iov[iovlen].iov_len = fixedlen;
	iovlen++;
	/* Note: casting to (u_long) is done to strip off "const". */
	iov[iovlen].iov_base = (void *) (u_long) msg->payload;
	iov[iovlen].iov_len = msg->paylen;
	iovlen++;
	if (msgpad != 0) {
		iov[iovlen].iov_base = (void *) padding;
		iov[iovlen].iov_len = msgpad;
		iovlen++;
	}
	writ = writev(fdes, iov, iovlen);
	if (writ < 0)
		FAILURE(strerror(errno));
	if (writ < (ssize_t)(fixedlen + msg->paylen + msgpad)) {
		errno = 0;
		FAILURE("short send()");
	}
	return (ncap_success);
}

/* Write an NCAP MSG to an output stream in export format.
 */
static ncap_result_e
ncap_fwrite(ncap_t ncap, ncap_msg_ct msg, FILE *fp) {
	static const u_char padding[NCAP_PADFACTOR];
	u_char fixedbuf[NCAP_MSGHDR + NCAP_NETHDR + NCAP_TPHDR], *p;
	ssize_t fixedlen, msglen, msgpad;
	size_t writ;

	/* If there is no message, we're writing a file header. */
	if (msg == NULL) {
		u_char filebuf[NCAP_FILEHDR];
		ssize_t len;

		len = export_hdr(ncap, filebuf);
		assert(len == NCAP_FILEHDR);
		writ = fwrite(filebuf, 1, len, fp);
		if ((ssize_t)writ != len)
			FAILURE(strerror(errno));
		return (ncap_success);
	}

	/* Make a header, then fix overall length. */
	fixedlen = export_msg(ncap, msg, fixedbuf);
	if (fixedlen < 0) {
		errno = 0;
		return (ncap_failure);
	}
	msglen = fixedlen + msg->paylen;
	msgpad = (msglen % NCAP_PADFACTOR);
	if (msgpad != 0) {
		msgpad = NCAP_PADFACTOR - msgpad;
		msglen += msgpad;
	}
	p = fixedbuf;
	NCAP_PUT32(msglen, p);

	writ = fwrite(fixedbuf, 1, fixedlen, fp);
	if ((ssize_t)writ != fixedlen)
		FAILURE(strerror(errno));
	writ = fwrite(msg->payload, 1, msg->paylen, fp);
	if (writ != msg->paylen)
		FAILURE(strerror(errno));
	if (msgpad != 0) {
		writ = fwrite(padding, 1, msgpad, fp);
		if ((ssize_t)writ != msgpad)
			FAILURE(strerror(errno));
	}
	return (ncap_success);
}

/* Write an NCAP MSG to an output socket in export format.
 */
static ncap_result_e
ncap_send(ncap_t ncap, ncap_msg_ct msg, int fdes, int flags) {
	static u_char padding[NCAP_PADFACTOR];
	u_char fixedbuf[NCAP_MSGHDR + NCAP_NETHDR + NCAP_TPHDR], *p;
	ssize_t fixedlen, msglen, msgpad, writ;
	struct iovec iov[3];
	struct msghdr mh;
	int iovlen;

	/* If there is no message, we're writing a file header. */
	if (msg == NULL) {
		u_char filebuf[NCAP_FILEHDR];
		ssize_t len;

		len = export_hdr(ncap, filebuf);
		assert(len == NCAP_FILEHDR);
		writ = send(fdes, filebuf, len, flags);
		if (writ < 0)
			FAILURE(strerror(errno));
		if (writ < len) {
			errno = 0;
			FAILURE("short send()");
		}
		return (ncap_success);
	}

	/* Make a header, then fix overall length. */
	fixedlen = export_msg(ncap, msg, fixedbuf);
	if (fixedlen < 0) {
		errno = 0;
		return (ncap_failure);
	}
	msglen = fixedlen + msg->paylen;
	msgpad = (msglen % NCAP_PADFACTOR);
	if (msgpad != 0) {
		msgpad = NCAP_PADFACTOR - msgpad;
		msglen += msgpad;
	}
	p = fixedbuf;
	NCAP_PUT32(msglen, p);

	iovlen = 0;
	iov[iovlen].iov_base = (void *) fixedbuf;
	iov[iovlen].iov_len = fixedlen;
	iovlen++;
	/* Note: casting to (u_long) is done to strip off "const". */
	iov[iovlen].iov_base = (void *) (u_long) msg->payload;
	iov[iovlen].iov_len = msg->paylen;
	iovlen++;
	if (msgpad != 0) {
		iov[iovlen].iov_base = (void *) padding;
		iov[iovlen].iov_len = msgpad;
		iovlen++;
	}

	memset(&mh, 0, sizeof mh);
	mh.msg_iov = iov;
	mh.msg_iovlen = iovlen;
	writ = sendmsg(fdes, &mh, flags);
	if (writ < 0)
		FAILURE(strerror(errno));
	if (writ < (ssize_t)(fixedlen + msg->paylen + msgpad)) {
		errno = 0;
		FAILURE("short send()");
	}
	return (ncap_success);
}

/* Destroy an NCAP object.
 */
static void
destroy(ncap_t ncap) {
	ncap_if_ptr ifp;
	ncap_nf_ptr nfp;
	ncap_pf_ptr pfp;
	ncap_dg_ptr dgp;

	free_filters(ncap);
	while ((ifp = ISC_LIST_HEAD(ncap->pvt->ifs)) != NULL)
		drop_if(ncap, ifp->fdes);
	while ((nfp = ISC_LIST_HEAD(ncap->pvt->nfs)) != NULL)
		drop_nf(ncap, nfp->fdes);
	while ((pfp = ISC_LIST_HEAD(ncap->pvt->pfs)) != NULL)
		drop_pf(ncap, pfp->fp);
	while ((dgp = ISC_LIST_HEAD(ncap->pvt->dgs)) != NULL)
		drop_dg(ncap, dgp->fdes);
	if (ncap->pvt->msgbuf != NULL)
		free(ncap->pvt->msgbuf);
	reasm_ip_free(ncap->pvt->reasm_ip);
	free(ncap->pvt);
	free(ncap->errstr);
	free(ncap);
}

/* Quasi-private. */

/* Add a rule to the current filter.
 */
void
ncap_addrule(ncap_t ncap, ncap_match_ptr matchfunc,
	     void *payload, unsigned argument)
{
	ncap_rule_ptr rule;

	rule = malloc(sizeof *rule);
	assert(rule != NULL);
	memset(rule, 0, sizeof *rule);
	ISC_LINK_INIT(rule, link);
	rule->match = matchfunc;
	rule->payload = payload;
	rule->argument = argument;
	ISC_LIST_APPEND(ISC_LIST_TAIL(ncap->pvt->filters)->rules, rule, link);
}

/* Private. */

/* Trampoline code from PCAP ifp callback to ncap_pcap_dl().
 */
static void
ncap_pcap_if(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
	ncap_if_closure_t ic = (ncap_if_closure_t) user;
	ncap_if_ptr ifp = ic->ifp;

	ncap_pcap_dl(ifp->ncap, ifp->dlt, ifp->label, ifp->vlans, ifp->nvlan,
		     ic->callback, ic->closure, h, bytes);
	if ((ifp->ncap->pvt->flags & NCAP_STOPPING) != 0)
		pcap_breakloop(ifp->pcap);
}

/* Trampoline code from PCAP file callback to ncap_pcap_dl().
 */
static void
ncap_pcap_pf(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes){
	ncap_pf_closure_t fc = (ncap_pf_closure_t) user;
	ncap_pf_ptr pfp = fc->pfp;

	ncap_pcap_dl(pfp->ncap, pfp->dlt, pfp->label, NULL, 0,
		     fc->callback, fc->closure, h, bytes);
	if ((pfp->ncap->pvt->flags & NCAP_STOPPING) != 0)
		pcap_breakloop(pfp->pcap);
}

/* Process a PCAP PKT and crack the datalink headers.
 */
static void
ncap_pcap_dl(ncap_t ncap, int dlt, const char *label,
	     const int *vlans, int nvlan,
	     ncap_callback_t callback, void *closure,
	     const struct pcap_pkthdr *h, const u_char *pkt)
{
	unsigned etype, vlan, pf;
	size_t len = h->caplen;

	/* If ever SNAPLEN wasn't big enough, we have no recourse. */
	if (h->len != h->caplen)
		return;

	/* Data link. */
	vlan = 0;
	switch (dlt) {
	case DLT_NULL: {
		unsigned x;

		if (len < sizeof(int32_t))
			return;
		x = *(const uint32_t *)pkt;
		if (x == PF_INET)
			etype = ETHERTYPE_IP;
		else if (x == PF_INET6)
			etype = ETHERTYPE_IPV6;
		else
			return;
		pkt += sizeof(int32_t);
		len -= sizeof(int32_t);
		break;
	    }
	case DLT_LOOP: {
		unsigned x;

		if (len < sizeof(int32_t))
			return;
		NCAP_GET32(x, pkt);
		len -= sizeof(int32_t);
		if (x == PF_INET)
			etype = ETHERTYPE_IP;
		else if (x == PF_INET6)
			etype = ETHERTYPE_IPV6;
		else
			return;
		break;
	    }
	case DLT_EN10MB: {
		const struct ether_header *ether;

		if (len < ETHER_HDR_LEN)
			return;
		ether = (const struct ether_header *) pkt;
		etype = ntohs(ether->ether_type);
		pkt += ETHER_HDR_LEN;
		len -= ETHER_HDR_LEN;
		if (etype == ETHERTYPE_VLAN) {
			if (len < 4)
				return;
			vlan = ntohs(*(const uint16_t *) pkt);
			pkt += 2;
			len -= 2;
			if (vlan < 1 || vlan > MAX_VLAN)
				return;
			etype = ntohs(*(const uint16_t *) pkt);
			pkt += 2;
			len -= 2;
		}
		break;
	    }
#ifdef DLT_LINUX_SLL
	case DLT_LINUX_SLL: {
		if (len < 16)
			return;
		etype = ntohs(*(const uint16_t *) &pkt[14]);
		pkt += 16;
		len -= 16;
		break;
	    }
#endif
	default:
		return;
	}

	if (nvlan == 0) {
		if (vlan != 0)
			return;
	} else {
		int vl;

		for (vl = 0; vl < nvlan; vl++)
			if (vlans[vl] == 0 || (unsigned)vlans[vl] == vlan)
				break;
		if (vl == nvlan)
			return;
	}

	switch (etype) {
	case ETHERTYPE_IP:
		pf = PF_INET;
		break;
	case ETHERTYPE_IPV6:
		pf = PF_INET6;
		break;
	default:
		return;
	}

	ncap_pcap_np(ncap, label, callback, closure, h->ts, pf, pkt, len);
}

/* Process a PCAP packet and try to crack the network headers.
 */
static void
ncap_pcap_np(ncap_t ncap, const char *label,
	     ncap_callback_t callback, void *closure,
	     my_bpftimeval ts, unsigned pf,
	     const u_char *pkt, size_t len)
{
	unsigned proto;
	union ncap_np npu;
	ncap_np_e np;
	int is_fragment = 0;
	unsigned frag_hdr_offset = 0;
	const u_char *const orig_pkt = pkt;
	const size_t orig_len = len;

	/* Fix the timestamp, which some operating systems snarl up. */
	while (ts.tv_usec >= MILLION) {
		ts.tv_sec++;
		ts.tv_usec -= MILLION;
	}

	/* Crack the network headers. */
	memset(&np, 0, sizeof np);
	switch (pf) {
	case PF_INET: {
		const struct ip *ip;
		unsigned x;

		if (len < sizeof *ip)
			return;
		ip = (const struct ip *) pkt;
		if (ip->ip_v != IPVERSION)
			return;
		proto = ip->ip_p;
		np = ncap_ip4;
		memcpy(&npu.ip4.src, &ip->ip_src, sizeof(struct in_addr));
		memcpy(&npu.ip4.dst, &ip->ip_dst, sizeof(struct in_addr));
		x = ip->ip_hl << 2;
		if (len <= x)
			return;
		pkt += x;
		len -= x;
		x = ntohs(ip->ip_off);
		is_fragment = (x & IP_OFFMASK) != 0 || (x & IP_MF) != 0;
		break;
	    }
	case PF_INET6: {
		const struct ip6_hdr *ipv6;
		uint16_t payload_len;
		uint8_t nexthdr;
		unsigned thusfar;

		if (len < sizeof *ipv6)
			return;
		ipv6 = (const struct ip6_hdr *) pkt;
		if ((ipv6->ip6_vfc & IPV6_VERSION_MASK) != IPV6_VERSION)
			return;

		nexthdr = ipv6->ip6_nxt;
		thusfar = sizeof(struct ip6_hdr);
		payload_len = ntohs(ipv6->ip6_plen);

		np = ncap_ip6;
		memcpy(&npu.ip6.src, &ipv6->ip6_src, sizeof(struct in6_addr));
		memcpy(&npu.ip6.dst, &ipv6->ip6_dst, sizeof(struct in6_addr));

                while (nexthdr == IPPROTO_ROUTING ||	/* routing header */
		       nexthdr == IPPROTO_HOPOPTS ||	/* Hop-by-Hop opts */
		       nexthdr == IPPROTO_FRAGMENT ||	/* fragmentation hdr */
		       nexthdr == IPPROTO_DSTOPTS ||	/* destination opts */
		       nexthdr == IPPROTO_AH ||		/* destination opts */
		       nexthdr == IPPROTO_ESP)		/* encap sec payload */
		{
			struct {
				uint8_t nexthdr;
				uint8_t length;
			} ext_hdr;
			uint16_t ext_hdr_len;

			/* Catch broken packets */
			if ((thusfar + sizeof ext_hdr) > len)
				return;

			if (nexthdr == IPPROTO_FRAGMENT) {
				is_fragment = 1;
				frag_hdr_offset = thusfar;
				break;
			}

			memcpy(&ext_hdr, (const u_char *)ipv6 + thusfar,
			       sizeof ext_hdr);
			nexthdr = ext_hdr.nexthdr;
			ext_hdr_len = (8 * (ntohs(ext_hdr.length) + 1));

			if (ext_hdr_len > payload_len)
				return;

			thusfar += ext_hdr_len;
			payload_len -= ext_hdr_len;
		}

		if ((thusfar + payload_len) > len || payload_len == 0)
			return;

		proto = nexthdr;
		pkt += thusfar;
		len -= thusfar;
		break;
	    }
	default:
		return;
	}

	if (is_fragment) {
		u_char new_pkt[SNAPLEN];
		unsigned new_len = sizeof(new_pkt);

		if (!reasm_ip_next(ncap->pvt->reasm_ip, orig_pkt, orig_len,
				   frag_hdr_offset, ts.tv_sec,
				   new_pkt, &new_len) ||
		    new_len == 0)
			return;

		/* Recursive call to parse reassembled packet. */
		ncap_pcap_np(ncap, label, callback, closure, ts,
			     pf, new_pkt, new_len);
	} else
		ncap_pcap_tp(ncap, label, callback, closure, ts,
			     np, &npu, proto, pkt, len);
}

/* Process a PCAP packet and try to crack the transport headers.
 */
static void
ncap_pcap_tp(ncap_t ncap, const char *label,
	     ncap_callback_t callback, void *closure,
	     my_bpftimeval ts, ncap_np_e np, ncap_np_t npu,
	     unsigned proto, const u_char *pkt, size_t len)
{
	struct timespec tts;
	struct ncap_msg msg;
	union ncap_tp tpu;
	ncap_tp_e tp;

	switch (proto) {
	case IPPROTO_UDP: {
		const struct udphdr *udp;
		size_t ulen;

		if (len < sizeof *udp)
			return;
		udp = (const struct udphdr *) pkt;
		tp = ncap_udp;
		tpu.udp.sport = ntohs(udp->uh_sport);
		tpu.udp.dport = ntohs(udp->uh_dport);
		ulen = ntohs(udp->uh_ulen);
		if (ulen > len || ulen < sizeof *udp)
			return;
		len = ulen;
		/* XXX should we be verifying the checksum? */
		pkt += sizeof *udp;
		len -= sizeof *udp;
		break;
	}
	case IPPROTO_TCP:
		/* XXX TCP support needed. */
		return;
	case IPPROTO_ICMP: {
		if (len < 2)
			return;
		tp = ncap_icmp;
		tpu.icmp.type = *pkt;
		tpu.icmp.code = *(pkt + 1);
		NCAP_GETBUF(&tpu.icmp.type, 1, pkt);
		NCAP_GETBUF(&tpu.icmp.code, 1, pkt);
		pkt += 2;
		len -= 2;
		break;
	}
	default:
		return;
	}

	tts.tv_sec = ts.tv_sec;
	tts.tv_nsec = ts.tv_usec * THOUSAND;
	msg = (*ncap->cons)(ncap, tts, 0, 0, np, npu, tp, &tpu, len, pkt);
	if ((ncap->match)(ncap, &msg))
		(*callback)(ncap, closure, &msg, label);
}

/* Try to read an NCAP MSG from a datagram socket.
 *
 * Return number of messages dispatched (can be one or zero).
 */
static int
ncap_read_dgmsg(ncap_dg_ptr dgp, ncap_callback_t callback, void *closure) {
	ncap_t ncap = dgp->ncap;
	ssize_t n;

	if (ncap->pvt->msgbuf == NULL) {
		ncap->pvt->msgbuf = malloc(ncap->pvt->maxmsg);
		if (ncap->pvt->msgbuf == NULL) {
			drop_dg(ncap, dgp->fdes);
			FAILZERO("malloc failed");
		}
	}

	n = recv(dgp->fdes, ncap->pvt->msgbuf, ncap->pvt->maxmsg, 0);
	if (n < 0) {
		if (errno != EAGAIN) {
			drop_dg(ncap, dgp->fdes);
			FAILZERO("recv failed");
		}
		return (0);
	}

	/* No real message will ever be as small as a file header. */
	if (n == NCAP_FILEHDR) {
		const u_char magic[] = ncap_magic, *p;

		if (memcmp(magic, ncap->pvt->msgbuf, 4) != 0)
			return (1);
		p = ncap->pvt->msgbuf + 4;
		NCAP_GET32(dgp->vers, p);
	}

	/* Real messages have to have a minimum sized fixed header. */
	if (dgp->vers == ncap_version && n > NCAP_MSGHDR) {
		size_t siz, netlen, tplen;
		struct ncap_msg msg;
		const u_char *p;
		ssize_t s;

		p = ncap->pvt->msgbuf;
		netlen = tplen = 0;
		s = import_mh1(p, n, &msg, &siz, &netlen, &tplen);
		if (s <= 0 || (s > 0 && (s != NCAP_MSGHDR ||
					 siz < NCAP_MSGHDR ||
					 netlen > NCAP_NETHDR ||
					 tplen > NCAP_TPHDR)))
			return (1);
		p += s, n -= s;
		s = import_mh2(p, n, netlen, tplen, &msg);
		if (s <= 0)
			return (1);
		p += s, n -= s;
		if ((ssize_t)msg.paylen > n)
			return (1);
		msg.payload = p;
		if ((ncap->match)(ncap, &msg))
			(*callback)(ncap, closure, &msg, dgp->label);
	}

	return (1);
}

/* Get some data from the NCAP file and return the next available character.
 *
 * Return: 0..255 (octet)
 *	or -1 (EOF)
 *	or -2 (errno)
 */
static int
my_getc_refill(ncap_nf_ptr nfp) {
	int n = read(nfp->fdes, nfp->fb, sizeof nfp->fb);

	if (n == 0)
		return (-1);
	if (n < 0)
		return (-2);
	nfp->fblen = (size_t) n;
	nfp->fbcur = 0;
	return (nfp->fb[nfp->fbcur++]);
}

/* Try to read an NCAP MSG out of a file.
 *
 * Return: 0 (success)
 *	or -1 (EOF)
 *	or -2 (errno)
 */
static int
ncap_read_nfmsg(ncap_nf_ptr nfp, ncap_callback_t callback, void *closure) {
	ncap_t ncap = nfp->ncap;

	/* If we have not got a version number yet, get it now. */
	if (nfp->vers == 0) {
		const u_char magic[] = ncap_magic;
		u_char *p;

		while (nfp->len < NCAP_FILEHDR) {
			int ch = MY_GETC(nfp);

			if (ch < 0)
				return (ch);
			nfp->fixedbuf[nfp->len++] = ch;
		}
		p = nfp->fixedbuf + 4;
		NCAP_GET32(nfp->vers, p);
		if (memcmp(nfp->fixedbuf, magic, 4) != 0 ||
		    nfp->vers != ncap_version)
		{
			deactivate_nf(nfp);
			return (-1);
		}
		assert(nfp->vers != 0);
		nfp->len = 0;
		nfp->saving = false;
	}

	/* If we have not got the fixed header yet, get it now. */
	if (nfp->len < NCAP_MSGHDR) {
		ssize_t n;

		while (nfp->len < NCAP_MSGHDR) {
			int ch = MY_GETC(nfp);

			if (ch < 0)
				return (ch);
			nfp->fixedbuf[nfp->len++] = ch;
		}

		n = import_mh1(nfp->fixedbuf, nfp->len, &nfp->msg,
			       &nfp->siz, &nfp->netlen, &nfp->tplen);
		if (n <= 0 || (n > 0 && (n != NCAP_MSGHDR ||
					 nfp->siz < NCAP_MSGHDR ||
					 nfp->netlen > NCAP_NETHDR ||
					 nfp->tplen > NCAP_TPHDR)))
		{
			deactivate_nf(nfp);
			return (-1);
		}

		/* If net/tp is unknown, or if the message is larger than
		 * the maxmsg given in create(), this message won't be saved.
		 */
		assert((nfp->varbuf == NULL) == (nfp->varsiz == 0));
		if (n != 0 && (int)nfp->siz <= ncap->pvt->maxmsg) {
			size_t s = nfp->siz - NCAP_MSGHDR;

			if (nfp->varbuf != NULL && s > nfp->varsiz) {
				free(nfp->varbuf);
				nfp->varbuf = NULL;
				nfp->varsiz = 0;
			}
			if (nfp->varbuf == NULL) {
				nfp->varbuf = malloc(s);
				if (nfp->varbuf == NULL) {
					deactivate_nf(nfp);
					return (-2);
				}
				nfp->varsiz = s;
			}
			nfp->saving = true;
		}
	}

	/* Get a record, and either save it or throw it away. */
	while (nfp->len < nfp->siz) {
		int ch = MY_GETC(nfp);

		if (ch < 0)
			return (ch);
		if (nfp->saving)
			nfp->varbuf[nfp->len++ - NCAP_MSGHDR] = ch;
	}

	/* Save record in memory and deliver it if it's a keeper. */
	if (nfp->saving) {
		int n;

		n = import_mh2(nfp->varbuf, nfp->len - NCAP_MSGHDR,
			       nfp->netlen, nfp->tplen, &nfp->msg);
		if (n == 0)
			abort();
		if (n < 0) {
			deactivate_nf(nfp);
			return (-1);
		}
		nfp->msg.payload = nfp->varbuf + n;
		if ((ncap->match)(ncap, &nfp->msg))
			(*callback)(ncap, closure, &nfp->msg, nfp->label);
	}

	/* Clear state for next record. */
	nfp->len = 0;
	return (1);
}

static ssize_t
import_mh1(const u_char msghdr[], size_t len,
	   ncap_msg_t msg, size_t *siz, size_t *netlen, size_t *tplen)
{
	const u_char *p = msghdr;

	if (len < NCAP_MSGHDR)
		return (-1);
	NCAP_GET32(*siz, p);
	NCAP_GET32(msg->ts.tv_sec, p);
	NCAP_GET32(msg->ts.tv_nsec, p);
	NCAP_GET32(msg->user1, p);
	NCAP_GET32(msg->user2, p);
	NCAP_GET16(msg->np, p);
	NCAP_GET16(msg->tp, p);
	NCAP_GET32(msg->paylen, p);

	switch (msg->np) {
	case ncap_ip4:
		*netlen = IN4SZ * 2;
		break;
	case ncap_ip6:
		*netlen = IN6SZ * 2;
		break;
	default:
		return (0);
	}

	switch (msg->tp) {
	case ncap_udp:
		*tplen = sizeof(int16_t) * 2;
		break;
	case ncap_tcp:
		*tplen = sizeof(int16_t) * 2 + sizeof(int32_t) * 2;
		break;
	case ncap_icmp:
		*tplen = 2;
		break;
	default:
		return (0);
	}

	return (p - msghdr);
}

static ssize_t
import_mh2(const u_char msghdr[], size_t len, size_t netlen, size_t tplen,
	   ncap_msg_t msg)
{
	const u_char *p = msghdr;

	if (netlen > len)
		return (-1);
	switch (msg->np) {
	case ncap_ip4:
		if (netlen != 2 * IN4SZ)
			return (-1);
		NCAP_GETBUF(&msg->npu.ip4.src, IN4SZ, p);
		NCAP_GETBUF(&msg->npu.ip4.dst, IN4SZ, p);
		break;
	case ncap_ip6:
		if (netlen != 2 * IN6SZ)
			return (-1);
		NCAP_GETBUF(&msg->npu.ip6.src, IN6SZ, p);
		NCAP_GETBUF(&msg->npu.ip6.dst, IN6SZ, p);
		break;
	default:
		return (0);
	}
	len -= netlen;

	if (tplen > len)
		return (-1);
	switch (msg->tp) {
	case ncap_udp:
		if (tplen !=  2 * sizeof(int16_t))
			return (-1);
		NCAP_GET16(msg->tpu.udp.sport, p);
		NCAP_GET16(msg->tpu.udp.dport, p);
		break;
	case ncap_tcp:
		if (tplen != 2 * sizeof(int16_t) + 2 * sizeof(int32_t))
			return (-1);
		NCAP_GET16(msg->tpu.tcp.sport, p);
		NCAP_GET16(msg->tpu.tcp.dport, p);
		NCAP_GET32(msg->tpu.tcp.offset, p);
		NCAP_GET32(msg->tpu.tcp.flags, p);
		break;
	case ncap_icmp:
		if (tplen != 2)
			return (-1);
		NCAP_GETBUF(&msg->tpu.icmp.type, 1, p);
		NCAP_GETBUF(&msg->tpu.icmp.code, 1, p);
		break;
	default:
		return (0);
	}
	len -= tplen;

	return (p - msghdr);
}

static size_t
export_hdr(ncap_t ncap __attribute__((unused)), u_char filehdr[]) {
	static const u_char magic[] = ncap_magic;
	u_char *p = filehdr;

	NCAP_PUTBUF(magic, sizeof magic, p);
	NCAP_PUT32(ncap_version, p);
	return (p - filehdr);
}

static ssize_t
export_msg(ncap_t ncap, ncap_msg_ct msg, u_char msghdr[]) {
	u_char *p = msghdr;

	NCAP_PUT32(0, p);			/* Placeholder. */
	NCAP_PUT32(msg->ts.tv_sec, p);
	NCAP_PUT32(msg->ts.tv_nsec, p);
	NCAP_PUT32(msg->user1, p);
	NCAP_PUT32(msg->user2, p);
	NCAP_PUT16(msg->np, p);
	NCAP_PUT16(msg->tp, p);
	NCAP_PUT32(msg->paylen, p);
	assert(p - msghdr == NCAP_MSGHDR);

	switch (msg->np) {
	case ncap_ip4:
		NCAP_PUTBUF(&msg->npu.ip4.src, IN4SZ, p);
		NCAP_PUTBUF(&msg->npu.ip4.dst, IN4SZ, p);
		break;
	case ncap_ip6:
		NCAP_PUTBUF(&msg->npu.ip6.src, IN6SZ, p);
		NCAP_PUTBUF(&msg->npu.ip6.dst, IN6SZ, p);
		break;
	default:
		FAILURE("unimplemented network type");
	}

	switch (msg->tp) {
	case ncap_udp:
		NCAP_PUT16(msg->tpu.udp.sport, p);
		NCAP_PUT16(msg->tpu.udp.dport, p);
		break;
	case ncap_tcp:
		NCAP_PUT16(msg->tpu.tcp.sport, p);
		NCAP_PUT16(msg->tpu.tcp.dport, p);
		NCAP_PUT32(msg->tpu.tcp.offset, p);
		NCAP_PUT32(msg->tpu.tcp.flags, p);
		break;
	case ncap_icmp:
		NCAP_PUTBUF(&msg->tpu.icmp.type, 1, p);
		NCAP_PUTBUF(&msg->tpu.icmp.code, 1, p);
		break;
	default:
		FAILURE("unimplemented transport type");
	}

	return (p - msghdr);
}

/* Destroy all filters and rules associated with an NCAP object, if any.
 */
static void
free_filters(ncap_t ncap) {
	ncap_filter_ptr filt;

	while ((filt = ISC_LIST_HEAD(ncap->pvt->filters)) != NULL)
		free_filter(ncap, filt);
}

/* Destroy one filter.
 */
static void
free_filter(ncap_t ncap, ncap_filter_ptr filt) {
	ncap_rule_ptr rule;

	while ((rule = ISC_LIST_HEAD(filt->rules)) != NULL) {
		if (rule->payload != NULL) {
			free(rule->payload);
			rule->payload = NULL;
		}
		ISC_LIST_UNLINK(filt->rules, rule, link);
		free(rule);
	}
	free(filt->bpf);
	ISC_LIST_UNLINK(ncap->pvt->filters, filt, link);
	free(filt);
}
