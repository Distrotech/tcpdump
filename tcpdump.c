/*
 * Copyright (c) 1988, 1989, 1990, 1991, 1992, 1993, 1994, 1995, 1996, 1997, 2000
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the University of California,
 * Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#ifndef lint
static const char copyright[] =
    "@(#) Copyright (c) 1988, 1989, 1990, 1991, 1992, 1993, 1994, 1995, 1996, 1997, 2000\n\
The Regents of the University of California.  All rights reserved.\n";
static const char rcsid[] =
    "@(#) $Header: /tcpdump/master/tcpdump/tcpdump.c,v 1.167.2.2 2001-10-15 16:54:12 mcr Exp $ (LBL)";
#endif

/*
 * tcpdump - monitor tcp/ip traffic on an ethernet.
 *
 * First written in 1987 by Van Jacobson, Lawrence Berkeley Laboratory.
 * Mercilessly hacked and occasionally improved since then via the
 * combined efforts of Van, Steve McCanne and Craig Leres of LBL.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <sys/time.h>

#include <netinet/in.h>

#include <pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>

#include "interface.h"
#include "addrtoname.h"
#include "machdep.h"
#include "setsignal.h"
#include "gmt2local.h"

struct netdissect_options gipdo;

/* these are tcpdump specific flags, not dissectors */
int Oflag = 1;			/* run filter code optimizer */
int pflag;			/* don't go promiscuous */
int Cflag;                      /* number of bytes before one roles dump file*/
int infoprint;

char *WFileName;

/* Forwards */
static RETSIGTYPE cleanup(int);
static void usage(struct netdissect_options *) __attribute__((noreturn));

extern void dump_and_trunc(u_char *user, const struct pcap_pkthdr *h, const u_char *sp);

void tcpdump_info(struct netdissect_options *, register int verbose);

#ifdef SIGINFO
RETSIGTYPE requestinfo(int);
#endif

/* Length of saved portion of packet. */

struct printer {
	pcap_handler f;
	int type;
};

static struct printer printers[] = {
	{ arcnet_if_print,	DLT_ARCNET },
	{ ether_if_print,	DLT_EN10MB },
	{ token_if_print,	DLT_IEEE802 },
#ifdef DLT_LANE8023
	{ lane_if_print,        DLT_LANE8023 },
#endif
#ifdef DLT_CIP
	{ cip_if_print,         DLT_CIP },
#endif
#ifdef DLT_ATM_CLIP
	{ cip_if_print,         DLT_ATM_CLIP },
#endif
	{ sl_if_print,		DLT_SLIP },
	{ sl_bsdos_if_print,	DLT_SLIP_BSDOS },
	{ ppp_if_print,		DLT_PPP },
	{ ppp_bsdos_if_print,	DLT_PPP_BSDOS },
	{ fddi_if_print,	DLT_FDDI },
	{ null_if_print,	DLT_NULL },
#ifdef DLT_LOOP
	{ null_if_print,	DLT_LOOP },
#endif
	{ raw_if_print,		DLT_RAW },
	{ atm_if_print,		DLT_ATM_RFC1483 },
#ifdef DLT_C_HDLC
	{ chdlc_if_print,	DLT_C_HDLC },
#endif
#ifdef DLT_HDLC
	{ chdlc_if_print,	DLT_HDLC },
#endif
#ifdef DLT_PPP_SERIAL
	{ ppp_hdlc_if_print,    DLT_PPP_SERIAL },
#endif
#ifdef DLT_PPP_ETHER
	{ pppoe_if_print,	DLT_PPP_ETHER },
#endif
#ifdef DLT_LINUX_SLL
	{ sll_if_print,		DLT_LINUX_SLL },
#endif
#ifdef DLT_IEEE802_11
	{ ieee802_11_if_print,	DLT_IEEE802_11},
#endif
#ifdef DLT_LTALK
	{ ltalk_if_print,	DLT_LTALK },
#endif
	{ NULL,			0 },
};

static pcap_handler
lookup_printer(struct netdissect_options *ipdo, int type)
{
	struct printer *p;

	for (p = printers; p->f; ++p)
		if (type == p->type)
			return p->f;

	error(ipdo,"unknown data link type %d", type);
	/* NOTREACHED */
}

pcap_t *pd;

extern int optind;
extern int opterr;
extern char *optarg;

int
main(int argc, char **argv)
{
	register int cnt, op, i;
	bpf_u_int32 localnet, netmask;
	register char *cp, *infile, *cmdbuf, *device, *RFileName;
	extern char *WFileName;
	pcap_handler printer;
	struct bpf_program fcode;
	RETSIGTYPE (*oldhandler)(int);
	u_char *pcap_userdata;
	char ebuf[PCAP_ERRBUF_SIZE];

	gipdo.ndo_snaplen = DEFAULT_SNAPLEN;
	gipdo.ndo_Rflag = 1;    /* print sequence # field in AH/ESP*/
	gipdo.ndo_tflag = 1; 	/* print packet arrival time */

	cnt = -1;
	device = NULL;
	infile = NULL;
	RFileName = NULL;
	WFileName = NULL;
	if ((cp = strrchr(argv[0], '/')) != NULL)
		gipdo.ndo_program_name = cp + 1;
	else
		gipdo.ndo_program_name = argv[0];

	if (abort_on_misalignment(ebuf, sizeof(ebuf)) < 0)
		error(&gipdo,"%s", ebuf);

#ifdef LIBSMI
	smiInit("tcpdump");
#endif
	
	opterr = 0;
	while (
	    (op = getopt(argc, argv, "ac:C:deE:fF:i:lm:nNOpqr:Rs:StT:uvw:xXY")) != -1)
		switch (op) {

		case 'a':
			++gipdo.ndo_aflag;
			break;

		case 'c':
			cnt = atoi(optarg);
			if (cnt <= 0)
				error(&gipdo,"invalid packet count %s", optarg);
			break;

		case 'C':
			Cflag = atoi(optarg) * 1000000;
			if (Cflag < 0) 
				error(&gipdo, "invalid file size %s", optarg);
			break;

		case 'd':
			++gipdo.ndo_dflag;
			break;

		case 'e':
			++gipdo.ndo_eflag;
			break;

		case 'E':
#ifndef HAVE_LIBCRYPTO
			warning(&gipdo,"crypto code not compiled in");
#endif
			gipdo.ndo_espsecret = optarg;
			break;

		case 'f':
			++gipdo.ndo_fflag;
			break;

		case 'F':
			infile = optarg;
			break;

		case 'i':
			device = optarg;
			break;

		case 'l':
#ifdef HAVE_SETLINEBUF
			setlinebuf(stdout);
#else
			setvbuf(stdout, NULL, _IOLBF, 0);
#endif
			break;

		case 'n':
			++gipdo.ndo_nflag;
			break;

		case 'N':
			++gipdo.ndo_Nflag;
			break;

		case 'm':
#ifdef LIBSMI
		        if (smiLoadModule(optarg) == 0) {
				error(&gipdo,"could not load MIB module %s", optarg);
		        }
			sflag = 1;
#else
			(void)fprintf(stderr, "%s: ignoring option `-m %s' ",
				      gipdo.ndo_program_name, optarg);
			(void)fprintf(stderr, "(no libsmi support)\n");
#endif
			
		case 'O':
			Oflag = 0;
			break;

		case 'p':
			++pflag;
			break;

		case 'q':
			++gipdo.ndo_qflag;
			break;

		case 'r':
			RFileName = optarg;
			break;

		case 'R':
			gipdo.ndo_Rflag = 0;
			break;

		case 's': {
			char *end;

			gipdo.ndo_snaplen = strtol(optarg, &end, 0);
			if (optarg == end || *end != '\0'
			    || gipdo.ndo_snaplen < 0
			    || gipdo.ndo_snaplen > 65535)
				error(&gipdo,"invalid snaplen %s", optarg);
			else if (gipdo.ndo_snaplen == 0)
				gipdo.ndo_snaplen = 65535;
			break;
		}

		case 'S':
			++gipdo.ndo_Sflag;
			break;

		case 't':
			--gipdo.ndo_tflag;
			break;

		case 'T':
			if (strcasecmp(optarg, "vat") == 0)
				gipdo.ndo_packettype = PT_VAT;
			else if (strcasecmp(optarg, "wb") == 0)
				gipdo.ndo_packettype = PT_WB;
			else if (strcasecmp(optarg, "rpc") == 0)
				gipdo.ndo_packettype = PT_RPC;
			else if (strcasecmp(optarg, "rtp") == 0)
				gipdo.ndo_packettype = PT_RTP;
			else if (strcasecmp(optarg, "rtcp") == 0)
				gipdo.ndo_packettype = PT_RTCP;
			else if (strcasecmp(optarg, "snmp") == 0)
				gipdo.ndo_packettype = PT_SNMP;
			else if (strcasecmp(optarg, "cnfp") == 0)
				gipdo.ndo_packettype = PT_CNFP;
			else
				error(&gipdo,"unknown packet type `%s'", optarg);
			break;

		case 'u':
			++gipdo.ndo_uflag;
			break;
			
		case 'v':
			++gipdo.ndo_vflag;
			break;

		case 'w':
			WFileName = optarg;
			break;

		case 'x':
			++gipdo.ndo_xflag;
			break;

		case 'X':
    		        ++gipdo.ndo_xflag;
			++gipdo.ndo_Xflag;
			break;

#ifdef YYDEBUG
		case 'Y':
			{
			/* Undocumented flag */
			extern int yydebug;
			yydebug = 1;
			}
			break;
#endif
		default:
			usage(&gipdo);
			/* NOTREACHED */
		}

	if (gipdo.ndo_aflag && gipdo.ndo_nflag)
		error(&gipdo,"-a and -n options are incompatible");

	if (gipdo.ndo_tflag > 0)
		gipdo.ndo_thiszone = gmt2local(0);

	if (RFileName != NULL) {
		/*
		 * We don't need network access, so set it back to the user id.
		 * Also, this prevents the user from reading anyone's
		 * trace file.
		 */
		setuid(getuid());

		pd = pcap_open_offline(RFileName, ebuf);
		if (pd == NULL)
			error(&gipdo,"%s", ebuf);
		localnet = 0;
		netmask = 0;
		if (gipdo.ndo_fflag != 0)
			error(&gipdo,"-f and -r options are incompatible");
	} else {
		if (device == NULL) {
			device = pcap_lookupdev(ebuf);
			if (device == NULL)
				error(&gipdo,"%s", ebuf);
		}
		*ebuf = '\0';
		pd = pcap_open_live(device, gipdo.ndo_snaplen,
				    !pflag, 1000, ebuf);
		if (pd == NULL)
			error(&gipdo,"%s", ebuf);
		else if (*ebuf)
			warning(&gipdo, "%s", ebuf);
		i = pcap_snapshot(pd);
		if (gipdo.ndo_snaplen < i) {
			warning(&gipdo,"snaplen raised from %d to %d",
				gipdo.ndo_snaplen, i);
			gipdo.ndo_snaplen = i;
		}
		if (pcap_lookupnet(device, &localnet, &netmask, ebuf) < 0) {
			localnet = 0;
			netmask = 0;
			warning(&gipdo,"%s", ebuf);
		}
		/*
		 * Let user own process after socket has been opened.
		 */
		setuid(getuid());
	}
	if (infile)
		cmdbuf = read_infile(&gipdo, infile);
	else
		cmdbuf = copy_argv(&gipdo, &argv[optind]);

	if (pcap_compile(pd, &fcode, cmdbuf,
			 Oflag, netmask) < 0)
		error(&gipdo,"%s", pcap_geterr(pd));
	if (gipdo.ndo_dflag) {
		bpf_dump(&fcode, gipdo.ndo_dflag);
		exit(0);
	}
	init_addrtoname(&gipdo, localnet, netmask);

	(void)setsignal(SIGTERM, cleanup);
	(void)setsignal(SIGINT, cleanup);
	/* Cooperate with nohup(1) */
	if ((oldhandler = setsignal(SIGHUP, cleanup)) != SIG_DFL)
		(void)setsignal(SIGHUP, oldhandler);

	/* setup default printer */
	gipdo.ndo_default_print = default_print;
	gipdo.ndo_info = tcpdump_info;

	if (pcap_setfilter(pd, &fcode) < 0)
		error(&gipdo,"%s", pcap_geterr(pd));
	if (WFileName) {
		pcap_dumper_t *p = pcap_dump_open(pd, WFileName);
		if (p == NULL)
			error(&gipdo,"%s", pcap_geterr(pd));
		printer = dump_and_trunc;
		pcap_userdata = (u_char *)p;
	} else {
		printer = lookup_printer(&gipdo, pcap_datalink(pd));
		pcap_userdata = (u_char *)&gipdo;
#ifdef SIGINFO
		(void)setsignal(SIGINFO, requestinfo);
#endif
	}

	if (RFileName == NULL) {
		(void)fprintf(stderr, "%s: listening on %s\n",
			      gipdo.ndo_program_name, device);
		(void)fflush(stderr);
	}
	if (pcap_loop(pd, cnt, printer, pcap_userdata) < 0) {
		(void)fprintf(stderr, "%s: pcap_loop: %s\n",
			      gipdo.ndo_program_name, pcap_geterr(pd));
		exit(1);
	}
	pcap_close(pd);
	exit(0);
}

/* make a clean exit on interrupts */
static RETSIGTYPE
cleanup(int signo)
{

	/* Can't print the summary if reading from a savefile */
	if (pd != NULL && pcap_file(pd) == NULL) {
		(void)fflush(stdout);
		putc('\n', stderr);
		tcpdump_info(&gipdo, 1);
	}
	exit(0);
}

void
tcpdump_info(struct netdissect_options *ndo, register int verbose)
{
	struct pcap_stat stat;

	if (pcap_stats(pd, &stat) < 0) {
		(void)fprintf(stderr, "pcap_stats: %s\n", pcap_geterr(pd));
		return;
	}
	if (!verbose)
		fprintf(stderr, "%s: ", ndo->ndo_program_name);
	(void)fprintf(stderr, "%d packets received by filter", stat.ps_recv);
	if (!verbose)
		fputs(", ", stderr);
	else
		putc('\n', stderr);
	(void)fprintf(stderr, "%d packets dropped by kernel\n", stat.ps_drop);
	infoprint = 0;
}

/* Like default_print() but data need not be aligned */
void
default_print_unaligned(struct netdissect_options *ipdo,
			register const u_char *cp, register u_int length)
{
	register u_int i, s;
	register int nshorts;

	if (ipdo->ndo_Xflag) {
		ascii_print(ipdo, cp, length);
		return;
	}
	nshorts = (u_int) length / sizeof(u_short);
	i = 0;
	while (--nshorts >= 0) {
		if ((i++ % 8) == 0)
			(void)printf("\n\t\t\t");
		s = *cp++;
		(void)printf(" %02x%02x", s, *cp++);
	}
	if (length & 1) {
		if ((i % 8) == 0)
			(void)printf("\n\t\t\t");
		(void)printf(" %02x", *cp);
	}
}

/*
 * By default, print the packet out in hex.
 */
void
default_print(struct netdissect_options *ndo,
	      register const u_char *bp, register u_int length)
{
	default_print_unaligned(ndo, bp, length);
}


#ifdef SIGINFO
RETSIGTYPE requestinfo(int signo)
{
	if (gipdo.ndo_infodelay)
		++infoprint;
	else
		tcpdump_info(&gipdo,0);
}
#endif

static void
usage(struct netdissect_options *ipdo)
{
	extern char version[];
	extern char pcap_version[];

	(void)fprintf(stderr, "%s version %s\n",
		      ipdo->ndo_program_name, version);
	(void)fprintf(stderr, "libpcap version %s\n", pcap_version);
	(void)fprintf(stderr,
"Usage: %s [-adeflnNOpqStuvxX] [-c count] [ -F file ]\n",
		      ipdo->ndo_program_name);
	(void)fprintf(stderr,
"\t\t[ -i interface ] [ -r file ] [ -s snaplen ]\n");
	(void)fprintf(stderr,
"\t\t[ -T type ] [ -w file ] [ expression ]\n");
	exit(1);
}
