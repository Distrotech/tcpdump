/*
 * Copyright (c) 1988, 1989, 1990, 1991, 1992, 1993, 1994, 1995, 1996, 1997, 1999, 2000
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
 *
 * @(#) $Header: /tcpdump/master/tcpdump/interface.h,v 1.172.2.1 2001-10-01 04:02:17 mcr Exp $ (LBL)
 */

#ifndef tcpdump_interface_h
#define tcpdump_interface_h

/*
 * Only put *TCPDUMP* specific stuff and compatibility stuff here.
 *
 * Most other stuff goes into the common library header file.
 */

#include "netdissect.h"

#ifdef AVOID_CHURN
#define ipdo  ndo
#define aflag ndo->ndo_aflag
#define dflag ndo->ndo_dflag
#define eflag ndo->ndo_eflag
#define fflag ndo->ndo_fflag
#define nflag ndo->ndo_nflag
#define Nflag ndo->ndo_Nflag
#define qflag ndo->ndo_qflag
#define Rflag ndo->ndo_Rflag
#define sflag ndo->ndo_sflag
#define Sflag ndo->ndo_Sflag
#define tflag ndo->ndo_tflag
#define uflag ndo->ndo_uflag
#define vflag ndo->ndo_vflag
#define xflag ndo->ndo_xflag
#define Xflag ndo->ndo_Xflag

#define espsecret ndo->ndo_espsecret

#define packettype ndo->ndo_packettype

#define program_name ndo->ndo_program_name

#define thiszone     ndo->ndo_thiszone
#define snaplen      ndo->ndo_snaplen

#define packetp      ndo->ndo_packetp
#define snapend      ndo->ndo_snapend
#define default_print(A,B) (*ndo->ndo_default_print)(ipdo, A, B)
#define default_print_unaligned(A,B) (*ndo->ndo_default_print_unaligned)(ipdo, A, B)

#define infodelay    ndo->ndo_infodelay
#define info(X)      (*ndo->ndo_info)(ndo, X)
#endif

int infoprint;

extern void
dump_and_trunc(u_char *user, const struct pcap_pkthdr *h, const u_char *sp);


#endif /* tcpdump_interface_h */

