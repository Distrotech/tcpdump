/*
 * Copyright (c) 1990, 1992, 1993, 1994, 1995, 1996, 1997
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
 * @(#) $Header: /tcpdump/master/tcpdump/addrtoname.h,v 1.18.2.1 2001-10-01 04:02:17 mcr Exp $ (LBL)
 */

/* Name to address translation routines. */

struct netdissect_options;

extern const char *etheraddr_string(struct netdissect_options *ipdo,
			      const u_char *);
extern const char *etherproto_string(struct netdissect_options *, u_short);
extern const char *tcpport_string(struct netdissect_options *, u_short);
extern const char *udpport_string(struct netdissect_options *, u_short);
extern const char *getname(struct netdissect_options *ipdo, const u_char *);
#ifdef INET6
extern const char *getname6(struct netdissect_options *ipdo, const u_char *);
#endif
extern const char *intoa(u_int32_t);

extern void init_addrtoname(struct netdissect_options *, u_int32_t, u_int32_t);
extern struct hnamemem *newhnamemem(struct netdissect_options *ipdo);
#ifdef INET6
extern struct h6namemem *newh6namemem(struct netdissect_options *ipdo);
#endif

#define ipaddr_string(p) getname(ipdo,(const u_char *)(p))
#ifdef INET6
#define ip6addr_string(p) getname6(ipdo,(const u_char *)(p))
#endif
