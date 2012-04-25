/* 
 * spp_ipv6_constants.h
 *
 * Copyright (C) 2011 Martin Schuette <info@mschuette.name>
 *
 * Include file for
 *  - network protocol constants and data structures not included in all OS
 *  - own plugin-specific constants
 *  - the plugin's SIDs
 *
 */

#ifndef _SPP_IPV6_CONSTANTS_H
#define	_SPP_IPV6_CONSTANTS_H

#include "sf_snort_packet.h"

/**********************************************************************
 ** Protocol Constants                                               **
 **********************************************************************/

/* some constants, as already used in decode.c */
#define IPPROTO_MOBILITY     135

/* ICMPv6 types, http://www.iana.org/assignments/icmpv6-parameters */
#define ICMP6_UNREACH 1
#define ICMP6_BIG    2
#define ICMP6_TIME   3
#define ICMP6_PARAMS 4
#define ICMP6_ECHO   128
#define ICMP6_REPLY  129
// NDP
#define ICMP6_SOLICITATION    133
#define ICMP6_ADVERTISEMENT   134
#define ICMP6_N_SOLICITATION  135
#define ICMP6_N_ADVERTISEMENT 136
#define ICMP6_REDIRECT        137
// Inverse ND
#define ICMP6_INV_SOLICITATION    141
#define ICMP6_INV_ADVERTISEMENT   142
// Mobile IPv6
#define ICMP6_HOME_AD_REQUEST  144
#define ICMP6_HOME_AD_REPLY    145
#define ICMP6_MOBILEPREFIX_SOL 146
#define ICMP6_MOBILEPREFIX_ADV 147
// SEND
#define ICMP6_CRT_SOLICITATION  148
#define ICMP6_CRT_ADVERTISEMENT 149
// MIP6 Fast Handovers
#define ICMP6_MOBILE_FH        154

/* IPv6 ND Options, http://www.iana.org/assignments/icmpv6-parameters */
#define ICMP6_OPT_HOMEAGENT  8
#define ICMP6_OPT_CGA       11
#define ICMP6_OPT_RSA       12
#define ICMP6_OPT_TIMESTAMP 13
#define ICMP6_OPT_NONCE     14
#define ICMP6_OPT_ANCHOR    15
#define ICMP6_OPT_CERT      16
#define ICMP6_OPT_EXP1     253
#define ICMP6_OPT_EXP2     254

/* some more constants copied from BSD's <netinet/icmp6.h> */
/* RFC2292 decls */
#define ICMP6_MEMBERSHIP_QUERY          130     /* group membership query */
#define ICMP6_MEMBERSHIP_REPORT         131     /* group membership report */
#define ICMP6_MEMBERSHIP_REDUCTION      132     /* group membership termination */
#define ICMP6_WRUREQUEST                139     /* who are you request */
#define ICMP6_WRUREPLY                  140     /* who are you reply */
#define ICMP6_FQDN_QUERY                139     /* FQDN query */
#define ICMP6_FQDN_REPLY                140     /* FQDN reply */
#define ICMP6_NI_QUERY                  139     /* node information request */
#define ICMP6_NI_REPLY                  140     /* node information reply */
#define MLDV2_LISTENER_REPORT           143     /* RFC3810 listener report */

/* and some more constants copied from BSD's <netinet/in.h> */
#define	IPPROTO_IPV4		4		/* IPv4 encapsulation */
#define	IPPROTO_IPEIP		94		/* IP encapsulated in IP */
#define	IPPROTO_ETHERIP		97		/* Ethernet IP encapsulation */

/**********************************************************************
 ** Snort-Plugin Constants                                           **
 **********************************************************************/

/*
 * every preprocessor has a 32-bit ID.
 * preprocids.h defines 20 standard IDs, we use magic numbers
 */
#define PP_IPv6   0xC0FFEE
/* generator.h defines about 170 standard GIDs, we use a magic number */
#define GEN_ID_IPv6 248

// useful for memcpy calls
#define MAC_LENGTH (6*sizeof(u_int8_t))

// some hashes store only keys, so this constant is used as a data ptr
#define HASHMARK ((void*)0xdead)
        
/**********************************************************************
 ** SIDs & descriptions for all alerts/warnings                      **
 **********************************************************************/
#define SID_ICMP6_RA_NEW_ROUTER             1
#define SID_ICMP6_RA_NEW_ROUTER_TEXT        "ipv6: RA from new router"
#define SID_ICMP6_INVALID_ROUTER_MAC        2
#define SID_ICMP6_INVALID_ROUTER_MAC_TEXT   "ipv6: RA from non-router MAC address"
#define SID_ICMP6_RA_PREFIX_CHANGED         3
#define SID_ICMP6_RA_PREFIX_CHANGED_TEXT    "ipv6: RA prefix changed"
#define SID_ICMP6_RA_FLAGS_CHANGED          4
#define SID_ICMP6_RA_FLAGS_CHANGED_TEXT     "ipv6: RA flags changed"
#define SID_ICMP6_RA_UNKNOWN_PREFIX         5
#define SID_ICMP6_RA_UNKNOWN_PREFIX_TEXT    "ipv6: RA for non-local net prefix"
#define SID_ICMP6_RA_LIFETIME0              6
#define SID_ICMP6_RA_LIFETIME0_TEXT         "ipv6: RA with lifetime 0"
#define SID_ICMP6_ND_NEW_DAD                7
#define SID_ICMP6_ND_NEW_DAD_TEXT           "ipv6: new DAD started"
#define SID_ICMP6_ND_NEW_HOST               8
#define SID_ICMP6_ND_NEW_HOST_TEXT          "ipv6: new host in network"
#define SID_ICMP6_INVALID_HOST_MAC          9
#define SID_ICMP6_INVALID_HOST_MAC_TEXT     "ipv6: new host with non-allowed MAC address"
#define SID_ICMP6_DAD_COLLISION             10
#define SID_ICMP6_DAD_COLLISION_TEXT        "ipv6: DAD with collision"
#define SID_ICMP6_DAD_DOS                   11
#define SID_ICMP6_DAD_DOS_TEXT              "ipv6: DAD with spoofed collision"
#define SID_ICMP6_LINKADDR_MISMATCH         12
#define SID_ICMP6_LINKADDR_MISMATCH_TEXT    "ipv6: mismatch in MAC and NDP source linkaddress option"
#define SID_IP6_ONLY_PADDING_EXT            13
#define SID_IP6_ONLY_PADDING_EXT_TEXT       "ipv6: extension header has only padding options (evasion?)"
#define SID_IP6_OPTION_LENGTH_ERR           14
#define SID_IP6_OPTION_LENGTH_ERR_TEXT      "ipv6: option lengths != ext length"
#define SID_IP6_PADDING_OPT_DATA            15
#define SID_IP6_PADDING_OPT_DATA_TEXT       "ipv6: PadN option with data != zero"
#define SID_IP6_CONSEC_PADDING_OPT          16
#define SID_IP6_CONSEC_PADDING_OPT_TEXT     "ipv6: consecutive padding options"


/* TODO:
 * is it desirable to have only one alert per SID per packet?
 * currently some SIDs test multiple attributes, thus can be raised more than once per packet.
 */

/* Macro for alerts */
/* Arguments are: gid, sid, rev, classification, priority, message, rule_info */
#define ALERT(x) { DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Raise Alert: %d, %s\n", x, x##_TEXT);); \
                   _dpd.alertAdd(GEN_ID_IPv6, x, 1, 0, 3, x##_TEXT, 0 ); }
/* different classification (?) 
#define WARN(x)  { DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Raise Warning: %d, %s\n", x, x##_TEXT);); \
                   _dpd.alertAdd(GEN_ID_IPv6, x, 1, 1, 3, x##_TEXT, 0 ); }
*/

#endif	/* _SPP_IPV6_CONSTANTS_H */
