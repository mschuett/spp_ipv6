/*
 * spp_ipv6.c
 *
 * Copyright (C) 2011 Martin Schuette <info@mschuette.name>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * Description:
 * The IPv6 Preprocessor.
 *
 */

#include "sf_ip.h"
#include "spp_ipv6.h"

/* snort boilerplate code to support contexts and profiling */
tSfPolicyUserContextId ipv6_config = NULL;
#ifdef SNORT_RELOAD
tSfPolicyUserContextId ipv6_swap_config = NULL;
#endif
extern DynamicPreprocessorData _dpd;

#include "profiler.h"
#ifdef PERF_PROFILING
PreprocStats ipv6PerfStats;
#endif

/* This array defines which ICMPv6 types may contain neighbor discovery options
 * and contain their header lengths, i.e. the right offsets to find their options.
 *
 * (Most lengths are sizeof(struct nd_router_solicit) -- this is the basic ICMPv6
 * type with 32 bits for type/code/checksum, 32 bits reserved or for identifiers,
 * and possibly ND options starting in the 3nd 32-bit block.)
 */
uint_fast8_t ND_hdrlen[255] = {
    [ICMP6_SOLICITATION]      = sizeof(struct nd_router_solicit),
    [ICMP6_ADVERTISEMENT]     = sizeof(struct nd_router_advert),
    [ICMP6_N_SOLICITATION]    = sizeof(struct nd_neighbor_solicit),
    [ICMP6_N_ADVERTISEMENT]   = sizeof(struct nd_neighbor_advert),
    [ICMP6_REDIRECT]          = sizeof(struct nd_redirect),
    [ICMP6_INV_SOLICITATION]  = sizeof(struct nd_router_solicit),
    [ICMP6_INV_ADVERTISEMENT] = sizeof(struct nd_router_solicit),
    [ICMP6_MOBILEPREFIX_ADV]  = sizeof(struct nd_router_solicit),
    [ICMP6_CRT_SOLICITATION]  = sizeof(struct nd_router_solicit),
    [ICMP6_CRT_ADVERTISEMENT] = sizeof(struct certpath_adv {struct icmp6_hdr hdr;
                                                u_int16_t compact; u_int16_t reserved;}),
    [ICMP6_MOBILE_FH]         = sizeof(struct nd_router_solicit),
};

/**
 * Register init functions when library is loaded.
 */
void IPv6_Preproc_Setup(void)
{
#ifndef SNORT_RELOAD
    _dpd.registerPreproc("ipv6", IPv6_Init);
#else
    _dpd.registerPreproc("ipv6", IPv6_Init, NULL, NULL, NULL);
#endif
}

/**
 * Reset Stats
 * (only used when reading multiple PCAP files, cf. README.pcap_readmode)
 */
static void IPv6_ResetStats(int signal __attribute__((unused)), void *foo __attribute__((unused)))
{
    struct IPv6_State *context;
    sfPolicyUserPolicySet(ipv6_config, _dpd.getRuntimePolicy());
    context = (struct IPv6_State *) sfPolicyUserDataGetCurrent(ipv6_config);

    memset(context->stat, 0, sizeof(struct IPv6_Statistics));
}

/**
 * Print some statistics on snort exit.
 */
static void IPv6_PrintStats(int exiting __attribute__((unused)))
{
    struct IPv6_State *context;
    sfPolicyUserPolicySet(ipv6_config, _dpd.getRuntimePolicy());
    context = (struct IPv6_State *) sfPolicyUserDataGetCurrent(ipv6_config);
    if (!context) return;

    _dpd.logMsg("IPv6 statistics:\n");
    _dpd.logMsg("% 10u seen Packets\n",      context->stat->pkt_seen);
    _dpd.logMsg("% 10u invalid Packets\n",   context->stat->pkt_invalid);
    _dpd.logMsg("% 10u Fragments\n",         context->stat->pkt_fragments);
    _dpd.logMsg("% 10u IPv6\n",              context->stat->pkt_ip6h);
    _dpd.logMsg("% 10u ICMPv6\n",            context->stat->pkt_icmpv6);
    _dpd.logMsg("% 10u Other Upper Layer\n", context->stat->pkt_other);
    _dpd.logMsg("\n");

    _dpd.logMsg("% 10u router solicitation\n",    context->stat->pkt_icmp_rsol);
    _dpd.logMsg("% 10u router announcement\n",    context->stat->pkt_icmp_radv);
    _dpd.logMsg("% 10u neighbour solicitation\n", context->stat->pkt_icmp_nsol);
    _dpd.logMsg("% 10u neighbour announcement\n", context->stat->pkt_icmp_nadv);
    _dpd.logMsg("% 10u Mcast query\n",            context->stat->pkt_icmp_mlquery);
    _dpd.logMsg("% 10u Mcast report\n",           context->stat->pkt_icmp_mlreport);
    _dpd.logMsg("% 10u dst unreachable\n",        context->stat->pkt_icmp_unreach);
    _dpd.logMsg("% 10u Other\n",                  context->stat->pkt_icmp_other);

    _dpd.logMsg("\nAll routers (%d entries):\n", context->routers->entry_counter);
    state_host_printlist(context->routers);

    _dpd.logMsg("\nAll hosts (%d entries):\n", context->hosts->entry_counter);
    state_host_printlist(context->hosts);

    _dpd.logMsg("\nAll hosts in DAD state (%d entries):\n", context->unconfirmed->entry_counter);
    state_host_printlist(context->unconfirmed);

    /*
    size_t size = 0;
    size_t total = 0;
    total += sizeof (*context);
    total += sizeof (*context->stat);
    total += sizeof (*context->config);
    _dpd.logMsg("\n\nlast memory usage\n\t is %6d bytes fix\n", total);

    size = state_host_memusage(context->routers);
    _dpd.logMsg("\tand %6d bytes for routers\n", size);
    total += size;
    size = state_host_memusage(context->hosts);
    _dpd.logMsg("\tand %6d bytes for hosts\n", size);
    total += size;
    size = state_host_memusage(context->unconfirmed);
    _dpd.logMsg("\tand %6d bytes for unconfirmed\n", size);
    total += size;

    _dpd.logMsg("\t==> %6d bytes total (IPv6_Host size: %d bytes)\n",
                total, sizeof(struct IPv6_Host));
     */
}

/**
 * Initialization function, invoked when preprocessor is activated.
 *
 * Has to parse our configuration options,  add preprocessing callbacks,
 * and init data structures.
 */
static void IPv6_Init(char *args)
{
    struct IP_List_head    *prefixwl;
    struct MAC_Entry_head  *routerwl;
    struct MAC_Entry_head  *hostwl;
    struct IPv6_Hosts_head *routers;
    struct IPv6_Hosts_head *hosts;
    struct IPv6_Hosts_head *unconf;
    struct IPv6_Statistics *stat;
    struct IPv6_State      *context;
    struct IPv6_Config     *config;

    if (ipv6_config == NULL) {
        ipv6_config = sfPolicyConfigCreate();
    }

    // allocate everything
    prefixwl = (struct IP_List_head *)    calloc(1, sizeof (struct IP_List_head));
    routerwl = (struct MAC_Entry_head *)  calloc(1, sizeof (struct MAC_Entry_head));
    hostwl   = (struct MAC_Entry_head *)  calloc(1, sizeof (struct MAC_Entry_head));
    routers  = (struct IPv6_Hosts_head *) calloc(1, sizeof (struct IPv6_Hosts_head));
    hosts    = (struct IPv6_Hosts_head *) calloc(1, sizeof (struct IPv6_Hosts_head));
    unconf   = (struct IPv6_Hosts_head *) calloc(1, sizeof (struct IPv6_Hosts_head));
    stat     = (struct IPv6_Statistics *) calloc(1, sizeof (struct IPv6_Statistics));
    config   = (struct IPv6_Config *)     calloc(1, sizeof (struct IPv6_Config));
    context  = (struct IPv6_State *)      calloc(1, sizeof (struct IPv6_State));
    if (!routerwl || !hostwl || !prefixwl || !routers || !hosts || !unconf
        || !stat || !config || !context || !ipv6_config)
        _dpd.fatalMsg("Could not allocate IPv6 dyn-pp configuration struct.\n");

    // initialize
    STAILQ_INIT(prefixwl);
    RB_INIT(&routerwl->data);
    RB_INIT(&hostwl->data);
    RB_INIT(&routers->data);
    RB_INIT(&hosts->data);
    RB_INIT(&unconf->data);

    config->router_whitelist = routerwl;
    config->host_whitelist   = hostwl;
    config->prefix_whitelist = prefixwl;

    IPv6_Parse(args, config);
    context->config  = config;
    context->stat    = stat;
    
    context->routers     = routers;
    context->hosts       = hosts;
    context->unconfirmed = unconf;
    context->routers->entry_limit     = context->config->max_routers;
    context->hosts->entry_limit       = context->config->max_hosts;
    context->unconfirmed->entry_limit = context->config->max_unconfirmed;

    sfPolicyUserPolicySet(ipv6_config, _dpd.getParserPolicy());
    sfPolicyUserDataSetCurrent(ipv6_config, context);

    /* Register the preprocessor function, priority, ICMP, ID PP_IPv6
     * -- we use PRIORITY_NORMALIZE because it's ok to run after frag3
     * and receive only reassembled packets.
     * Change to PRIORITY_FIRST if any checks have to see fragments as well.
     */
    _dpd.addPreproc(IPv6_Process, PRIORITY_NORMALIZE, PP_IPv6, PROTO_BIT__ICMP);
    //_dpd.addPreproc(IPv6_Process, PRIORITY_FIRST, PP_IPv6, PROTO_BIT__ALL);

    _dpd.addPreprocResetStats(IPv6_ResetStats, NULL, PRIORITY_FIRST, PP_IPv6);
    _dpd.registerPreprocStats("ipv6", IPv6_PrintStats);
#ifdef PERF_PROFILING
    _dpd.addPreprocProfileFunc("ipv6", (void *)&ipv6PerfStats, 0, _dpd.totalPerfStats);
#endif

    // and now all rule options:
    _dpd.preprocOptRegister("ipv", IPv6_Rule_Init, IPv6_Rule_Eval,
            free, IPv6_Rule_Hash, IPv6_Rule_KeyCompare, NULL, NULL);
    _dpd.preprocOptRegister("ip6_exthdr", IPv6_Rule_Init, IPv6_Rule_Eval,
            free, IPv6_Rule_Hash, IPv6_Rule_KeyCompare, NULL, NULL);
    _dpd.preprocOptRegister("ip6_extnum", IPv6_Rule_Init, IPv6_Rule_Eval,
            free, IPv6_Rule_Hash, IPv6_Rule_KeyCompare, NULL, NULL);
    _dpd.preprocOptRegister("ip6_flow", IPv6_Rule_Init, IPv6_Rule_Eval,
            free, IPv6_Rule_Hash, IPv6_Rule_KeyCompare, NULL, NULL);
    _dpd.preprocOptRegister("ip6_tclass", IPv6_Rule_Init, IPv6_Rule_Eval,
            free, IPv6_Rule_Hash, IPv6_Rule_KeyCompare, NULL, NULL);
    _dpd.preprocOptRegister("ip6_option", IPv6_Rule_Init, IPv6_Rule_Eval,
            free, IPv6_Rule_Hash, IPv6_Rule_KeyCompare, NULL, NULL);
    _dpd.preprocOptRegister("ip6_optval", IPv6_Rule_Init, IPv6_Rule_Eval,
            free, IPv6_Rule_Hash, IPv6_Rule_KeyCompare, NULL, NULL);
    _dpd.preprocOptRegister("ip6_rh", IPv6_Rule_Init, IPv6_Rule_Eval,
            free, IPv6_Rule_Hash, IPv6_Rule_KeyCompare, NULL, NULL);
    _dpd.preprocOptRegister("ip6_ext_ordered", IPv6_Rule_Init, IPv6_Rule_Eval,
            free, IPv6_Rule_Hash, IPv6_Rule_KeyCompare, NULL, NULL);
    _dpd.preprocOptRegister("icmp6_nd", IPv6_Rule_Init, IPv6_Rule_Eval,
            free, IPv6_Rule_Hash, IPv6_Rule_KeyCompare, NULL, NULL);
    _dpd.preprocOptRegister("icmp6_nd_option", IPv6_Rule_Init, IPv6_Rule_Eval,
            free, IPv6_Rule_Hash, IPv6_Rule_KeyCompare, NULL, NULL);

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Preprocessor: IPv6 is initialized\n"););
}

/**
 * Count packet in statistics.
 *
 * @param p current packet
 * @param stat my statistics
 *
 * @return void function
 */
inline static void IPv6_UpdateStats(const SFSnortPacket *p, struct IPv6_Statistics *stat)
{
    /* IPv6_Process already handles
     *      pkt_seen and pkt_invalid
     * and aborts if not pkt_ip6h
     */
    stat->pkt_ip6h++;

    if (p->icmp_header) {
        switch(p->icmp_header->type) {
        case ICMP6_SOLICITATION:
            stat->pkt_icmp_rsol++;
            break;
        case ICMP6_N_SOLICITATION:
            stat->pkt_icmp_nsol++;
            break;
        case ICMP6_ADVERTISEMENT:
            stat->pkt_icmp_radv++;
            break;
        case ICMP6_N_ADVERTISEMENT:
            stat->pkt_icmp_nadv++;
            break;
        case ICMP6_UNREACH:
            stat->pkt_icmp_unreach++;
            break;
        case ICMP6_MEMBERSHIP_QUERY:
            stat->pkt_icmp_mlquery++;
            break;
        case ICMP6_MEMBERSHIP_REPORT:
        case MLDV2_LISTENER_REPORT:
            stat->pkt_icmp_mlreport++;
            break;
        default:
            stat->pkt_icmp_other++;
            break;
        }
    }
}

/* simple stateless checks of extension headers */
inline static void IPv6_Process_Extensions(const SFSnortPacket *p, struct IPv6_State *context __attribute__((unused)))
{
    uint_fast8_t i;
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGBASE,
            "IPv6_Process_Extensions() ext num = %d\n",
            p->num_ip6_extensions););
    for(i = 0; i < p->num_ip6_extensions; i++) {
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGBASE,
            "IPv6_Process_Extensions() ext type = %d\n",
            p->ip6_extensions[i].option_type););

        if (p->ip6_extensions[i].option_type != IPPROTO_HOPOPTS
            && p->ip6_extensions[i].option_type != IPPROTO_DSTOPTS) {
            continue;
        } else {
            /* hbh_hdr   is the Ext Hdr with type and length
             * hbh_hdr+1 is the first option with type and length
             * cursor    iterates over the options
             */
            struct ip6_hbh *hbh_hdr = (struct ip6_hbh*) p->ip6_extensions[i].option_data;
            u_int16_t ext_len = (hbh_hdr->ip6h_len + 1) << 3;
            u_int8_t *cursor  = (u_int8_t *) (hbh_hdr+1);
            u_int8_t *ext_end = ((u_int8_t *) hbh_hdr) + ext_len;
            bool only_padding = true;
            bool last_was_padding = false;          // keep state between two options
            bool last_was_padding_alerted = false;  // alarm only once per packet
            u_int8_t* c;

            while (cursor < ext_end) {
                struct ip6_opt *opt = (struct ip6_opt*) cursor;
                switch (opt->ip6o_type) {
                case 0: // Pad1
                    if (last_was_padding && !last_was_padding_alerted) {
                        ALERT(SID_IP6_CONSEC_PADDING_OPT);
                        last_was_padding_alerted = true;
                    }
                    last_was_padding = true;
                    cursor += 1;
                    break;
                case 1: // PadN
                    if (last_was_padding && !last_was_padding_alerted) {
                        ALERT(SID_IP6_CONSEC_PADDING_OPT);
                        last_was_padding_alerted = true;
                    }
                    last_was_padding = true;

                    for(c = cursor+2; c < (cursor + 2 + opt->ip6o_len); c++) {
                        if (*c != 0) {
                            ALERT(SID_IP6_PADDING_OPT_DATA);
                            break;
                        }
                    }
                    
                    cursor += 2 + opt->ip6o_len;
                    break;
                default: // everything else
                    only_padding = false;
                    last_was_padding = false;
                    cursor += 2 + opt->ip6o_len;
                    break;
                }
            }
            if (cursor != ext_end)
                ALERT(SID_IP6_OPTION_LENGTH_ERR);
            if (only_padding)
                ALERT(SID_IP6_ONLY_PADDING_EXT);
        }
    }
}

/**
 * Processing callback function for all packets.
 *
 * @param p packet to detect anomalies and overwrite attacks on
 * @param context unused
 *
 * @return void function
 */
void IPv6_Process(void *pkt, void *snortcontext __attribute__((unused)))
{
    PROFILE_VARS;
    SFSnortPacket *p = (SFSnortPacket *) pkt;
    struct IPv6_State *context;

    sfPolicyUserPolicySet(ipv6_config, _dpd.getRuntimePolicy());
    context = (struct IPv6_State *) sfPolicyUserDataGetCurrent(ipv6_config);

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "IPv6_Process() called, pkt type = %d\n",
        (p && p->ip6h) ? p->ip6h->next : 0););

    context->stat->pkt_seen++;
    /* is the packet and the configuration valid? */
    if ((p == NULL) || (context == NULL)) {
        context->stat->pkt_invalid++;
        return;
    } else if (!p->ip6h) {
        return;
    } else if (p->ip_fragmented) { /* skip incomplete packets */
        context->stat->pkt_fragments++;
        return;
    }
    // else

    PREPROC_PROFILE_START(ipv6PerfStats);
    IPv6_UpdateStats(p, context->stat);
    if (p->ip6h->next != IPPROTO_ICMPV6) {
        context->stat->pkt_other++;
    } else {
        context->stat->pkt_icmpv6++;

        IPv6_Process_Extensions(p, context);
        
        if (ND_hdrlen[p->icmp_header->type]) {
            IPv6_Process_ND_Options(p, context);
        }
        if (p->icmp_header->type == ICMP6_ADVERTISEMENT) {
            IPv6_Process_ICMPv6_RA_stateless(p);
        }
        if (context->config->track_ndp) {
            IPv6_Process_ICMPv6(p, context);
        }
    }
    PREPROC_PROFILE_END(ipv6PerfStats);
}

/**
 * Check ICMPv6 ND Options.
 * icmp_hdr_len is givenby caller, because it varies depending on msg type
 */
inline static void IPv6_Process_ND_Options(const SFSnortPacket *p, struct IPv6_State *context __attribute__((unused)))
{
    size_t icmp_hdr_len = ND_hdrlen[p->icmp_header->type];
    size_t len = p->ip_payload_size - icmp_hdr_len;
    const u_int8_t *ptr = p->ip_payload + icmp_hdr_len;
    struct nd_opt_hdr *option = (struct nd_opt_hdr *) ptr;

    while (len) {
        uint_fast8_t optlen = 8 * (option->nd_opt_len);
        if (option->nd_opt_type == ND_OPT_SOURCE_LINKADDR
            && memcmp(p->ether_header->ether_source, option + 1, MAC_LENGTH))
            ALERT(SID_ICMP6_LINKADDR_MISMATCH);
 
        if (optlen > len) {
            // should this be an alert of its own?
            _dpd.logMsg("IPv6 decoder problem. malformed ND option lenghts.");
            break;
        }
        len -= optlen;
        option = (struct nd_opt_hdr *) ((u_int8_t*) option + (8 * option->nd_opt_len));
    }
}

/**
 * Process an IPv6 ICMP packet.
 */
static void IPv6_Process_ICMPv6(const SFSnortPacket *p, struct IPv6_State *context)
{
    // safety check
    if (!p || !p->icmp_header) {
        _dpd.logMsg("IPv6 decoder problem. ICMP packet without struct icmp_header");
        return;
    }

    /* check if ongoing DAD */
    struct IPv6_Host *ip_entry;
    ip_entry = get_host_entry(context->unconfirmed, &(p->ip6h->ip_dst));
    if (ip_entry) {
        ip_entry->type.dad.contacted++;
    }

    /* check type */
    switch (p->icmp_header->type) {
    case ICMP6_ADVERTISEMENT:
        IPv6_Process_ICMPv6_RA(p, context);
        break;
    case ICMP6_N_ADVERTISEMENT:
        IPv6_Process_ICMPv6_NA(p, context);
        break;
    case ICMP6_N_SOLICITATION:
        IPv6_Process_ICMPv6_NS(p, context);
        break;
    default:
        break;
    }

    /* periodically expire old entries from state */
    if (p->pkt_header->ts.tv_sec >= context->next_expire) {
        //DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "%s expire state\n", pprint_ts(p->pkt_header->ts.tv_sec)););
        context->next_expire = p->pkt_header->ts.tv_sec + context->config->expire_run_interval;
        state_host_expirelist(context->routers,     p->pkt_header->ts.tv_sec, context->config->keep_state_duration);
        state_host_expirelist(context->hosts,       p->pkt_header->ts.tv_sec, context->config->keep_state_duration);
        state_host_expirelist(context->unconfirmed, p->pkt_header->ts.tv_sec, context->config->keep_state_duration);
    };

}

/**
 * Process an IPv6 RA packet stateless, ie. check lifetime.
 */
static void IPv6_Process_ICMPv6_RA_stateless(const SFSnortPacket *p)
{
    struct ICMPv6_RA *radv = (struct ICMPv6_RA*) p->ip_payload;

    if (radv->nd_ra_lifetime == 0) {
        ALERT(SID_ICMP6_RA_LIFETIME0);
    }
}

/**
 * Process an IPv6 RA packet.
 */
static void IPv6_Process_ICMPv6_RA(const SFSnortPacket *p, struct IPv6_State *context)
{
    struct IPv6_Host *hostentry;
    struct ICMPv6_RA *radv;
    struct nd_opt_hdr *option;
    struct nd_opt_prefix_info *prefix_info;
    sfip_t *prefix;
    uint_fast16_t len = p->ip_payload_size;
    LISTOP_RET rc;
    SFIP_RET sfip_rc;

    radv   = (struct ICMPv6_RA*) p->ip_payload;
    option = (struct nd_opt_hdr *) (radv + 1);
    len -= sizeof (struct ICMPv6_RA);

    while (len) {
        // check some known options
        switch (option->nd_opt_type) {
        case ND_OPT_PREFIX_INFORMATION:
            prefix_info = (struct nd_opt_prefix_info *) option;
            prefix = sfip_alloc_raw(&prefix_info->nd_opt_pi_prefix, AF_INET6, &sfip_rc);
            if (sfip_rc != SFIP_SUCCESS) {
                _dpd.errMsg("sfip_alloc_raw() failed\n");
                return;
            }
            sfip_set_bits(prefix, prefix_info->nd_opt_pi_prefix_len);
            if (context->config->report_prefix_change && !ip_inlist(context->config->prefix_whitelist, prefix)) {
                DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "IP prefix %s/%d not in "
                    "configured list\n", sfip_to_str(prefix), sfip_bits(prefix)););
                ALERT(SID_ICMP6_RA_UNKNOWN_PREFIX);
            }

            break;
        default:
            break;
        }
        len -= 8 * (option->nd_opt_len);
        option = (struct nd_opt_hdr *) ((u_int8_t*) option + (8 * option->nd_opt_len));
    }
    // add state
    rc = state_router_add(context->routers,
                     &hostentry,
                     &p->pkt_header->ts,
                     p->ether_header->ether_source,
                     &p->ip6h->ip_src,
                     prefix, radv);

    if (rc == LISTOP_ADDED) {
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "new IPv6 router advertised: %s / %s\n",
                      pprint_mac(p->ether_header->ether_source),
                      sfip_to_str(&p->ip6h->ip_src)););

        // different events, depending on existing whitelist
        if (context->config->router_whitelist
         && !RB_EMPTY(&context->config->router_whitelist->data)
         && !get_mac_entry(context->config->router_whitelist,
                           p->ether_header->ether_source)) {
            ALERT(SID_ICMP6_INVALID_ROUTER_MAC);
        } else {
            ALERT(SID_ICMP6_RA_NEW_ROUTER);
        }
    }
}

/**
 * Process neighbour advertisement msgs
 */
static void IPv6_Process_ICMPv6_NA(const SFSnortPacket *p, struct IPv6_State *context)
{
    /* check if part of DAD */
    struct nd_neighbor_advert *na = (struct nd_neighbor_advert *) p->ip_payload;
    SFIP_RET sfrc;
    sfip_t *target_ip;
    struct IPv6_Host *ip_entry;

    target_ip = sfip_alloc_raw(&na->nd_na_target, AF_INET6, &sfrc);
    if (sfrc != SFIP_SUCCESS) {
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "sfip_alloc_raw failed in %s:%d\n", __FILE__, __LINE__););
        return;
    };

    ip_entry = get_host_entry(context->unconfirmed, target_ip);
    if (!ip_entry) {
        /* IP is yet unknown --> put into DAD state */
        ip_entry = create_dad_entry_ifnew(context->unconfirmed,
                                           &p->pkt_header->ts,
                                           p->ether_header->ether_source,
                                           target_ip);
        /* no DAD info, so simply trust NA
         *
         * TODO: this leads to new DoS opportunity
         *  --> only confirm after some other communication occurs (TCP, UDP or MLD)

        confirm_host(p, context, target_ip);
         */
        return;
    }

    /* current DAD for this IP, now check details */
    if (!memcmp(p->ether_header->ether_source, ip_entry->ether_source, MAC_LENGTH)) {
        /* MAC matches -- same node */
        if (ip_entry->type.dad.contacted) {
            /* host entered the network */
            // possible optimization: keep IPv6_Host object to save free/malloc
            confirm_host(p, context, target_ip);
            del_dad_entry(context->unconfirmed, ip_entry);
        }
        /* else DAD exists, but still unconfirmed, so do nothing
         *  (could be result of NA flood/spoof) */
    } else {
        /* MAC does not match -- collision
         * --> check if NA from known MAC (legitimate) or not (suspicious) */
        if (get_host_entry(context->hosts, target_ip)
            || get_host_entry(context->routers, target_ip)
            || get_mac_entry(context->config->host_whitelist, p->ether_header->ether_source)
            || get_mac_entry(context->config->router_whitelist, p->ether_header->ether_source)) {
            // looks legitimate
            DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "DAD collision with host %s / %s\n",
                          pprint_mac(p->ether_header->ether_source),
                          sfip_to_str(target_ip)););
            ALERT(SID_ICMP6_DAD_COLLISION);
        } else {
            // never seen the 2nd host before --> probably an attack
            DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "DAD DoS from (prob. fake MAC) %s / %s\n",
                          pprint_mac(p->ether_header->ether_source),
                          sfip_to_str(target_ip)););
            ALERT(SID_ICMP6_DAD_DOS);
        }
    }
}

/**
 * Process neighbour solicitation msgs
 */
static void IPv6_Process_ICMPv6_NS(const SFSnortPacket *p, struct IPv6_State *context)
{
    struct nd_neighbor_solicit *ns = (struct nd_neighbor_solicit *) p->ip_payload;
    SFIP_RET rc;
    sfip_t *target_ip;
    struct IPv6_Host *ip_entry;

    target_ip = sfip_alloc_raw(&ns->nd_ns_target, AF_INET6, &rc);
    if (rc != SFIP_SUCCESS) {
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "sfip_alloc_raw failed in %s:%d\n", __FILE__, __LINE__););
        return;
    };

    // sfip_compare() is confusing, roll my own test for "::"
    if (p->ip6h->ip_src.ip.u6_addr32[0]
     || p->ip6h->ip_src.ip.u6_addr32[1]
     || p->ip6h->ip_src.ip.u6_addr32[2]
     || p->ip6h->ip_src.ip.u6_addr32[3]) {
        /* src address set --> LLA resolution or reachability check */
        return;
    }

    /* else:
     * unspecified address
     * --> i.e. new node tries to get address
     * --> check if already known
     */
    ip_entry = get_host_entry(context->hosts, target_ip);
    if (ip_entry) {
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Neighbour solicitation from known host\n"););
        return;
    }

    /* this is the expected part: the IP is yet unknown --> put into DAD state */
    ip_entry = create_dad_entry_ifnew(context->unconfirmed,
                                       &p->pkt_header->ts,
                                       p->ether_header->ether_source,
                                       target_ip);
    if (!ip_entry) {
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "create_dad_entry_ifnew failed in %s:%d\n", __FILE__, __LINE__););
        return;
    }
    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "%s DAD started by %s / %s\n",
                  pprint_ts(ip_entry->last_adv_ts),
                  pprint_mac(ip_entry->ether_source),
                  sfip_to_str(&ip_entry->ip)););
    ALERT(SID_ICMP6_ND_NEW_DAD);
}

/**
 * Parse the configuration options in snort.conf
 *
 * Currently supported options: router_mac, host_mac, net_prefix
 */
void set_default_config(struct IPv6_Config *config)
{
    config->track_ndp = true;
    // for testing: 1h, later: 2-12h
    config->keep_state_duration = 60*60;
    config->expire_run_interval = 20*60;
    // not sure if these are realistic, should be high enough
    config->max_routers     = 32;
    config->max_hosts       = 8192;
    config->max_unconfirmed = 32768;

    return;
}

#define BIN_OPTION(X, Y) if (!strcasecmp(X, arg)) {         \
                             (Y) = false;                   \
                             _dpd.logMsg("  " X "\n");      \
                             arg = strtok(NULL, " \t\n\r"); \
                         }

void read_num(char **arg, const char *param, u_int32_t *configptr)
{
    uint_fast32_t minutes;
    *arg = strtok(NULL, " \t\n\r");
    minutes = (uint_fast32_t) strtoul(*arg, NULL, 10);
    if (errno) {
        _dpd.fatalMsg("  Invalid parameter to %s\n", param);
    }
    *configptr = 60 * minutes;
    _dpd.logMsg("  %s = %u minutes = %u secs\n",
                param, minutes, *configptr);
    *arg = strtok(NULL, " \t\n\r");
}

static void IPv6_Parse(char *args, struct IPv6_Config *config)
{
    char *arg;
    char ismac;
    sfip_t *prefix;
    SFIP_RET rc;

    set_default_config(config);
    _dpd.logMsg("IPv6 preprocessor config:\n");
    if (!args) {
        _dpd.logMsg("\tno additional parameters\n");
        return;
    }

    arg = strtok(args, " \t\n\r");
    while (arg) {
        if(!strcasecmp("router_mac", arg)) { // and now a list of 0-n router MACs
            config->report_new_routers = true;
            while ((arg = strtok(NULL, ", \t\n\r")) && (ismac = IS_MAC(arg))) {
                mac_add(config->router_whitelist, arg);
                _dpd.logMsg("  default router MAC %s\n", arg);
            }
        } else if(!strcasecmp("host_mac", arg)) { // and now a list of 0-n host MACs
            config->report_new_hosts = true;
            while ((arg = strtok(NULL, ", \t\n\r")) && (ismac = IS_MAC(arg))) {
                mac_add(config->host_whitelist, arg);
                _dpd.logMsg("  default host MAC %s\n", arg);
            }
        } else if(!strcasecmp("net_prefix", arg)) { // and now a list of 0-n prefixes
            config->report_prefix_change = true;
            while ((arg = strtok(NULL, ", \t\n\r")) && strchr(arg, '/')) {  // TODO remove /-check
                prefix = sfip_alloc(arg, &rc);
                if (rc == SFIP_SUCCESS) {
                    add_ip(config->prefix_whitelist, prefix);
                    _dpd.logMsg("  default net prefix %s/%d\n",
                        sfip_to_str(prefix), sfip_bits(prefix));
                } else {
                    _dpd.fatalMsg("  Invalid prefix %s\n", arg);
                }
            }
        } else if(!strcasecmp("max_routers", arg)) {
            read_num(&arg, "max_routers", &(config->max_routers));
        } else if(!strcasecmp("max_hosts", arg)) {
            read_num(&arg, "max_hosts", &(config->max_hosts));
        } else if(!strcasecmp("max_unconfirmed", arg)) {
            read_num(&arg, "max_unconfirmed", &(config->max_unconfirmed));
        } else if(!strcasecmp("keep_state", arg)) {
            read_num(&arg, "keep_state", &(config->keep_state_duration));
        } else if(!strcasecmp("expire_run", arg)) {
            read_num(&arg, "expire_run", &(config->expire_run_interval));
        } else BIN_OPTION("disable_tracking", config->track_ndp)
          else {
            _dpd.fatalMsg("IPv6: Invalid option %s\n", arg);
        }
    }
}

