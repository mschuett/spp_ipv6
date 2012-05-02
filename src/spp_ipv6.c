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

    _dpd.logMsg("\nAll routers (%d entries):\n", hostset_count(context->routers));
    hostset_print_all(context->routers);

    _dpd.logMsg("\nAll hosts (%d entries):\n", hostset_count(context->hosts));
    hostset_print_all(context->hosts);

    _dpd.logMsg("\nAll hosts in DAD state (%d entries):\n", dad_count(context->unconfirmed));
    dad_print_all(context->unconfirmed);

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
    IP_set                 *prefixwl;
    MAC_set                *routerwl;
    MAC_set                *hostwl;
    struct IPv6_Statistics *stat;
    struct IPv6_State      *context;
    struct IPv6_Config     *config;

    if (ipv6_config == NULL) {
        ipv6_config = sfPolicyConfigCreate();
    }

    // allocate everything, try to guess sensible default data struct sizes
    prefixwl = ipset_create( 5);
    routerwl = macset_create( 8);
    hostwl   = macset_create(32);
    stat     = (struct IPv6_Statistics *) calloc(1, sizeof (struct IPv6_Statistics));
    config   = (struct IPv6_Config *)     calloc(1, sizeof (struct IPv6_Config));
    context  = (struct IPv6_State *)      calloc(1, sizeof (struct IPv6_State));
    if (!routerwl || !hostwl || !prefixwl
        || !stat || !config || !context || !ipv6_config)
        _dpd.fatalMsg("Could not allocate IPv6 dyn-pp configuration struct.\n");

    config->router_whitelist = routerwl;
    config->host_whitelist   = hostwl;
    config->prefix_whitelist = prefixwl;

    IPv6_Parse(args, config);
    context->config  = config;
    context->stat    = stat;
    
    // these are created after IPv6_Parse, so they can directly use user config values
    context->routers     = hostset_create(3,
            context->config->max_routers,
            context->config->mem_routers);
    context->hosts       = hostset_create(64,
            context->config->max_hosts,
            context->config->mem_hosts);
    context->unconfirmed = dad_create(256,
            context->config->max_unconfirmed,
            context->config->mem_unconfirmed);
    if (!context->routers || !context->hosts || !context->unconfirmed)
        _dpd.fatalMsg("Could not allocate IPv6 dyn-pp configuration struct.\n");

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
    //DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,
    //    "IPv6_Process_Extensions() ext num = %d\n",
    //    p->num_ip6_extensions););
    for(i = 0; i < p->num_ip6_extensions; i++) {
        //DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,
        //    "IPv6_Process_Extensions() ext type = %d\n",
        //    p->ip6_extensions[i].option_type););

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

    //DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "IPv6_Process() called, pkt type = %d\n",
    //    (p && p->ip6h) ? p->ip6h->next : 0););

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
    HOST_t *ip_entry;

    // safety check
    if (!p || !p->icmp_header) {
        _dpd.logMsg("IPv6 decoder problem. ICMP packet without struct icmp_header");
        return;
    }

    //DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,
    //    "IPv6_Process_ICMPv6() icmpv6 type %d\n",
    //    p->icmp_header->type););
            
    /* check if ongoing DAD */
    ip_entry = dad_get(context->unconfirmed, host_set(NULL, mac_from_pkt(p), &(p->ip6h->ip_dst), 0));
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

    /*
    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,
            "packet: %d/%s; next_expire: %d/%s %s\n",
            p->pkt_header->ts.tv_sec, strdup(ts_str(p->pkt_header->ts.tv_sec)),
            context->next_expire, strdup(ts_str(context->next_expire)),
            ((p->pkt_header->ts.tv_sec >= context->next_expire) ? "--> calling dad_expire()" : "" )););
    periodically expire old entries from state */
    if (p->pkt_header->ts.tv_sec >= context->next_expire) {
        context->next_expire = p->pkt_header->ts.tv_sec + context->config->expire_run_interval;
        dad_expire(context->unconfirmed);
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
    struct ICMPv6_RA *radv;
    struct nd_opt_hdr *option;
    struct nd_opt_prefix_info *prefix_info;
    IP_t prefix = {0};
    uint_fast16_t len = p->ip_payload_size;
    DATAOP_RET addrc;
    SFIP_RET sfrc;
    HOST_t *pivot, *entry;

    radv   = (struct ICMPv6_RA*) p->ip_payload;
    option = (struct nd_opt_hdr *) (radv + 1);
    len -= sizeof (struct ICMPv6_RA);

    while (len) {
        // check some known options
        switch (option->nd_opt_type) {
        case ND_OPT_PREFIX_INFORMATION:
            // TODO: support multiple prefixes per router
            if (sfip_is_set(&prefix)) {
                _dpd.errMsg("got RA with multiple prefix options -- will use only the first one\n");
                break;
            }
            
            prefix_info = (struct nd_opt_prefix_info *) option;
            sfrc = sfip_set_raw(&prefix, &prefix_info->nd_opt_pi_prefix, AF_INET6);
            if (sfrc != SFIP_SUCCESS) {
                _dpd.errMsg("sfip_set_raw() failed\n");
                return;
            }
            
            sfip_set_bits(&prefix, prefix_info->nd_opt_pi_prefix_len);
            if (context->config->report_prefix_change
                    && !ipset_contains(context->config->prefix_whitelist, &prefix)) {
                DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "IP prefix %s not in "
                    "configured list\n", ip_str(&prefix)););
                ALERT(SID_ICMP6_RA_UNKNOWN_PREFIX);
            }

            break;
        default:
            break;
        }
        len -= 8 * (option->nd_opt_len);
        option = (struct nd_opt_hdr *) ((u_int8_t*) option + (8 * option->nd_opt_len));
    }
    
    if (!sfip_is_set(&prefix)) {
        // TODO: add alert(?)
        _dpd.errMsg("got RA without any prefix options -- how unusual...\n");
        return;
    }
    
    // check for known router
    pivot = host_set(NULL, mac_from_pkt(p), ip_from_sfip(&p->ip6h->ip_src), ts_from_pkt(p));
    host_setrouterdata(pivot, radv->flags.all, radv->nd_ra_lifetime, &prefix);
    entry = hostset_get(context->routers, pivot);
    if (entry) {
        // known router, only check for changes
        if (!ip_eq(entry->type.router.prefix, &prefix)) {
            DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,
                "announced router prefix changed from %s to %s\n",
                ip_str(entry->type.router.prefix), ip_str(&prefix)););
            ALERT(SID_ICMP6_RA_PREFIX_CHANGED);
            // update state
            ip_cpy(entry->type.router.prefix, &prefix);
        }

        if ((entry->type.router.flags.all != pivot->type.router.flags.all)
            || (entry->type.router.lifetime != pivot->type.router.lifetime)) {
            DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,
                "announced router flags changed from 0x%x/lifetime %d to 0x%x/lifetime %d\n",
                entry->type.router.flags.all, entry->type.router.lifetime,
                pivot->type.router.flags.all, pivot->type.router.lifetime););
            ALERT(SID_ICMP6_RA_FLAGS_CHANGED);
            // update state
            entry->type.router.lifetime = pivot->type.router.lifetime;
            entry->type.router.flags.all = pivot->type.router.flags.all;
        }
    }
    
    
    // add state
    entry = host_set(NULL, mac_from_pkt(p), ip_from_sfip(&p->ip6h->ip_src), ts_from_pkt(p));
    host_setrouterdata(entry, radv->flags.all, radv->nd_ra_lifetime, &prefix);
    
    addrc = hostset_add(context->routers, entry);
    if (addrc == DATA_ADDED) {
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "new IPv6 router advertised: %s\n",
                      host_str(entry)););

        // different events, depending on existing whitelist
        if (context->config->router_whitelist
         && !macset_empty(context->config->router_whitelist)
         && !macset_contains(context->config->router_whitelist, mac_from_pkt(p))) {
            ALERT(SID_ICMP6_INVALID_ROUTER_MAC);
        } else {
            ALERT(SID_ICMP6_RA_NEW_ROUTER);
        }
    } else if (addrc == DATA_EXISTS) {
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "known IPv6 router advertised: %s\n",
                      host_str(entry)););
    } else {
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "error in processing RA: %s\n",
                      host_str(entry)););
    }
}

/**
 * Process neighbour advertisement msgs, i.e. check if part of DAD
 */
static void IPv6_Process_ICMPv6_NA(const SFSnortPacket *p, struct IPv6_State *context)
{
    struct nd_neighbor_advert *na = (struct nd_neighbor_advert *) p->ip_payload;
    SFIP_RET sfrc;
    DATAOP_RET addrc;
    IP_t target_ip;
    HOST_t *pivot, *dad_entry;
    
    /* NB: this whole address verification does not check the
     * address of the msg sender but that of the msg's subject    */
    sfrc = sfip_set_raw(&target_ip, &na->nd_na_target, AF_INET6);
    if (sfrc != SFIP_SUCCESS) {
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "sfip_set failed in %s:%d\n", __FILE__, __LINE__););
        return;
    };

    pivot = host_set(NULL, mac_from_pkt(p), &target_ip, ts_from_pkt(p));
    if (hostset_contains(context->hosts, pivot, ts_from_pkt(p))
        || hostset_contains(context->routers, pivot, ts_from_pkt(p))) {
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "NA for known host %s\n",
                        host_str(pivot)););
        return;
    }
    
    // otherwise: new host --> DAD
    dad_entry = dad_get(context->unconfirmed, pivot);
    if (dad_entry) {
        /* IP/MAC is already in DAD state */
        dad_entry->last_adv_ts = ts_from_pkt(p);
        if (dad_entry->type.dad.contacted) {
            /* host also was contacted by someone
             *  -- so it correctly entered the network */
            confirm_host(context, dad_entry);
        }
        /* else DAD exists, but still unconfirmed,
         * so do nothing (could be result of NA flood/spoof) */
        return;
    }
    
    /* IP/MAC combination is yet unknown --> check IP, check MAC and put into DAD state */
    
    
    /* check IP.
     * 
     * Problem here: we can detect whether the IP collides with another
     * ongoing DAD. -- But we cannot check against the context->hosts set,
     * because the sfxhash does not allow to search by IP.  :-(
     * Thus we can no longer trigger the ALERT(SID_ICMP6_DAD_DOS);
     */
    if (dad_count_ip(context->unconfirmed, &pivot->ip)) {
        // already have a DAD for the same IP
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "NA DAD collision for IP %s\n",
                        ip_str(&pivot->ip)););
        ALERT(SID_ICMP6_DAD_COLLISION);
    }
    
    addrc = dad_add(context->unconfirmed, pivot);
    switch (addrc) {
        case DATA_ADDED:
            DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "NA started by %s\n", host_str(pivot)););
            ALERT(SID_ICMP6_ND_NEW_DAD);
            return;
        case DATA_NOMEM: 
            DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "NA dad_add failed, out of memory\n"););
            return;
        default:
            DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "NA dad_add failed\n"););
            return;
    }
}

/**
 * Process neighbour solicitation msgs
 */
static void IPv6_Process_ICMPv6_NS(const SFSnortPacket *p, struct IPv6_State *context)
{
    struct nd_neighbor_solicit *ns = (struct nd_neighbor_solicit *) p->ip_payload;
    SFIP_RET rc;
    DATAOP_RET addrc;
    IP_t target_ip;
    HOST_t *pivot, *dad_entry;

    // sfip_compare() is confusing, roll my own test for "::"
    if (p->ip6h->ip_src.ip.u6_addr32[0]
     || p->ip6h->ip_src.ip.u6_addr32[1]
     || p->ip6h->ip_src.ip.u6_addr32[2]
     || p->ip6h->ip_src.ip.u6_addr32[3]) {
        /* src address set --> LLA resolution or reachability check --> ignore */
        return;
    }

    /* NB: this whole address verification does not check the
     * address of the msg sender but that of the msg subject    */
    rc = sfip_set_raw(&target_ip, &ns->nd_ns_target, AF_INET6);
    if (rc != SFIP_SUCCESS) {
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "sfip_set failed in %s:%d\n", __FILE__, __LINE__););
        return;
    };

    pivot = host_set(NULL, mac_from_pkt(p), &target_ip, ts_from_pkt(p));
    if (hostset_contains(context->hosts, pivot, 0)
        || hostset_contains(context->routers, pivot, 0)) {
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "NS for known host %s\n", host_str(pivot)););
        return;
    }
    
    /* this is the expected part: the IP is yet unknown --> thus in DAD state */
    dad_entry = host_set(NULL, mac_from_pkt(p), &target_ip, ts_from_pkt(p));
    addrc = dad_add(context->unconfirmed, dad_entry);
    
    switch (addrc) {
        case DATA_EXISTS:
            DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "NS DAD hostset_add, item already existed\n"););
            return;
        case DATA_ADDED:
            DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "NS DAD started by %s\n", host_str(dad_entry)););
            ALERT(SID_ICMP6_ND_NEW_DAD);
            return;
        case DATA_NOMEM: 
            DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "NS DAD hostset_add failed, out of memory\n"););
            return;
        default:
            DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "NS DAD hostset_add failed\n"););
            return;
    }
}

/**
 * Parse the configuration options in snort.conf
 *
 * Currently supported options: router_mac, host_mac, net_prefix
 */
void set_default_config(struct IPv6_Config *config)
{
    config->track_ndp = true;
    config->expire_run_interval = 20*60;
    // not sure if these are realistic, should be high enough
    config->max_routers     = 32;
    config->max_hosts       = 8192;
    config->max_unconfirmed = 32768;
    
    /* TODO: add config option for memory cap */
    config->mem_routers     = 1024*1024;
    config->mem_hosts       = 1024*1024*2;
    config->mem_unconfirmed = 1024*1024*8;
    
    return;
}

#define BIN_OPTION(X, Y) if (!strcasecmp(X, arg)) {         \
                             (Y) = false;                   \
                             _dpd.logMsg("  " X "\n");      \
                             arg = strtok(NULL, " \t\n\r"); \
                         }

static inline void read_num(char **arg, const char *param, u_int32_t *configptr)
{
    uint_fast32_t input_num;
    
    *arg = strtok(NULL, " \t\n\r");
    input_num = (uint_fast32_t) strtoul(*arg, NULL, 10);
    if (errno) {
        _dpd.fatalMsg("  Invalid parameter to %s\n", param);
    }
    *configptr = input_num;
    _dpd.logMsg("  %s = %u\n", param, *configptr);
    *arg = strtok(NULL, " \t\n\r");
}

static void IPv6_Parse(char *args, struct IPv6_Config *config)
{
    char *arg;
    char ismac;
    IP_t *prefix;

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
                macset_add(config->router_whitelist, mac_parse(NULL, arg));
                //old_mac_add(config->router_whitelist, arg);
                _dpd.logMsg("  default router MAC %s\n", arg);
            }
        } else if(!strcasecmp("host_mac", arg)) { // and now a list of 0-n host MACs
            config->report_new_hosts = true;
            while ((arg = strtok(NULL, ", \t\n\r")) && (ismac = IS_MAC(arg))) {
                macset_add(config->host_whitelist, mac_parse(NULL, arg));
                //old_mac_add(config->host_whitelist, arg);
                _dpd.logMsg("  default host MAC %s\n", arg);
            }
        } else if(!strcasecmp("net_prefix", arg)) { // and now a list of 0-n prefixes
            config->report_prefix_change = true;
            while ((arg = strtok(NULL, ", \t\n\r")) && strchr(arg, '/')) {  // TODO remove /-check
                prefix = ip_parse(NULL, arg);
                if (prefix) {
                    DATAOP_RET rc;
                    rc = ipset_add(config->prefix_whitelist, prefix);
                    if (rc == DATA_ADDED)
                        _dpd.logMsg("  default net prefix %s\n", ip_str(prefix));
                    else
                        _dpd.logMsg("  cannot store net prefix %s\n", ip_str(prefix));
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
        } else if(!strcasecmp("mem_routers", arg)) {
            read_num(&arg, "mem_routers", &(config->mem_routers));
        } else if(!strcasecmp("mem_hosts", arg)) {
            read_num(&arg, "mem_hosts", &(config->mem_hosts));
        } else if(!strcasecmp("mem_unconfirmed", arg)) {
            read_num(&arg, "mem_unconfirmed", &(config->mem_unconfirmed));
        } else if(!strcasecmp("expire_run", arg)) {
            read_num(&arg, "expire_run", &(config->expire_run_interval));
        } else BIN_OPTION("disable_tracking", config->track_ndp)
          else {
            _dpd.fatalMsg("IPv6: Invalid option %s\n", arg);
        }
    }
    
    ipv6_config_print(config);
}

/**
 * Move a HOST_t out of the DAD and into the 'confirmed hosts' state,
 * and check MAC whitelist.
 */
static void confirm_host(struct IPv6_State *context, const HOST_t *newhost)
{
    DATAOP_RET rc;
    
    rc = hostset_add(context->hosts, newhost);

    if (rc != DATA_ADDED) {
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "cannot add state for new IPv6 host: %s\n",
                host_str(newhost)););
        return;
    }
    
    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "new IPv6 host: %s\n",
            host_str(newhost)););
    if (context->config->host_whitelist
            && !macset_contains(context->config->host_whitelist, &newhost->mac)
            && !macset_contains(context->config->router_whitelist, &newhost->mac)) {
        ALERT(SID_ICMP6_INVALID_HOST_MAC);
    } else {
        ALERT(SID_ICMP6_ND_NEW_HOST);
    }
    dad_remove(context->unconfirmed, newhost);
}

static void ipv6_config_print(struct IPv6_Config *config) {
    _dpd.logMsg(" == Stored configuration == \n");
    _dpd.logMsg("Routers/Hosts/DADs max: %d/%d/%d, mem: %d/%d/%d\n"
            "Flags track_ndp = %d, report_prefix_change = %d,\n"
            "report_new_routers = %d, report_new_hosts = %d\n",
            config->max_routers, config->max_hosts, config->max_unconfirmed,
            config->mem_routers, config->mem_hosts, config->mem_unconfirmed,
            config->track_ndp, config->report_prefix_change,
            config->report_new_routers, config->report_new_hosts);
    macset_print_all(config->router_whitelist, "router_whitelist");
    macset_print_all(config->host_whitelist, "host_whitelist");
    ipset_print_all(config->prefix_whitelist, "prefix_whitelist");
}