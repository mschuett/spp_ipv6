/*
 * spp_ipv6_ruleopt.c
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
 *   IPv6 Preprocessor functions related to rule option handling.
 *
 */

#include <errno.h>
#include "spp_ipv6.h"
#include "spp_ipv6_constants.h"
#include "spp_ipv6_data_structs.h"
// for rule option:
#include "sf_snort_plugin_api.h"
// for IPv6_Rule_Hash
#include "sfhashfcn.h"

/* reads whitespace and optional comparison operator;
 * advances the char* and returns the operator to use
 */
static enum cmp_op get_op(char **param_ptr)
{
    enum cmp_op op = check_eq;
    if (!*param_ptr) return op; // if called w/o params

    while (isblank(**param_ptr)) (*param_ptr)++;
    switch(*param_ptr[0]) {
    case '=': op = check_eq;  (*param_ptr)++; break;
    case '!': op = check_neq; (*param_ptr)++; break;
    case '<': op = check_lt;  (*param_ptr)++; break;
    case '>': op = check_gt;  (*param_ptr)++; break;
    case '&': op = check_and; (*param_ptr)++; break;
    case '^': op = check_xor; (*param_ptr)++; break;
    case '|': op = check_nand;(*param_ptr)++; break;
    }
    while (isblank(**param_ptr)) (*param_ptr)++;
    return op;
}

/* reads a decimal or hexadecimal number.
 * FatalMessage on error
 */
static u_int32_t get_num(char **param_ptr, const char *name)
{
    char *endptr;
    u_int32_t parameter;
    if (*param_ptr) {
        while (isblank(**param_ptr)) (*param_ptr)++;
        if (isdigit(*param_ptr[0])) {
            if ((*param_ptr)[0] == '0' && (*param_ptr)[1] == 'x') {
                (*param_ptr)++; (*param_ptr)++;
                parameter = (u_int32_t) _dpd.SnortStrtoul(*param_ptr, &endptr, 16);
            } else
                parameter = (u_int32_t) _dpd.SnortStrtoul(*param_ptr, &endptr, 10);

            if (!errno && endptr && (*endptr == '\0'))
                return parameter;
        }
    }
    DynamicPreprocessorFatalMessage("%s(%d) => keyword %s with invalid number %s\n",
        *(_dpd.config_file), *(_dpd.config_line), name, (*param_ptr ? *param_ptr : ""));
}

/* copied from src/detection-plugins/sf_snort_plugin_hdropts.c */
inline static bool checkField(enum cmp_op op, uint_fast32_t value1, uint_fast32_t value2)
{
    switch (op)
    {
        case check_eq:
            if (value1 == value2)
                return true;
            break;
        case check_neq:
            if (value1 != value2)
                return true;
            break;
        case check_lt:
            if (value1 < value2)
                return true;
            break;
        case check_gt:
            if (value1 > value2)
                return true;
            break;
        case check_and:
            if (value1 & value2)
                return true;
            break;
        case check_xor:
            if (value1 ^ value2)
                return true;
            break;
        case check_nand:
            if (!(value1 & value2))
                return true;
            break;
    }

    return false;
}

/* Check order of extension headers */
static bool IPv6_Check_Ext_Order(SFSnortPacket *p)
{
    u_int8_t order[] = {IPPROTO_HOPOPTS, IPPROTO_ROUTING, IPPROTO_FRAGMENT,
            IPPROTO_AH, IPPROTO_ESP, IPPROTO_DSTOPTS, IPPROTO_MOBILITY};
    u_short size = sizeof(order)/sizeof(u_int8_t);
    u_short i = 0, c = 0;

    while (i < p->num_ip6_extensions) {
        if (c >= size)
            return false; // i.e. option_type not found, not good
        else if (order[c] == IPPROTO_ROUTING
             && p->ip6_extensions[i].option_type == IPPROTO_DSTOPTS
             && p->ip6_extensions[i+1].option_type == IPPROTO_ROUTING) {
            // special case: a 2nd dst opt hdr may be in front of a routing hdr,
            c++; i++; i++;
        } else if (p->ip6_extensions[i].option_type == order[c]) { // option_type good
            c++; i++;
        } else { // order[c] not present, check next
            c++;
        }
    }
    return true;
}

/* Parsing for rule options */
static int IPv6_Rule_Init(char *name, char *params, void **data)
{
    struct IPv6_RuleOpt_Data *sdata;
    enum IPv6_RuleOpt_Type ruletype;
#ifdef DEBUG
    char *orig_params = params ? strdup(params) : "" ; // to preserve full option in **data
    char *orig_name = strdup(name);    // to preserve full name   in **data
#endif /* DEBUG */

    DEBUG_WRAP(DebugMessage(DEBUG_RULES, "IPv6_rule_init(\"%s\", \"%s\", ...)\n",
        orig_name, orig_params););

    if (!strcmp(name, "ipv"))
        ruletype = IPV6_RULETYPE_IPV;
    else if (!strcmp(name, "ip6_tclass"))
        ruletype = IPV6_RULETYPE_TRAFFICCLASS;
    else if (!strcmp(name, "ip6_flow"))
        ruletype = IPV6_RULETYPE_FLOWLABEL;
    else if (!strcmp(name, "ip6_exthdr"))
        ruletype = IPV6_RULETYPE_IP6EXTHDR;
    else if (!strcmp(name, "ip6_extnum"))
        ruletype = IPV6_RULETYPE_IP6EXTCOUNT;
    else if (!strcmp(name, "ip6_option"))
        ruletype = IPV6_RULETYPE_OPTION;
    else if (!strcmp(name, "ip6_optval"))
        ruletype = IPV6_RULETYPE_OPTVAL;
    else if (!strcmp(name, "ip6_rh"))
        ruletype = IPV6_RULETYPE_RH;
    else if (!strcmp(name, "ip6_ext_ordered"))
        ruletype = IPV6_RULETYPE_EXT_ORDERED;
    else if (!strcmp(name, "icmp6_nd"))
        ruletype = IPV6_RULETYPE_ND;
    else if (!strcmp(name, "icmp6_nd_option"))
        ruletype = IPV6_RULETYPE_ND_OPTION;
    else
        DynamicPreprocessorFatalMessage("%s(%d) => invalid keyword %s\n",
            *(_dpd.config_file), *(_dpd.config_line), name);

    sdata = (struct IPv6_RuleOpt_Data *)calloc(1, sizeof(*sdata));
    if (sdata == NULL)
        DynamicPreprocessorFatalMessage("Could not allocate memory for the "
                "%s preprocessor rule option.\n", name);
    sdata->type       = ruletype;
#ifdef DEBUG
    sdata->debugparam = strdup(orig_params);
    sdata->debugname  = strdup(orig_name);
#endif /* DEBUG */

    if (!params
    && ruletype != IPV6_RULETYPE_ND
    && ruletype != IPV6_RULETYPE_EXT_ORDERED) {
            DynamicPreprocessorFatalMessage("%s(%d) => keyword %s requires parameter\n",
                *(_dpd.config_file), *(_dpd.config_line), name);
    }

    switch(ruletype) {
    case IPV6_RULETYPE_EXT_ORDERED:     /* fallthrough */
    case IPV6_RULETYPE_ND:
        sdata->op = get_op(&params);
        // no numeric params, just ignore them if given
        break;
    case IPV6_RULETYPE_IPV:             /* fallthrough */
    case IPV6_RULETYPE_IP6EXTCOUNT:     /* fallthrough */
    case IPV6_RULETYPE_IP6EXTHDR:       /* fallthrough */
    case IPV6_RULETYPE_FLOWLABEL:       /* fallthrough */
    case IPV6_RULETYPE_TRAFFICCLASS:    /* fallthrough */
    case IPV6_RULETYPE_ND_OPTION:       /* fallthrough */
    case IPV6_RULETYPE_RH:
        sdata->op         = get_op(&params);
        sdata->opt.number = get_num(&params, name);
        break;
    case IPV6_RULETYPE_OPTION: {
        /* NB: the ip6_optval/IPV6_RULETYPE_OPTVAL was
         * split off to clarify the user documentation.
         *
         * Internally the three syntax variants are mapped
         * to three ruletypes, but the functional difference
         * is small and they share most code in IPv6_Rule_Eval().
         */
        /* syntax:
         * <op>Y   --> normal, test options for <op>Y
         * <op>X.Y --> test for <op>Y in ext./nd. type X
         */
        char *split;
        sdata->op = get_op(&params);                           // <op>
        split = strchr(params, '.');
        if (!split) {
            sdata->opt.exthdr.ext_type = 0;
            sdata->opt.exthdr.opt_type = get_num(&params, name);   // Y
        } else {
            sdata->type = IPV6_RULETYPE_OPTION_EXT;
            *split++ = '\0';
            sdata->opt.exthdr.ext_type = get_num(&params, name);   // X
            sdata->opt.exthdr.opt_type = get_num(&split, name);    // Y
        }
        break;
    }
    case IPV6_RULETYPE_OPTVAL: {
        /* syntax: X.Y<op>Z --> test for value Z<op>Y in ext. type X */
        char *split;
        char *op, *orig_op;
        u_int32_t tmp;

        split = strchr(params, '.');
        *split++ = '\0';
        op = strpbrk(split, " =!<>^&");

        sdata->opt.exthdr.ext_type = get_num(&params, name);   // X
        // have to remember the position for \0:
        orig_op = op;
        sdata->op = get_op(&op);                               // <op>
        *orig_op = '\0';
        sdata->opt.exthdr.opt_type = get_num(&split, name);    // Y
        
        // handle possibly larger Z values:
        tmp = get_num(&op, name);
        if (tmp > UINT16_MAX) {
            free(sdata);
            DynamicPreprocessorFatalMessage(
                "%s(%d) => keyword %s only supports 16-bit values\n",
                *(_dpd.config_file), *(_dpd.config_line), name, params);
        }
        sdata->opt.exthdr.opt_value = (u_int16_t) tmp;         // Z
        break;
    }
    default:
        free(sdata);
        DynamicPreprocessorFatalMessage("%s(%d) => invalid ruletype %s\n",
            *(_dpd.config_file), *(_dpd.config_line), name);
    }

    /* verify given modifiers */
    switch(ruletype) {
    case IPV6_RULETYPE_IP6EXTHDR:       /* fallthrough */
    case IPV6_RULETYPE_EXT_ORDERED:     /* fallthrough */
    case IPV6_RULETYPE_RH:              /* fallthrough */
    case IPV6_RULETYPE_ND:
        if (sdata->op != check_eq && sdata->op != check_neq)
            DynamicPreprocessorFatalMessage("%s(%d) => keyword %s "
                "only allows the operators '=' or '!'\n",
                *(_dpd.config_file), *(_dpd.config_line), name);
        break;
    case IPV6_RULETYPE_IP6EXTCOUNT:
        if (sdata->op != check_eq
         && sdata->op != check_neq
         && sdata->op != check_gt
         && sdata->op != check_lt)
            DynamicPreprocessorFatalMessage("%s(%d) => keyword %s "
                "only allows the operators '=', '!', '<', or '>'\n",
                *(_dpd.config_file), *(_dpd.config_line), name);
        break;
    default: // all modifiers OK
        break;
    }

    *data = (void *)sdata;
    DEBUG_WRAP(DebugMessage(DEBUG_RULES, " --> IPv6_rule_init returns data 0x%x\n", *data););
    return 1;
}

static u_int32_t IPv6_Rule_Hash(void *d)
{
    u_int32_t a,b,c;
    struct IPv6_RuleOpt_Data *sdata = (struct IPv6_RuleOpt_Data *)d;

    a = sdata->type;
    b = sdata->opt.number;
    c = sdata->op & PP_IPv6;

    final(a,b,c);
    return c;
}

static int IPv6_Rule_KeyCompare(void *l, void *r)
{
    struct IPv6_RuleOpt_Data *left = (struct IPv6_RuleOpt_Data *)l;
    struct IPv6_RuleOpt_Data *right = (struct IPv6_RuleOpt_Data *)r;

    if (left && right
        && left->type == right->type
        && left->op   == right->op
        && left->opt.number == right->opt.number) {
        DEBUG_WRAP(DebugMessage(DEBUG_RULES, "IPv6_Rule_KeyCompare(%x, %x) --> equal\n", l, r););
        return PREPROC_OPT_EQUAL;
    }

    DEBUG_WRAP(DebugMessage(DEBUG_RULES, "IPv6_Rule_KeyCompare(%x, %x) --> not equal\n", l, r););
    return PREPROC_OPT_NOT_EQUAL;
}

#define RETURN_MATCH do {                                                \
    DEBUG_WRAP(DebugMessage(DEBUG_RULES,                                \
        "IPv6_rule_eval on raw_packet at 0x%x\n\twith option %s: %s "    \
        "(internally: option %u, op %u, value 0x%04x)\n\tmatches\n",        \
        raw_packet, sdata->debugname, sdata->debugparam,                 \
        sdata->type, sdata->op, sdata->opt.number););                    \
    return RULE_MATCH;                                                   \
} while (0)
#define RETURN_NOMATCH do {                                              \
    DEBUG_WRAP(DebugMessage(DEBUG_RULES,                                \
        "IPv6_rule_eval on raw_packet at 0x%x\n\twith option %s: %s "    \
        "(internally: option %u, op %u, value 0x%04x)\n\tdoes not match\n", \
        raw_packet, sdata->debugname, sdata->debugparam,                 \
        sdata->type, sdata->op, sdata->opt.number););                    \
    return RULE_NOMATCH;                                                 \
} while (0)


/* Rule option evaluation */
static int IPv6_Rule_Eval(void *raw_packet, const u_int8_t **cursor __attribute__((unused)), void *data)
{
    SFSnortPacket *p = (SFSnortPacket*) raw_packet;
    struct IPv6_RuleOpt_Data *sdata = (struct IPv6_RuleOpt_Data *) data;
    DEBUG_WRAP(DebugMessage(DEBUG_RULES, "IPv6_Rule_Eval()\n"););

    if (!p || !sdata) {
        _dpd.errMsg("Error in IPv6_Rule_Eval(): missing packet or option data\n");
        return RULE_NOMATCH;
    }
    // small optimization: except ipv all rules match IPv6 only
    if (!p->ip6h && (sdata->type != IPV6_RULETYPE_IPV)) {
        return RULE_NOMATCH;
    }

    switch (sdata->type) {
    case IPV6_RULETYPE_IPV: {
        uint_fast8_t ipv = GET_IPH_VER(p);
        if (ipv != 6 && ipv != 4) {
            //_dpd.errMsg("buggy Snort version: ip6_ret_ver() uses wrong byte order\n");
            ipv = ntohl(p->ip6h->vcl) >> 28;
        }

        if (checkField(sdata->op, ipv, sdata->opt.number))
            RETURN_MATCH;
        else
            RETURN_NOMATCH;
    }
    case IPV6_RULETYPE_IP6EXTCOUNT:
        if (checkField(sdata->op, p->num_ip6_extensions, sdata->opt.number))
            RETURN_MATCH;
        else
            RETURN_NOMATCH;
    case IPV6_RULETYPE_FLOWLABEL:
        if (checkField(sdata->op, (ntohl(p->ip6h->vcl) & 0x000fffff), sdata->opt.number))
            RETURN_MATCH;
        else
            RETURN_NOMATCH;
    case IPV6_RULETYPE_TRAFFICCLASS: {
        uint_fast8_t tos;
        tos = (ntohl(p->ip6h->vcl) & 0x0ff00000) >> 20;
        if (checkField(sdata->op, tos, sdata->opt.number))
            RETURN_MATCH;
        else
            RETURN_NOMATCH;
    }
    case IPV6_RULETYPE_EXT_ORDERED: {
        bool rc = IPv6_Check_Ext_Order(p);
        if ((rc && sdata->op == check_eq)
        || (!rc && sdata->op == check_neq))
            RETURN_MATCH;
        else
            RETURN_NOMATCH;
    }
    case IPV6_RULETYPE_IP6EXTHDR: {
        uint_fast8_t i;

        for (i = 0; i < p->num_ip6_extensions; i++)
            if (p->ip6_extensions[i].option_type == sdata->opt.number) {
                if (sdata->op == check_eq)  RETURN_MATCH;
                if (sdata->op == check_neq) RETURN_NOMATCH;
            }
        if (sdata->op == check_neq) RETURN_MATCH;
        break;
    }
    case IPV6_RULETYPE_RH: {
        uint_fast8_t i;

        for (i = 0; i < p->num_ip6_extensions; i++)
            if (p->ip6_extensions[i].option_type == IPPROTO_ROUTING) {
                struct ip6_rthdr *rt_hdr = (struct ip6_rthdr *)
                    p->ip6_extensions[i].option_data;
                if (rt_hdr->ip6r_type == sdata->opt.number) {
                    if (sdata->op == check_eq)  RETURN_MATCH;
                    if (sdata->op == check_neq) RETURN_NOMATCH;
                }
            }
        if (sdata->op == check_neq) RETURN_MATCH;
        break;
    }
    case IPV6_RULETYPE_ND:
        if (!p->icmp_header) {
            // no ICMPv6 or a type that may not contain rule options
            if (sdata->op == check_neq) RETURN_MATCH;
            else                        RETURN_NOMATCH;
        }
        switch (p->icmp_header->type) {
        case ICMP6_SOLICITATION:      /* fallthrough */
        case ICMP6_ADVERTISEMENT:     /* fallthrough */
        case ICMP6_N_SOLICITATION:    /* fallthrough */
        case ICMP6_N_ADVERTISEMENT:   /* fallthrough */
        case ICMP6_REDIRECT:          /* fallthrough */
        case ICMP6_INV_SOLICITATION:  /* fallthrough */
        case ICMP6_INV_ADVERTISEMENT: /* fallthrough */
        case ICMP6_HOME_AD_REQUEST:   /* fallthrough */
        case ICMP6_HOME_AD_REPLY:     /* fallthrough */
        case ICMP6_MOBILEPREFIX_SOL:  /* fallthrough */
        case ICMP6_MOBILEPREFIX_ADV:  /* fallthrough */
        case ICMP6_CRT_SOLICITATION:  /* fallthrough */
        case ICMP6_CRT_ADVERTISEMENT: /* fallthrough */
        case ICMP6_MOBILE_FH:
            if (sdata->op == check_eq)
                RETURN_MATCH;
            else
                RETURN_NOMATCH;
        default:
            if (sdata->op == check_neq)
                RETURN_MATCH;
            else
                RETURN_NOMATCH;
        }
    case IPV6_RULETYPE_ND_OPTION: {
        if (!p->icmp_header || !ND_hdrlen[p->icmp_header->type]) {
            // no ICMPv6 or a type that may not contain rule options
            if (sdata->op == check_neq) RETURN_MATCH;
            else                        RETURN_NOMATCH;
        } else {
            uint_fast8_t icmp_hdr_len = ND_hdrlen[p->icmp_header->type];
            uint_fast16_t len  = p->ip_payload_size - icmp_hdr_len;
            struct nd_opt_hdr *option = (struct nd_opt_hdr *) (p->ip_payload + icmp_hdr_len);
            while (len) {
                uint_fast8_t optlen = 8 * (option->nd_opt_len);
                bool rc = checkField(sdata->op, option->nd_opt_type, sdata->opt.number);
                if ( rc && sdata->op != check_neq) RETURN_MATCH;
                if (!rc && sdata->op == check_neq) RETURN_NOMATCH;
                if (optlen > len) {
                    _dpd.logMsg("IPv6 decoder problem. malformed ND option lenghts.\n");
                    break;
                }
                len -= optlen;
                option = (struct nd_opt_hdr *) ((char *)option + optlen);
            }
            if (sdata->op == check_neq) RETURN_MATCH;
            else                        RETURN_NOMATCH;
        }
    }
    case IPV6_RULETYPE_OPTVAL:     /* fallthrough */
    case IPV6_RULETYPE_OPTION:     /* fallthrough */
    case IPV6_RULETYPE_OPTION_EXT: {
        uint_fast8_t i;

        for (i = 0; i < p->num_ip6_extensions; i++) {
            if (p->ip6_extensions[i].option_type != IPPROTO_HOPOPTS
                && p->ip6_extensions[i].option_type != IPPROTO_DSTOPTS)
                continue;
            if ((sdata->type == IPV6_RULETYPE_OPTION_EXT
                || sdata->type == IPV6_RULETYPE_OPTVAL)
                && p->ip6_extensions[i].option_type != sdata->opt.exthdr.ext_type)
                continue;

            {
            /* hbh_hdr   is the Ext Hdr with type and length
             * hbh_hdr+1 is the first option with type and length
             * cursor    iterates over the options
             */
            struct ip6_hbh *hbh_hdr = (struct ip6_hbh*) p->ip6_extensions[i].option_data;
            u_int16_t ext_len = (hbh_hdr->ip6h_len + 1) << 3;
            u_int8_t *cursor  = (u_int8_t *) (hbh_hdr+1);
            u_int8_t *ext_end = ((u_int8_t *) hbh_hdr) + ext_len;

            while (cursor < ext_end) {
                struct ip6_opt *opt = (struct ip6_opt*) cursor;

                DEBUG_WRAP(DebugMessage(DEBUG_RULES,
                        "checkOpt(type %u, len %u at 0x%04x)\n",
                        opt->ip6o_type, opt->ip6o_len, opt););

                // NB: ext_type already checked in outer loop
                if (sdata->type == IPV6_RULETYPE_OPTION
                 || sdata->type == IPV6_RULETYPE_OPTION_EXT) {
                    bool rc = checkField(sdata->op, opt->ip6o_type, sdata->opt.exthdr.opt_type);
                    DEBUG_WRAP(DebugMessage(DEBUG_RULES,
                        "checkField(%u, 0x%04x, 0x%04x) = %s\n",
                        sdata->op, opt->ip6o_type, sdata->opt.exthdr.opt_type,
                        (rc ? "match" : "fail")););
                    if ( rc && sdata->op != check_neq) RETURN_MATCH;
                    if (!rc && sdata->op == check_neq) RETURN_NOMATCH;
                } else if (sdata->type == IPV6_RULETYPE_OPTVAL
                    && opt->ip6o_type == sdata->opt.exthdr.opt_type) {
                        u_int16_t *ptr = (u_int16_t*) opt;
                        u_int16_t val = ntohs(*(ptr+1));
                        bool rc = checkField(sdata->op, val, sdata->opt.exthdr.opt_value);
                        if ( rc && sdata->op != check_neq) RETURN_MATCH;
                        if (!rc && sdata->op == check_neq) RETURN_NOMATCH;
                }

                cursor += (opt->ip6o_type == 0) ? 1    // Pad1 is special
                    : (2+opt->ip6o_len);
            }
            }
        }
        if (sdata->op == check_neq) RETURN_MATCH;
        else                        RETURN_NOMATCH;
        break;
    }
    }
    RETURN_NOMATCH;
}
