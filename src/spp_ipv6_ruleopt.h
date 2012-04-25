/*
 * spp_ipv6_ruleopt.h
 *
 * Copyright (C) 2012 Martin Schuette <info@mschuette.name>
 *
 */

#ifndef SPP_IPV6_RULEOPT_H
#define	SPP_IPV6_RULEOPT_H

#include "spp_ipv6_common.h"
#include "spp_ipv6_data_structs.h"
// for rule option:
#include "sf_snort_plugin_api.h"
// for IPv6_Rule_Hash
#include "sfhashfcn.h"

/*
 * Return values for the rule option comparison operations.
 */
enum cmp_op {
    check_eq=0, check_neq,
    check_lt, check_gt,
    check_and, check_xor, check_nand
};

/*
 * for Rule Options
 */
enum IPv6_RuleOpt_Type {
    IPV6_RULETYPE_IPV,
    IPV6_RULETYPE_IP6EXTHDR,
    IPV6_RULETYPE_IP6EXTCOUNT,
    IPV6_RULETYPE_FLOWLABEL,
    IPV6_RULETYPE_TRAFFICCLASS,
    IPV6_RULETYPE_OPTION,
    IPV6_RULETYPE_OPTION_EXT,
    IPV6_RULETYPE_OPTVAL,
    IPV6_RULETYPE_ND,
    IPV6_RULETYPE_ND_OPTION,
    IPV6_RULETYPE_RH,
    IPV6_RULETYPE_EXT_ORDERED
};

struct IPv6_RuleOpt_Data {
#ifdef DEBUG
    char *debugname;
    char *debugparam;
#endif /* DEBUG */
    enum IPv6_RuleOpt_Type type:4;
    int op:4;
    union {
            u_int32_t number;
            struct { // for ip6_optval
                u_int8_t  ext_type;
                u_int8_t  opt_type;
                u_int16_t opt_value;
            } exthdr;
    } opt;
} __attribute__((packed));

int IPv6_Rule_Init(char *, char *, void **);
int IPv6_Rule_Eval(void *, const u_int8_t **, void *);
u_int32_t IPv6_Rule_Hash(void *);
int IPv6_Rule_KeyCompare(void *, void *);

#endif	/* SPP_IPV6_RULEOPT_H */

