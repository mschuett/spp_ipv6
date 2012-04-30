/*
 * spp_ipv6_data_host.h
 *
 * Copyright (C) 2012 Martin Schuette <info@mschuette.name>
 *
 * Data structures and functions to store seen hosts, where hosts
 * are defined by their combination of HOST and IP address.
 * Currently a wrapper arround Snort's sfxhash.
 *
 */

#ifndef SPP_IPV6_DATA_HOST_H
#define	SPP_IPV6_DATA_HOST_H

#include <time.h>
#include <sys/time.h>
#include "sf_types.h"
#include "sfxhash.h"
#include "snort_debug.h"
#include "spp_ipv6_data_common.h"
#include "spp_ipv6_data_ip.h"
#include "spp_ipv6_data_mac.h"
#include "spp_ipv6_data_time.h"

typedef struct _HOST_t {
    // common data for all hosts
    MAC_t  mac;
    IP_t   ip;
    time_t last_adv_ts;
    // extra data for routers/DAD detection
    union {
        struct {
            IP_t *prefix;
            u_int16_t lifetime;
            union {
                u_int8_t m:1,
                         o:1,
                         h:1,
                       prf:2;
                u_int8_t all;
            } flags;
        } router;
        struct {
            IP_t *noprefix;      // FIXME: currently only non-NULL in this field indicates a router entry
            u_int32_t contacted; // count if any 2nd host sends request
        } dad;
    } type;    
} HOST_t;

/* _very_ thin abstraction layer */
typedef SFXHASH HOST_set;

/* it would be nice to benchmark these options some time */
#define HOSTSET_SPLAY   0
#define HOSTSET_RECYCLE 1
// length of string representation
#define TS_STR_BUFLEN 20
#define ROUTER_STR_BUFLEN IP_STR_BUFLEN + 60
#define HOST_STR_BUFLEN (IP_STR_BUFLEN + MAC_STR_BUFLEN + 20 + TS_STR_BUFLEN + ROUTER_STR_BUFLEN)

// for debugging/assertions
#define MAGICMARKER 0xabcd1234

/* The handling of DAD events needs to index its data set by IP address only.
 * To implement this with the same data structures, the 'unconfirmed' set
 * always uses this 'ff:ff:ff:ff:ff:ff' MAC address.  */
#define DAD_MAC ((MAC_t) {.mac = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}})
//#define host_dad_set(h, i, t) host_set(h, &DAD_MAC, i, t)

bool       host_eq(const HOST_t *a, const HOST_t *b);
char      *host_str(const HOST_t *h);
HOST_t    *host_set(HOST_t *h, const MAC_t *m, const IP_t *i, time_t t);
void       host_setrouterdata(HOST_t *h, u_int8_t ra_flags, u_int16_t ra_lifetime, sfip_t* prefix);
void       host_free(HOST_t *h);
HOST_set  *hostset_create(int count, int maxcount, int memsize);
void       hostset_delete(HOST_set *s);
DATAOP_RET hostset_add(HOST_set *s, const HOST_t *h);
HOST_t    *hostset_get(HOST_set *s, const HOST_t *h);
HOST_t    *hostset_get_by_ipmac(HOST_set *s, const MAC_t *m, const IP_t *i);
bool       hostset_contains(HOST_set *s, const HOST_t *h, time_t update_ts);
int        hostset_remove(HOST_set *s, const HOST_t *h);
void       hostset_print_all(HOST_set *s);
int        hostset_count(HOST_set *s);
bool       hostset_empty(HOST_set *s);
int        hostset_userfree(void *key, void *data);

static inline HOST_t *host_dad_set(HOST_t *h, const IP_t *i, time_t t)
{
    return host_set(h, &DAD_MAC, i, t);
}

#endif	/* SPP_IPV6_DATA_HOST_H */
