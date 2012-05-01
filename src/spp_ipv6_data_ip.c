/*
 * spp_ipv6_data_ip.c
 *
 * Copyright (C) 2012 Martin Schuette <info@mschuette.name>
 *
 * Data structures and functions to store a plain list of IP addresses.
 *
 * A later optimization may replace some functions by macros, but during
 * development I keep them for better debugging, testing, and type checking.
 *
 */

#include "spp_ipv6_data_mac.h"
#include "spp_ipv6_data_ip.h"
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>

#include "sf_dynamic_preprocessor.h"
extern DynamicPreprocessorData _dpd;

/**
 * Compare IP addesses for equality
 */
bool ip_eq(const IP_t *a, const IP_t *b)
{
    return (SFIP_EQUAL == sfip_compare((sfip_t *) a, (sfip_t *) b));
}

/**
 * Compare IP addesses with memcmp return value.
 */
int ip_cmp(const IP_t *a, const IP_t *b)
{
    SFIP_RET rc;
    rc = sfip_compare((sfip_t *) a, (sfip_t *) b);
    switch (rc) {
        case SFIP_LESSER:  return -1;
        case SFIP_EQUAL:   return 0;
        case SFIP_GREATER: return 1;
        default:           return -2; // useful value here?
    }
}

/**
 * Copy IP address
 */
void ip_cpy(IP_t *dst, const IP_t *src)
{
    sfip_set_ip(dst, src);
}

/**
 * Duplicate IP address (including malloc())
 */
IP_t *ip_dup(const IP_t *src)
{
    IP_t *dst;
    dst = malloc(sizeof(IP_t));
    sfip_set_ip(dst, src);
    printf("ip_dup: %p --> %p\n", src, dst);
    return dst;
}


/**
 * Parse a string IP into binary data
 * no input and little output checking, arguments have to be valid
 * 
 * IP_node parameter is optional, if NULL then the static buffer is used.
 */
IP_t *ip_parse(IP_t *dst, const char* string)
{
    static IP_t node;
    SFIP_RET status;

    if (!dst)
        dst = &node;
    status = sfip_pton(string, dst);

    if (status != SFIP_SUCCESS)
        dst = NULL;
    return dst;
}

/**
 * Make IP_t from sfip_t.
 * IP_t parameter is optional, if NULL then the static buffer is used.
 * 
 */
IP_t *ip_set(IP_t *dst, const sfip_t *src)
{
    static IP_t node;
    SFIP_RET status;

    if (!dst)
        dst = &node;
    status = sfip_set_ip(dst, src);

    if (status != SFIP_SUCCESS)
        dst = NULL;
    return dst;
}

/**
 * Check if IP is a network/prefix.
 */
#define ip_isprefix(m) !( \
           ((sfip_family(m) == AF_INET6) && (sfip_bits((sfip_t*)m) == 128)) \
        || ((sfip_family(m) == AF_INET)  && (sfip_bits((sfip_t*)m) ==  32)) \
)

/**
 * Aux. function to format IP address (in static buffer).
 */
char *ip_str(const IP_t *m)
{
    if (ip_isprefix(m)) {
        static char buf[IP_STR_BUFLEN];
        snprintf(buf, sizeof(buf), "%s/%d",
                sfip_to_str(m), sfip_bits((sfip_t*) m));
        return buf;
    }
    else 
        return sfip_to_str(m);
}

/**
 * Aux. function to print all IP addresses in set.
 */
void ipset_print_all(IP_set *s, const char *title)
{
    IP_t *ip;
    SFGHASH_NODE *n;

    _dpd.logMsg("IP set '%s' with %d entries:\n", title, ipset_count(s));
    n = sfghash_findfirst(s);
    while (n) {
        ip = n->key;
        _dpd.logMsg("%s\n", ip_str(ip));
        n = sfghash_findnext(s);
    }
}

/**
 * alloc and create IPset.
 */
IP_set *ipset_create(int count)
{
    IP_set *s;
    if (!count) // set default
        count = 20;
    s = sfghash_new(count, sizeof(IP_t), 0, ipset_dad_userfree);
    return s;
}

/**
 * Delete and free IPset.
 */
void ipset_delete(IP_set *s)
{
    sfghash_delete(s);
}

/**
 * Free IPset entries, here either HASHMARKs or MAC_sets.
 */
void ipset_dad_userfree(void *p)
{
    if (p && p != HASHMARK)
        macset_delete(p);
}

/**
 * Add IP_node to a set.
 */
DATAOP_RET ipset_add(IP_set *s, const IP_t *m)
{
    return sfghash_add(s, (IP_t *) m, HASHMARK);
}

/**
 * Add IP_node to a set.
 */
DATAOP_RET ipset_add_data(IP_set *s, const IP_t *m, const void *data)
{
    return sfghash_add(s, (IP_t *) m, (void *) data);
}

/**
 * Add string IP to a set.
 */
DATAOP_RET ipset_addstring(IP_set *s, const char *ipstr)
{
    IP_t *m;
    m = ip_parse(NULL, ipstr);
    return sfghash_add(s, m, HASHMARK);
}

/**
 * check if set contains IP
 */
bool ipset_contains(IP_set *s, const IP_t *m)
{
    return (NULL != sfghash_find(s, (IP_t *) m));
}

/**
 * check if set contains IP
 */
void *ipset_get(IP_set *s, const IP_t *m)
{
    return sfghash_find(s, (IP_t *) m);
}

/**
 * remove IP from set
 */
int ipset_remove(IP_set *s, const IP_t *m)
{
    return sfghash_remove(s, (IP_t *) m);
}

bool ipset_empty(IP_set *s)
{
    return (ipset_count(s) == 0);
}

int ipset_count(IP_set *s)
{
    return sfghash_count(s);
}
