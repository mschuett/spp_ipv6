/*
 * spp_ipv6_data_ip.h
 *
 * Copyright (C) 2012 Martin Schuette <info@mschuette.name>
 *
 * Data structures and functions to store a plain list of IP addresses.
 * Currently a wrapper arround Snort's sfghash -- which does not meet the
 * requirement to store network prefixes and check against them.
 * 
 * TODO: use a tree.
 *
 */

#ifndef SPP_IPV6_DATA_IP_H
#define	SPP_IPV6_DATA_IP_H

#include <time.h>
#include <sys/time.h>
#include "sf_types.h"
#include "sf_ip.h"
#include "sfxhash.h"
#include "snort_debug.h"
#include "spp_ipv6_data_common.h"

/* _very_ thin abstraction layers */
typedef sfip_t  IP_t;
typedef SFXHASH IP_set;
/* it would be nice to benchmark these options some time */
#define IPSET_SPLAY   0
#define IPSET_RECYCLE 1

// length of string representation of IP and prefix
#define IP_STR_BUFLEN (INET6_ADDRSTRLEN+5)

// just for readability and to make future changes easier
#define ip_from_sfip(i) ((IP_t *) i)

bool       ip_eq(const IP_t *a, const IP_t *b);
int        ip_cmp(const IP_t *a, const IP_t *b);
void       ip_cpy(IP_t *dst, const IP_t *src);
IP_t      *ip_dup(const IP_t *src);
IP_t      *ip_parse(IP_t *dst, const char* string);
IP_t      *ip_set(IP_t *dst, const sfip_t *src);
char      *ip_str(const IP_t *m);
void       ipset_print_all(IP_set *s);
IP_set    *ipset_create(int count, int maxcount, int memsize);
void       ipset_delete(IP_set *s);
DATAOP_RET ipset_add(IP_set *s, const IP_t *m);
DATAOP_RET ipset_addstring(IP_set *s, const char *ipstr);
bool       ipset_contains(IP_set *s, const IP_t *m);
int        ipset_remove(IP_set *s, const IP_t *m);
bool       ipset_empty(IP_set *s);
int        ipset_count(IP_set *s);

#endif	/* SPP_IPV6_DATA_IP_H */
