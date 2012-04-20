/*
 * spp_ipv6_data_ip.h
 *
 * Copyright (C) 2012 Martin Schuette <info@mschuette.name>
 *
 * Data structures and functions to store a plain list of IP addresses.
 * Currently a wrapper arround Snort's sfghash.
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
#include "spp_ipv6_constants.h"
#include "spp_ipv6_data_common.h"

/* _very_ thin abstraction layers */
typedef sfip_t  IP_node;
typedef SFXHASH IP_set;
/* it would be nice to benchmark these options some time */
#define IPSET_SPLAY   0
#define IPSET_RECYCLE 1

int        ip_cmp(IP_node *a, IP_node *b);
IP_node   *ip_parse(const char* string, IP_node *m);
char      *ip_pprint(const IP_node *m);
IP_set    *ipset_create(int count, int maxcount, int memsize);
DATAOP_RET ipset_add(IP_set *s, IP_node *m);
DATAOP_RET ipset_addstring(IP_set *s, const char *mac);
bool       ipset_contains(IP_set *s, IP_node *m);

#endif	/* SPP_IPV6_DATA_IP_H */
