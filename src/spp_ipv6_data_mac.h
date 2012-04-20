/*
 * spp_ipv6_data_mac.h
 *
 * Copyright (C) 2012 Martin Schuette <info@mschuette.name>
 *
 * Data structures and functions to store a plain list of MAC addresses.
 * Currently a wrapper arround Snort's sfxhash.
 *
 */

#ifndef SPP_IPV6_DATA_MAC_H
#define	SPP_IPV6_DATA_MAC_H

#include <time.h>
#include <sys/time.h>
#include "sf_types.h"
#include "sfxhash.h"
#include "snort_debug.h"
#include "spp_ipv6_constants.h"
#include "spp_ipv6_data_common.h"

// useful for memcpy calls
#define MAC_LENGTH (6*sizeof(u_int8_t))

/* verify string contains a MAC address */
#define IS_MAC(string) ((string) != NULL                                     \
  && isxdigit((string)[ 0]) && isxdigit((string)[ 1]) && (string)[ 2] == ':' \
  && isxdigit((string)[ 3]) && isxdigit((string)[ 4]) && (string)[ 5] == ':' \
  && isxdigit((string)[ 6]) && isxdigit((string)[ 7]) && (string)[ 8] == ':' \
  && isxdigit((string)[ 9]) && isxdigit((string)[10]) && (string)[11] == ':' \
  && isxdigit((string)[12]) && isxdigit((string)[13]) && (string)[14] == ':' \
  && isxdigit((string)[15]) && isxdigit((string)[16]) && (string)[17] == '\0')

typedef struct _MAC_node {
    u_int8_t mac[6];
} MAC_node;

/* _very_ thin abstraction layer */
typedef SFXHASH MAC_set;
/* it would be nice to benchmark these options some time */
#define MACSET_SPLAY   0
#define MACSET_RECYCLE 1

int        mac_cmp(MAC_node *a, MAC_node *b);
MAC_node  *mac_parse(const char* string, MAC_node *m);
char      *mac_pprint(const MAC_node *m);
MAC_set   *macset_create(int count, int maxcount, int memsize);
DATAOP_RET macset_add(MAC_set *s, MAC_node *m);
DATAOP_RET macset_addstring(MAC_set *s, const char *mac);
bool       macset_contains(MAC_set *s, MAC_node *m);

#endif	/* SPP_IPV6_DATA_MAC_H */
