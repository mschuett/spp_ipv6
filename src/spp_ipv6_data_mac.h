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
#include "sfghash.h"
#include "snort_debug.h"
#include "spp_ipv6_data_common.h"

/* verify string contains a MAC address */
#define IS_MAC(string) ((string) != NULL                                     \
  && isxdigit((string)[ 0]) && isxdigit((string)[ 1]) && (string)[ 2] == ':' \
  && isxdigit((string)[ 3]) && isxdigit((string)[ 4]) && (string)[ 5] == ':' \
  && isxdigit((string)[ 6]) && isxdigit((string)[ 7]) && (string)[ 8] == ':' \
  && isxdigit((string)[ 9]) && isxdigit((string)[10]) && (string)[11] == ':' \
  && isxdigit((string)[12]) && isxdigit((string)[13]) && (string)[14] == ':' \
  && isxdigit((string)[15]) && isxdigit((string)[16]) && (string)[17] == '\0')

typedef struct _MAC_t {
    u_int8_t mac[6];
} MAC_t;

/* _very_ thin abstraction layer */
typedef SFGHASH MAC_set;

// length of string representation
#define MAC_STR_BUFLEN 18

// useful for memcpy calls
#define MAC_LENGTH (6*sizeof(u_int8_t))

// just for readability and to make future changes easier
#define mac_from_pkt(p) ((MAC_t *) &(p->ether_header->ether_source))

bool       mac_eq(const MAC_t *a, const MAC_t *b);
int        mac_cmp(const MAC_t *a, const MAC_t *b);
void       mac_cpy(MAC_t *dst, const MAC_t *src);
MAC_t     *mac_parse(MAC_t *m, const char* string);
char      *mac_str(const MAC_t *m);
MAC_t     *mac_set(MAC_t *m, const u_int8_t ether_source[]);
MAC_set   *macset_create(int count);
void       macset_delete(MAC_set *s);
void       macset_dad_userfree(void *p);
DATAOP_RET macset_add(MAC_set *s, const MAC_t *m);
DATAOP_RET macset_addstring(MAC_set *s, const char *mac);
DATAOP_RET macset_add_host(MAC_set *s, const void *h);
DATAOP_RET macset_remove(MAC_set *s, const MAC_t *m);
bool       macset_contains(MAC_set *s, const MAC_t *m);
void      *macset_get(MAC_set *s, const MAC_t *m);
bool       macset_empty(MAC_set *s);
int        macset_count(MAC_set *s);

#endif	/* SPP_IPV6_DATA_MAC_H */
