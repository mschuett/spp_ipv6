/*
 * spp_ipv6_data_common.h
 *
 * Copyright (C) 2012 Martin Schuette <info@mschuette.name>
 *
 * Common types and macros for all data structure code.
 *
 */

#ifndef SPP_IPV6_DATA_COMMON_H
#define	SPP_IPV6_DATA_COMMON_H

/* return values for data operations -- set to match sfxhash codes */
typedef enum _data_op_return_values {
    DATA_NOMEM   = SFXHASH_NOMEM,     // memory error, e.g. malloc() failed
    DATA_ERROR   = SFXHASH_ERR,       // other error
    DATA_ADDED   = SFXHASH_OK,        // entry added
    DATA_EXISTS  = SFXHASH_INTABLE,   // entry already exists, no change
    DATA_UPDATED,                     // entry updatet (e.g. new timestamp)
} DATAOP_RET;
// some sanity checks
#if DATA_ADDED != 0
#error Strange value for SFXHASH_OK
#endif /* DATA_ADDED != 0 */
#if SFXHASH_ERR >= 0
#error Strange value for SFXHASH_ERR
#endif /* SFXHASH_ERR >= 0 */


// some hashes store only keys, so this constant is used as a data ptr
#define HASHMARK ((void*)0xdead)


#endif	/* SPP_IPV6_DATA_COMMON_H */
