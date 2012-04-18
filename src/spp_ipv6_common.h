/*
 * spp_ipv6.h
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
 */

#ifndef _SPP_IPV6_COMMON_H
#define	_SPP_IPV6_COMMON_H

/**********************************************************************
 ** Includes                                                         **
 **********************************************************************/
#include "../include/sf_types.h"
#include <time.h>
#include <sys/time.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <sys/queue.h>
#include <errno.h>

#ifdef __linux__
#ifndef __unused
#define __unused __attribute__((__unused__)) 
#endif /* __unused */
#include "tree.h"
#else /* BSD */
#include <sys/tree.h>
#endif /* __linux__  */

#include "preprocids.h"
#include "sf_snort_packet.h"
#include "sf_dynamic_preproc_lib.h"
#include "sf_dynamic_preprocessor.h"
#include "snort_debug.h"
#include "sfPolicy.h"
#include "sfPolicyUserData.h"
/* for ICMPv6 format */
#include <netinet/icmp6.h>
#include <netinet/ip6.h>
#include <netinet/in.h>

#include "spp_ipv6_constants.h"
#include "spp_ipv6_data_structs.h"

/* verify string contains a MAC address */
#define IS_MAC(string) ((string) != NULL                                     \
  && isxdigit((string)[ 0]) && isxdigit((string)[ 1]) && (string)[ 2] == ':' \
  && isxdigit((string)[ 3]) && isxdigit((string)[ 4]) && (string)[ 5] == ':' \
  && isxdigit((string)[ 6]) && isxdigit((string)[ 7]) && (string)[ 8] == ':' \
  && isxdigit((string)[ 9]) && isxdigit((string)[10]) && (string)[11] == ':' \
  && isxdigit((string)[12]) && isxdigit((string)[13]) && (string)[14] == ':' \
  && isxdigit((string)[15]) && isxdigit((string)[16]) && (string)[17] == '\0')


/**********************************************************************
 ** Function Prototypes                                              **
 **********************************************************************/

#endif	/* _SPP_IPV6_COMMON_H */
