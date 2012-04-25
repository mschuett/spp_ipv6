/*
 * spp_ipv6_data_time.c
 *
 * Copyright (C) 2011 Martin Schuette <info@mschuette.name>
 *
 * Aux. function(s) for timestamps.
 */

#ifndef SPP_IPV6_DATA_TIME_H
#define	SPP_IPV6_DATA_TIME_H

#include <time.h>
#include <stdio.h>
#include "spp_ipv6_data_time.h"

/**
 * Aux. function to format timestamp (in static buffer).
 */
char *ts_str(const time_t ts)
{
    struct tm *printtm;
    static char buf[64];

    if (ts) {
        printtm = localtime(&ts);
        strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", printtm);
    } else {
        sprintf(buf, "unknown");
    }

    return buf;
}

#endif	/* SPP_IPV6_DATA_TIME_H */
