/*
 * spp_ipv6_data_time.h
 *
 * Copyright (C) 2011 Martin Schuette <info@mschuette.name>
 *
 * Aux. function(s) for timestamps.
 */

#ifndef SPP_IPV6_DATA_TIME_H
#define	SPP_IPV6_DATA_TIME_H

#include <time.h>

#define ts_from_pkt(p) (p->pkt_header->ts.tv_sec)
char *ts_str(const time_t ts);

#endif	/* SPP_IPV6_DATA_TIME_H */

