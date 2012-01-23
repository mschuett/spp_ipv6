/*
 * spp_ipv6_parse.c
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
 * Description:
 *  Function to parse configuration options in snort.conf
 *
 */

#include "spp_ipv6.h"

/**
 * Parse the configuration options in snort.conf
 *
 * Currently supported options: router_mac, host_mac, net_prefix
 */
void set_default_config(struct IPv6_Config *config)
{
    config->track_ndp = true;
    // for testing: 1h, later: 2-12h
    config->keep_state_duration = 60*60;
    config->expire_run_interval = 20*60;
    // not sure if these are realistic, should be high enough
    config->max_routers     = 32;
    config->max_hosts       = 8192;
    config->max_unconfirmed = 32768;

    return;
}

#define BIN_OPTION(X, Y) if (!strcasecmp(X, arg)) {         \
                             (Y) = false;                   \
                             _dpd.logMsg("  " X "\n");      \
                             arg = strtok(NULL, " \t\n\r"); \
                         }

inline void read_num(char **arg, const char *param, u_int32_t *configptr)
{
    uint_fast32_t minutes;
    *arg = strtok(NULL, " \t\n\r");
    minutes = (uint_fast32_t) strtoul(*arg, NULL, 10);
    if (errno) {
        _dpd.fatalMsg("  Invalid parameter to %s\n", param);
    }
    *configptr = 60 * minutes;
    _dpd.logMsg("  %s = %u minutes = %u secs\n",
                param, minutes, *configptr);
    *arg = strtok(NULL, " \t\n\r");
}

void IPv6_Parse(char *args, struct IPv6_Config *config)
{
    char *arg;
    char ismac;
    sfip_t *prefix;
    SFIP_RET rc;

    set_default_config(config);
    _dpd.logMsg("IPv6 preprocessor config:\n");
    if (!args) {
        _dpd.logMsg("\tno additional parameters\n");
        return;
    }

    arg = strtok(args, " \t\n\r");
    while (arg) {
        if(!strcasecmp("router_mac", arg)) { // and now a list of 0-n router MACs
            config->report_new_routers = true;
            while ((arg = strtok(NULL, ", \t\n\r")) && (ismac = IS_MAC(arg))) {
                mac_add(config->router_whitelist, arg);
                _dpd.logMsg("  default router MAC %s\n", arg);
            }
        } else if(!strcasecmp("host_mac", arg)) { // and now a list of 0-n host MACs
            config->report_new_hosts = true;
            while ((arg = strtok(NULL, ", \t\n\r")) && (ismac = IS_MAC(arg))) {
                mac_add(config->host_whitelist, arg);
                _dpd.logMsg("  default host MAC %s\n", arg);
            }
        } else if(!strcasecmp("net_prefix", arg)) { // and now a list of 0-n prefixes
            config->report_prefix_change = true;
            while ((arg = strtok(NULL, ", \t\n\r")) && strchr(arg, '/')) {  // TODO remove /-check
                prefix = sfip_alloc(arg, &rc);
                if (rc == SFIP_SUCCESS) {
                    add_ip(config->prefix_whitelist, prefix);
                    _dpd.logMsg("  default net prefix %s/%d\n",
                        sfip_to_str(prefix), sfip_bits(prefix));
                } else {
                    _dpd.fatalMsg("  Invalid prefix %s\n", arg);
                }
            }
        } else if(!strcasecmp("max_routers", arg)) {
            read_num(&arg, "max_routers", &(config->max_routers));
        } else if(!strcasecmp("max_hosts", arg)) {
            read_num(&arg, "max_hosts", &(config->max_hosts));
        } else if(!strcasecmp("max_unconfirmed", arg)) {
            read_num(&arg, "max_unconfirmed", &(config->max_unconfirmed));
        } else if(!strcasecmp("keep_state", arg)) {
            read_num(&arg, "keep_state", &(config->keep_state_duration));
        } else if(!strcasecmp("expire_run", arg)) {
            read_num(&arg, "expire_run", &(config->expire_run_interval));
        } else BIN_OPTION("disable_tracking", config->track_ndp)
          else {
            _dpd.fatalMsg("IPv6: Invalid option %s\n", arg);
        }
    }
}

