/* 
 * File:   test_data_structs.c
 * Author: mschuett
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <assert.h>

// stub for util.c
// SnortAlloc will probably crash on access (in case of errors), but good enough for a test tool
#include "sf_types.h"
#include "sf_dynamic_preprocessor.h"
DynamicPreprocessorData _dpd;

int init_plugin_deps(void) {
    _dpd.logMsg   = &LogMessage;
    _dpd.fatalMsg = &LogMessage;
    return 0;
}

#include "spp_ipv6_data_mac.h"
#include "spp_ipv6_data_ip.h"
#include "spp_ipv6_data_host.h"

// some random values for testing. macdata has to be NULL terminated
// and have less or equal length than ipdata.
char *macdata[] = {
    "ec:ac:24:70:4c:f6",
    "38:45:63:f6:8e:83",
    "f7:d5:9c:38:8f:db",
    "bf:de:9e:0e:6e:eb",
    "b6:f5:bf:ff:c2:32",
    "83:23:3d:f2:17:31",
    "26:3e:f2:4e:0d:ff",
    "d4:fc:84:dc:81:a9",
    "39:9f:2c:e6:26:b3",
    "64:7d:22:ee:b1:82",
    "14:a2:18:0d:f2:c4",
    "e3:c9:9f:06:10:02",
    "43:55:7b:ae:a2:09",
    "e0:01:0c:78:31:0a",
    "19:d9:a3:25:ee:e3",
    "e5:6d:9f:1e:ae:07",
    "bf:ad:66:a9:29:c5",
    "2f:bd:69:19:3c:84",
    "12:10:5a:05:b5:7e",
    "55:1e:c4:48:27:c8",
    "0d:36:73:87:2a:8e",
    "b1:de:6a:42:07:6f",
    "97:60:6b:22:0c:ff",
    "29:98:ef:14:00:9c",
    "10:9b:7f:b1:ef:f7",
    NULL
};

char *ipdata[] = {
    "ffe5:1838:afd7:2472:b3e7:3ae6:a228:12b4",
    "0e51:a030:c113:3838:c080:dd09:4d6c:189d",
    "9af2:2354:ecd1:f412:b9e3:648c:519d:dddf",
    "69df:0c97:aaff:ef86:7cc0:ede5:2a7b:6cc0",
    "4605:da5a:9f0f:8a36:f63a:e40a:1614:0554",
    "6956:2caa:6abf:f6b2:3c57:a99c:d88d:ff7d",
    "4a7d:e4d7:54ea:48ed:8467:6b59:3670:a941",
    "1d24:c623:219a:0aa1:7628:51ce:870a:898f",
    "5e0f:1e4b:e619:d99f:dd65:caf1:12a5:01fc",
    "8693:39c0:36de:d326:cb63:a585:c63e:2f04",
    "e4b8:49bf:c446:61d1:be0e:9c2c:576c:5569",
    "8c15:aa3e:fe29:02f4:3b26:e0cc:e11b:841e",
    "8ec7:35c2:42cf:3807:76fe:5559:3416:0159",
    "9343:d8c4:5312:b33c:e122:9ef1:495c:3219",
    "50c3:42cc:1ae4:232e:2f65:2688:185a:e358",
    "f268:1e93:8152:330d:af0c:739d:a7cc:7c32",
    "4f8b:17ea:ba51:9125:c6a1:1926:0e97:ebf7",
    "71ac:7e51:df32:a7c0:2e1e:4e72:1c1c:b1fe",
    "08f2:4b6b:19ec:0134:70f3:e535:30eb:2abf",
    "72e5:1837:4ed4:55b9:ab1d:fd72:5f5a:619f",
    "9da0:1246:e942:b4d8:815f:5b9c:a602:4ceb",
    "6b01:7257:7cf1:0896:a0d0:f130:c736:e0db",
    "5338:41ab:64f7:a598:39b6:e0f8:5a6e:5ec8",
    "629d:d9fe:4a47:3513:86c1:bc3d:38c3:0aa8",
    "caa0:301b:1c87:b030:7dc8:4938:db56:ddc4",
    "eb41:18ee:1ba3:91ea:cf72:19d9:5f5e:f72b",
    "2003:d730:c26d:17b4:8692:ff9a:da88:c99f",
    "2a01:8d53:900b:24fe::972f:3ecb",
    "2003:d730:c26d:17b4:8692:ff9a:da88:0000/96",
    "2a01:8d53:900b:d2ee:0000:0000:0000:0000/64",
    "2a01::/16",
    NULL
};


void show_mem_addrs(HOST_set *s)
{
    int j;
    
    printf("show hostset mem addresses\n");
    for (j = 0; macdata[j]; j++) {
        IP_t   ip;
        MAC_t  mac;
        HOST_t *i;
        HOST_t node;

        mac_parse(&mac, macdata[j]);
        ip_parse(&ip, ipdata[j]);
        host_set(&node, &mac, &ip, 0);
        
        i = hostset_get(s, &node);
        assert(i != NULL);
        printf("@mem: %p, %p\n", i, i->type.router.prefix);
    }
}


/*
 * Test routines
 */
int test_mac()
{
    MAC_t node_m, node_n;
    MAC_t *m = &node_m, *n = &node_n, *o;
    MAC_set *s;
    int j, rc;
    char *c;
    u_int8_t plainmac[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

    printf("create macset\n");
    s = macset_create(0,0,0);
    assert(s != NULL);
    
    printf("fill macset\n");
    for (j = 0; macdata[j]; j++) {
        c = macdata[j];
        o = mac_parse(m, c);
        assert(m == o);
        rc = macset_add(s, m);
        assert(rc == DATA_ADDED);
    }

    printf("macset addstrings\n");
    for (j = 0; macdata[j]; j++) {
        c = macdata[j];
        assert(IS_MAC(c));
        rc = macset_addstring(s, c);
        assert(rc == DATA_EXISTS);
    }
    
    printf("macset addmacs\n");
    for (j = 0; macdata[j]; j++) {
        c = macdata[j];
        o = mac_parse(m, c);
        assert(m == o);
        rc = macset_add(s, m);
        assert(rc == DATA_EXISTS);
    }

    printf("mac_parse/mac_cmp/mac_eq\n");
    mac_parse(m, "10:9b:7f:b1:ef:f7");
    mac_parse(n, "10:9b:7f:b1:ef:f7");
    assert(!mac_cmp(m,n));
    assert(mac_eq(m,n));
    mac_parse(n, "00:9b:7f:b1:ef:f7");
    assert(mac_cmp(m,n));
    assert(!mac_eq(m,n));
    mac_parse(n, "10:9b:7f:b1:ef:f6");
    assert(mac_cmp(m,n));
    assert(!mac_eq(m,n));
    
    printf("macset_contains\n");
    assert(macset_contains(s, mac_parse(NULL, "10:9b:7f:b1:ef:f7")));
    assert(!macset_contains(s, mac_parse(NULL, "00:9b:7f:b1:ef:f7")));
    assert(!macset_contains(s, mac_parse(NULL, "00:00:00:00:00:00")));
   
    printf("mac_pprint: '%s'\n", mac_str(m));
    printf("mac_pprint: '%s'\n", mac_str(n));

    macset_delete(s);
    
    mac_set(m, plainmac);
    mac_cmp(m, (MAC_t *)plainmac);
    printf("mac_pprint: '%s'\n", mac_str((MAC_t *) plainmac));
    
    return (EXIT_SUCCESS);
}

int test_ip()
{
    IP_t node_m, node_n;
    IP_t *m = &node_m, *n = &node_n, *o;
    IP_set *s;
    int j, rc;
    char *c;

    printf("ip_parse/ip_cmp/ip_eq\n");
    ip_parse(m, "2003:d730:c26d:17b4:8692:ff9a:da88:c99f");
    ip_parse(n, "2003:d730:c26d:17b4:8692:ff9a:da88:c99f");
    assert(0 == ip_cmp(m,n));
    assert(!memcmp(m, n, sizeof(*m)));
    ip_parse(n, "2003:d730:c26d:17b4:8692:ff9a:da88:c99e");
    assert(+1 == ip_cmp(m,n));
    assert(memcmp(m, n, sizeof(*m)) > 0);
    ip_parse(n, "2003:d730:c26d:17b4:8692:ff9a:da88:c9a0");
    assert(-1 == ip_cmp(m,n));
    assert(memcmp(m, n, sizeof(*m)) < 0);

    ip_parse(n, "2003:d730:c26d:17b4:8692:ff9a:da88:c99f");
    assert(ip_eq(m,n));
    ip_parse(n, "1003:d730:c26d:17b4:8692:ff9a:da88:c99f");
    assert(!ip_eq(m,n));
    ip_parse(n, "2003:d730:c26d:17b4:8692:ff9a:da88:c99e");
    assert(!ip_eq(m,n));

    printf("create ipset\n");
    s = ipset_create(0,0,0);
    assert(s);
    
    printf("fill ipset\n");
    for (j = 0; ipdata[j]; j++) {
        c = ipdata[j];
        o = ip_parse(m, c);
        assert(m == o);
        rc = ipset_add(s, m);
        assert(rc == DATA_ADDED);
    }

    printf("ipset addstrings\n");
    for (j = 0; ipdata[j]; j++) {
        c = ipdata[j];
        rc = ipset_addstring(s, c);
        assert(rc == DATA_EXISTS);
    }
    
    printf("ipset addips\n");
    for (j = 0; ipdata[j]; j++) {
        c = ipdata[j];
        o = ip_parse(m, c);
        assert(m == o);
        rc = ipset_add(s, m);
        assert(rc == DATA_EXISTS);
    }

    printf("ipset_contains\n");
    assert(ipset_contains(s, ip_parse(NULL, "6b01:7257:7cf1:0896:a0d0:f130:c736:e0db")));
    assert(!ipset_contains(s, ip_parse(NULL, "6b01:7257:7cf1:0896:a0d0:f130:c736:e0de")));
    assert(!ipset_contains(s, ip_parse(NULL, "6b00:7257:7cf1:0896:a0d0:f130:c736:e0db")));
   
    printf("ip_pprint: '%s'\n", ip_str(m));
    printf("ip_pprint: '%s'\n", ip_str(n));

    printf("ip_pprint_all:\n");
    ipset_print_all(s);
    
    ipset_delete(s);
    return (EXIT_SUCCESS);
}

int test_host()
{
    HOST_t node_h, node_i;
    HOST_t *h = &node_h, *i = &node_i;
    HOST_set *s;
    int j, rc;

    MAC_t mac;
    IP_t  ip;
    IP_t *ipdup;
    
    printf("create hostset\n");
    s = hostset_create(0,0,0);
    assert(s);

    printf("fill hostset\n");
    for (j = 0; macdata[j]; j++) {
        mac_parse(&mac, macdata[j]);
        ip_parse(&ip, ipdata[j]);
        host_set(h, &mac, &ip, time(NULL));
        
        rc = hostset_add(s, h);
        assert(rc == DATA_ADDED);
        assert(h->type.router.prefix == NULL);
        assert(h->last_adv_ts != 0);
        assert(h->type.dad.contacted == MAGICMARKER);
    }
    assert(hostset_count(s) == j);

    printf("full hostset\n");
    for (j = 0; macdata[j]; j++) {
        mac_parse(&mac, macdata[j]);
        ip_parse(&ip, ipdata[j]);
        host_set(h, &mac, &ip, 0);
        
        rc = hostset_add(s, h);
        assert(rc == DATA_EXISTS);
        assert(h->type.router.prefix == NULL);
        assert(h->type.dad.contacted == MAGICMARKER);
    }

    printf("host_eq\n");
    j = 1;
    host_set(h, mac_parse(NULL, macdata[j]), ip_parse(NULL, ipdata[j]), time(NULL));
    host_set(i, mac_parse(NULL, macdata[j]), ip_parse(NULL, ipdata[j]), time(NULL));
    assert(host_eq(h, i));
    printf("hostset_contains\n");
    assert(hostset_contains(s, h, 0));
    assert(hostset_contains(s, i, 0));
    printf("hostset_get\n");
    assert(host_eq(hostset_get(s, i), h));
    assert(host_eq(hostset_get(s, h), i));

    printf("!host_eq\n");
    i = hostset_get(s, h);
    host_set(i, mac_parse(NULL, macdata[j+1]), ip_parse(NULL, ipdata[j]), time(NULL));
    assert(!host_eq(h, i));
    assert(!hostset_contains(s, i, 0));
    assert(NULL == hostset_get(s, i));
    host_set(i, mac_parse(NULL, macdata[j]), ip_parse(NULL, ipdata[j+1]), time(NULL));
    assert(!host_eq(h, i));
    assert(!hostset_contains(s, i, 0));
    assert(NULL == hostset_get(s, i));

    show_mem_addrs(s);

    printf("host_setrouterdata\n");
    j = 1;
    i = host_set(NULL, mac_parse(NULL, macdata[j]), ip_parse(NULL, ipdata[j]), time(NULL));
    h = hostset_get(s, i);
    assert(h);
    ip_parse(&ip, "2003:d730:c26d:17b4::/64");
    ipdup = ip_dup(&ip);
    host_setrouterdata(h, 0x0a, 1800, ipdup);
    printf("@mem: %p, %p\n", h, ipdup);
    assert(h->type.router.prefix == ipdup);

    show_mem_addrs(s);

    j++;
    i = host_set(NULL, mac_parse(NULL, macdata[j]), ip_parse(NULL, ipdata[j]), time(NULL));
    h = hostset_get(s, i);
    assert(h);
    ip_parse(&ip, "1234::/16");
    ipdup = ip_dup(&ip);
    host_setrouterdata(h, 0x08, 3600, ipdup);
    printf("@mem: %p, %p\n", h, ipdup);
    assert(h->type.router.prefix == ipdup);
    ipdup = NULL;

    printf("print hostset\n");
    hostset_print_all(s);
    show_mem_addrs(s);
    
    printf("remove hostset\n");
    for (j = 0; macdata[j]; j++) {
        HOST_t host;
        mac_parse(&mac, macdata[j]);
        ip_parse(&ip, ipdata[j]);
        host_set(&host, &mac, &ip, 0);
        
        rc = hostset_remove(s, &host);
        assert(rc == 0);
    }
    
    assert(hostset_count(s) == 0);
    printf("print hostset\n");
    hostset_print_all(s);
    
    hostset_delete(s);
    return (EXIT_SUCCESS);
}

int main(int argc, char** argv)
{
    init_plugin_deps();
    return test_mac() || test_ip() || test_host();
}
