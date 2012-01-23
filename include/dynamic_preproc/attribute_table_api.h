#ifndef _SF_ATTRIBUTE_TABLE_API_H
#define _SF_ATTRIBUTE_TABLE_API_H
#ifdef TARGET_BASED

typedef struct
{
    int (*addHost)(snort_ip_p ip);
    //int (*delHost)(snort_ip_p ip);
    int (*updateOs)(snort_ip_p ip, char *os, char *vendor, char *version, char *fragPolicy, char *streamPolicy);
    int (*addService)(snort_ip_p ip, uint16_t port, const char *ipproto, char *protocol, char *application, char *version, uint32_t confidence);
    int (*delService)(snort_ip_p ip, uint16_t port);
    //int (*addClient)( snort_ip_p ip, char *ipproto, char *protocol, char *application, char *version, uint32_t confidence);
    //int (*delClient)( snort_ip_p ip, char *ipproto, char *protocol, char *application);

} HostAttributeTableApi;

extern HostAttributeTableApi *AttributeTableAPI;

#endif
#endif   // _SF_ATTRIBUTE_TABLE_API_H

