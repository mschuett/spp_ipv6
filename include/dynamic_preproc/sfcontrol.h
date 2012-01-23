#ifndef __SF_CONTROL_H__
#define __SF_CONTROL_H__

#define CONTROL_FILE    "SNORT.sock"

#define CS_TYPE_HUP_DAQ     0x0001
#define CS_TYPE_MAX         0x1FFF
#define CS_HEADER_VERSION   0x0001

typedef struct _CS_MESSAGE_HEADER
{
    /* All values must be in network byte order */
    uint16_t version;
    uint16_t type;
    uint32_t length;    /* Does not include the header */
} CSMessageHeader;

typedef int (*OOBPreControlFunc)(uint16_t type, const uint8_t *data, uint32_t length, void **new_context);
typedef int (*IBControlFunc)(uint16_t type, void *new_context, void **old_context);
typedef void (*OOBPostControlFunc)(uint16_t type, void *old_context);

#endif

