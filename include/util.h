#ifndef __UTIL_H__
#define __UTIL_H__

#define SNORT_STRNCPY_SUCCESS 0
#define SNORT_STRNCPY_TRUNCATION 1
#define SNORT_STRNCPY_ERROR -1

int SnortStrncpy(char *, const char *, size_t);
void *SnortAlloc(unsigned long);
void LogMessage(const char *,...);

#endif /*__UTIL_H__*/
