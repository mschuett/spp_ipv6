/* $Id$ */
/*
** Copyright (C) 2002-2011 Sourcefire, Inc.
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <syslog.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include "sf_types.h"
#include "snort_debug.h"

//#include "snort.h"
#define STD_BUF 1024

#ifdef DEBUG_MSGS
char *DebugMessageFile = NULL;
int DebugMessageLine = 0;

int DebugThis(uint64_t level)
{
    if (!(level & GetDebugLevel()))
        return 0;

    return 1;
}

uint64_t GetDebugLevel(void)
{
    static int debug_init = 0;
    static uint64_t debug_level = 0;

    const char* key;

    if ( debug_init )
        return debug_level;

    key = getenv(DEBUG_PP_VAR);

    if ( key )
        debug_level = strtoul(key, NULL, 0);

    debug_level <<= 32;

    key = getenv(DEBUG_VARIABLE);

    if ( key )
        debug_level |= strtoul(key, NULL, 0);

    debug_init = 1;

    return debug_level;
}

void DebugMessageFunc(uint64_t level, char *fmt, ...)
{
    va_list ap;

    if (!(level & GetDebugLevel()))
        return;

    va_start(ap, fmt);

    {
        if (DebugMessageFile != NULL)
            printf("%s:%d: ", DebugMessageFile, DebugMessageLine);
        vprintf(fmt, ap);
    }

    va_end(ap);
}

#ifdef SF_WCHAR
void DebugWideMessageFunc(uint64_t level, wchar_t *fmt, ...)
{
    va_list ap;

    if (!(level & GetDebugLevel()))
    {
        return;
    }

    /* filename and line number information */
    if (DebugMessageFile != NULL)
        printf("%s:%d: ", DebugMessageFile, DebugMessageLine);

    va_start(ap, fmt);

    {
#ifdef HAVE_WPRINTF
        vwprintf(fmt, ap);
#endif
    }

    va_end(ap);
}
#endif
#else /* DEBUG_MSGS */
void DebugMessageFunc(uint64_t level, char *fmt, ...)
{
}
#ifdef SF_WCHAR
void DebugWideMessageFunc(uint64_t level, wchar_t *fmt, ...)
{
}
#endif
#endif /* DEBUG_MSGS */
