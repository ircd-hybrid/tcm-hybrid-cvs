/* Prototypes for util.c portability functions.
 * 2003 Joshua Kwan and the Hybrid team
 *
 * $Id: util.h,v 1.1 2003/08/17 02:59:04 joshk Exp $
 */

#ifndef INCLUDED_util_h
#define INCLUDED_util_h

#include "setup.h"
#include <sys/types.h>

#ifndef HAVE_INET_ATON
int inet_aton(const char *cp, struct in_addr *addr);
#endif

#ifndef HAVE_STRLCAT
size_t strlcat(char *dst, const char *src, size_t siz);
#endif

#ifndef HAVE_STRLCPY
size_t strlcpy(char *dst, const char *src, size_t siz);
#endif

#ifndef HAVE_STRCASESTR
char *strcasestr(char *haystack, char *needle);
#endif

#ifndef HAVE_SNPRINTF
int snprintf (char *str, size_t count, const char *fmt,...);
#endif

#ifndef HAVE_VSNPRINTF
int vsnprintf (char *str, size_t count, const char *fmt, va_list args);
#endif

#endif /* !INCLUDED_util_h */
