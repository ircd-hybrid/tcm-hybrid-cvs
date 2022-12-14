/* $Id: snprintf.h,v 1.1 2004/06/15 22:36:43 bill Exp $ */

#ifndef _PORTABLE_SNPRINTF_H_
#define _PORTABLE_SNPRINTF_H_
#include <stddef.h>
#include <stdarg.h>

#define PORTABLE_SNPRINTF_VERSION_MAJOR 2
#define PORTABLE_SNPRINTF_VERSION_MINOR 2

#ifdef HAVE_SNPRINTF
#include <stdio.h>
#else
extern int libopm_snprintf(char *, size_t, const char *, /*args*/ ...);
extern int libopm_vsnprintf(char *, size_t, const char *, va_list);
#undef snprintf
#undef vsnprintf
#define snprintf libopm_snprintf
#define vsnprintf libopm_vsnprintf
#endif

#if defined(HAVE_SNPRINTF) && defined(PREFER_PORTABLE_SNPRINTF)
extern int portable_snprintf(char *str, size_t str_m, const char *fmt, /*args*/ ...);
extern int portable_vsnprintf(char *str, size_t str_m, const char *fmt, va_list ap);
#undef snprintf
#undef vsnprintf
#define snprintf  portable_snprintf
#define vsnprintf portable_vsnprintf
#endif

extern int asprintf  (char **ptr, const char *fmt, /*args*/ ...);
extern int vasprintf (char **ptr, const char *fmt, va_list ap);
extern int asnprintf (char **ptr, size_t str_m, const char *fmt, /*args*/ ...);
extern int vasnprintf(char **ptr, size_t str_m, const char *fmt, va_list ap);

#endif
