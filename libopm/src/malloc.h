/* $Id: malloc.h,v 1.1 2004/06/15 22:36:42 bill Exp $ */

#ifndef MALLOC_H
#define MALLOC_H

#include "setup.h"

#ifdef STDC_HEADERS
# include <stdlib.h>
#endif

#define MyMalloc(SIZE) libopm_MyMalloc(SIZE)
#define MyFree(X) libopm_MyFree((void **) &X)

void *libopm_MyMalloc(size_t bytes);
void libopm_MyFree(void **var);

#endif /* MALLOC_H */
