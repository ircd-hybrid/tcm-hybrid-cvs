#ifndef __HASH_H
#define __HASH_H

/* $Id: hash.h,v 1.1 2002/05/27 21:02:30 db Exp $ */

struct userentry {
  char nick[MAX_NICK];
  char user[MAX_USER];
  char host[MAX_HOST];
  char ip_host[MAX_IP];         /* host ip as string */
#ifdef VIRTUAL
  char ip_class_c[MAX_IP];      /* /24 of host ip as string */
#endif
  char domain[MAX_HOST];
  char link_count;
  char isoper;
  char class[MAX_CLASS];
  time_t connecttime;
  time_t reporttime;
};

struct hashrec {
  struct userentry *info;
  struct hashrec *collision;
};

struct sortarray
{
  struct userentry *domainrec;
  int count;
};


#endif
