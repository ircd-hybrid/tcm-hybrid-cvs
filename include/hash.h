#ifndef __HASH_H
#define __HASH_H

/* $Id: hash.h,v 1.3 2002/05/28 00:35:06 db Exp $ */


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

void freehash(void);
int  removefromhash(struct hashrec *table[], char *key, char *hostmatch,
		    char *usermatch, char *nickmatch);

void addtohash(struct hashrec *table[], char *key,struct userentry *item);
void updatehash(struct hashrec**,char *,char *,char *); 
void adduserhost(struct plus_c_info *, int, int);
void removeuserhost(char *, struct plus_c_info *);
void updateuserhost(char *nick1, char *nick2, char *userhost);
void check_clones(void *);
void init_hash(void);

#endif

