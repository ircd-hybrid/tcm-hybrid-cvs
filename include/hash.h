#ifndef __HASH_H
#define __HASH_H

/* $Id: hash.h,v 1.2 2002/05/27 23:59:42 db Exp $ */

struct plus_c_info
{
  char *nick;
  char *user;
  char *host;
  char class[MAX_CLASS+1];
  char ip[MAX_IP+1];
};

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
void init_hash(void);

#endif

