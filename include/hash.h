#ifndef __HASH_H
#define __HASH_H

/* $Id: hash.h,v 1.9 2002/05/30 01:45:27 db Exp $ */

#define HASHTABLESIZE 3001

extern struct hashrec *usertable[HASHTABLESIZE];
extern struct hashrec *hosttable[HASHTABLESIZE];
extern struct hashrec *domaintable[HASHTABLESIZE];
extern struct hashrec *iptable[HASHTABLESIZE];


struct hashrec {
  char nick[MAX_NICK];
  char user[MAX_USER];
  char host[MAX_HOST];
  char ip_host[MAX_IP];         /* host ip as string */
#ifdef VIRTUAL
  char ip_class_c[MAX_IP];      /* /24 of host ip as string */
#endif
  char domain[MAX_HOST];
  char isoper;
  char class[MAX_CLASS];
  time_t connecttime;
  time_t reporttime;
  int  link_count;
  struct hashrec *next;
};

struct sortarray
{
  struct hashrec *domainrec;
  int count;
};

void freehash(void);
int  removefromhash(struct hashrec *table[], char *key, char *hostmatch,
		    char *usermatch, char *nickmatch);

void addtohash(struct hashrec *table[], char *key, struct hashrec *item);
void updatehash(struct hashrec**,char *,char *, char *); 
void adduserhost(struct plus_c_info *, int, int);
void removeuserhost(char *, struct plus_c_info *);
void updateuserhost(char *nick1, char *nick2, char *userhost);

struct hashrec *find_nick(const char * nick);
struct hashrec *find_host(const char * host);

void list_nicks(int sock,char *nick,int regex);
void list_users(int sock,char *userhost,int regex);
void kill_list_users(int sock,char *userhost,char *reason,int regex);
void report_mem(int sock);
void report_failures(int sock,int num);

/* XXX - this is now in clones.c */
void check_reconnect_clones(char *);

void report_failures(int sock, int num);
void report_domains(int sock, int num);
void kill_add_report(char *);
void report_domains(int sock,int num);
void list_class(int sock,char *class_to_find,int total_only);
#endif

