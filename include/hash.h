#ifndef __HASH_H
#define __HASH_H

/* $Id: hash.h,v 1.10 2002/05/30 18:22:12 db Exp $ */

#define HASHTABLESIZE 3001

extern struct hashrec *user_table[HASHTABLESIZE];
extern struct hashrec *host_table[HASHTABLESIZE];
extern struct hashrec *domain_table[HASHTABLESIZE];
extern struct hashrec *ip_table[HASHTABLESIZE];

struct userentry {
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
};

struct hashrec {
  struct userentry *info;
  struct hashrec *next;
};

struct sortarray
{
  struct hashrec *domainrec;
  int count;
};

int  removefromhash(struct hashrec *table[], char *key, char *hostmatch,
		    char *usermatch, char *nickmatch);

void add_to_hash_table(struct hashrec *table[], const char *key,
		       struct hashrec *item);
void add_user_host(struct plus_c_info *, int, int);
void remove_user_host(char *, struct plus_c_info *);
void update_nick(char *nick1, char *nick2);

struct userentry *find_nick(const char * nick);
struct userentry *find_host(const char * host);

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

