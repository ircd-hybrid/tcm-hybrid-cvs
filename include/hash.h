#ifndef __HASH_H
#define __HASH_H

/* $Id: hash.h,v 1.23 2002/06/23 19:50:14 db Exp $ */

#define HASHTABLESIZE 3001

extern struct hash_rec *user_table[HASHTABLESIZE];
extern struct hash_rec *host_table[HASHTABLESIZE];
extern struct hash_rec *domain_table[HASHTABLESIZE];
extern struct hash_rec *ip_table[HASHTABLESIZE];

struct user_entry {
  char nick[MAX_NICK];
  char username[MAX_USER];
  char host[MAX_HOST];
  char ip_host[MAX_IP];         /* host ip as string */
#ifdef VIRTUAL
  char ip_class_c[MAX_IP];      /* /24 of host ip as string */
#endif
  char domain[MAX_HOST];
  char class[MAX_CLASS];
  time_t connecttime;
  time_t reporttime;
  int  link_count;
};

struct hash_rec {
  struct user_entry *info;
  struct hash_rec *next;
};

struct sort_array
{
  struct hash_rec *domain_rec;
  int count;
};

int remove_from_hash_table(struct hash_rec *table[],
			   const char *key, const char *host_match,
			   const char *user_match, const char *nick_match);
void add_to_hash_table(struct hash_rec *table[], const char *key,
		       struct user_entry *new_user);
void add_user_host(struct user_entry *, int);
void remove_user_host(struct user_entry *);
void update_nick(char *user, char *host, char *oldnick, char *newnick);

void clear_hash(void);

struct user_entry *find_nick_or_host(const char *find, int type);
#define FIND_NICK 1
#define FIND_HOST 0

void list_nicks(int sock, char *nick, int regex);
void kill_or_list_users(int sock, char *userhost, int regex, int kill,
			const char *reason);
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

