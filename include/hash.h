#ifndef __HASH_H
#define __HASH_H

/* $Id: hash.h,v 1.28 2003/02/26 10:25:38 bill Exp $ */

#define HASHTABLESIZE 3001

extern struct hash_rec *user_table[HASHTABLESIZE];
extern struct hash_rec *host_table[HASHTABLESIZE];
extern struct hash_rec *domain_table[HASHTABLESIZE];
extern struct hash_rec *ip_table[HASHTABLESIZE];

struct user_entry {
  char nick[MAX_NICK];
  char username[MAX_USER];
  char host[MAX_HOST];
  char gecos[MAX_GECOS];
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
void update_nick(char *, char *, char *, char *);
#ifdef AGGRESSIVE_GECOS
void update_gecos(char *, char *, char *, char *);
#endif

void clear_hash(void);

struct user_entry *find_nick_or_host(const char *find, int type);
#define FIND_NICK 1
#define FIND_HOST 0

void list_nicks(struct connection *, char *, int);
void kill_or_list_users(struct connection *, char *, int, int, const char *);
void list_gecos(struct connection *, char *, int);
void report_mem(struct connection *);
void report_failures(struct connection *, int);

/* XXX - this is now in clones.c */
void check_reconnect_clones(char *, char *);

void report_domains(struct connection *connection_p, int num);
void kill_add_report(char *);
void list_class(struct connection *connection_p,
		char *class_to_find,int total_only);
#endif

