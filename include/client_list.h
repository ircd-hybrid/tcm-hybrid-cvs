/* $Id: client_list.h,v 1.1 2003/03/29 10:06:03 bill Exp $ */
#ifndef _CLIENT_H_
#define _CLIENT_H_

#define MAX_LISTS	1024

struct client_list {
  dlink_list dlink;
  char name[BUFFERSIZE];
  struct oper_entry *creator;
  time_t creation_time;
};

struct client_list client_lists[MAX_LISTS];

void init_client_lists();
void print_list(struct connection *connection_p, char *name);
void print_lists(struct connection *connection_p, char *mask);
struct client_list *create_list(struct connection *connection_p, char *name);
int add_client_to_list(struct user_entry *user, int idx);
int del_client_from_list(struct user_entry *user, int idx);
int find_list(char *name);
void del_client_from_all_lists(struct user_entry *user);

#endif
