/*
 * client_list.c: contains routines for managing lists of clients
 *
 * $Id: client_list.c,v 1.1 2003/03/29 10:06:05 bill Exp $
 */

#include "tcm.h"
#include "config.h"
#include "tcm_io.h"
#include "tools.h"
#include "userlist.h"
#include "hash.h"
#include "client_list.h"

static int find_empty();
static void init_list(int index);

static int
find_empty()
{
  int a = 0;

  for (a=0; a<MAX_LISTS; ++a)
  {
    if (client_lists[a].name[0] == '\0')
      return a;
  }

  return -1;
}

static void
init_list(int index)
{
  dlink_node *ptr, *nextptr;

  DLINK_FOREACH_SAFE(ptr, nextptr, client_lists[index].dlink.head)
  {
    dlink_free(ptr);
  }
  memset(&client_lists[index].name, 0, sizeof(client_lists[index].name));
  client_lists[index].creator = NULL;
  client_lists[index].creation_time = (time_t) 0;
  client_lists[index].dlink.count = 0;
}

void
init_client_lists()
{
  int a = 0;
 
  for (a=0; a<MAX_LISTS; ++a)
    init_list(a);
}

void
print_list(struct connection *connection_p, char *name)
{
  dlink_node *ptr;
  struct user_entry *user;
  int index;

  if ((index = find_list(name)) == -1)
  {
    send_to_connection(connection_p, "No such list.");
    return;
  }

  if (client_lists[index].dlink.head == NULL)
    return;

  DLINK_FOREACH(ptr, client_lists[index].dlink.head)
  {
    user = ptr->data;

#ifndef AGGRESSIVE_GECOS
    if (user->gecos[0] == '\0')
      send_to_connection(connection_p, " %s (%s@%s) [%s] {%s}",
                         user->nick, user->username, user->host,
                         user->ip_host, user->class);
    else
#endif
      send_to_connection(connection_p, " %s (%s@%s) [%s] {%s} [%s]",
                         user->nick, user->username, user->host,
                         user->ip_host, user->class);
  }
}

void
print_lists(struct connection *connection_p, char *mask)
{
  int a;
  time_t now = time(NULL);

  if (BadPtr(mask))
    return;

  for (a=0; a<MAX_LISTS; ++a)
  {
    if (!match(mask, client_lists[a].name))
      send_to_connection(connection_p, "%s) %d entries -- created by %s lifetime: %ld",
                         client_lists[a].name, dlink_length(&client_lists[a].dlink),
                         client_lists[a].creator, (now - client_lists[a].creation_time));
  }
}

struct client_list *
create_list(struct connection *connection_p, char *name)
{
  int index;

  if (BadPtr(name))
    return NULL;

  if ((index = find_list(name)) >= 0)
  {
    send_to_connection(connection_p, "Error: list already exists!");
    return NULL;
  }

  if ((index = find_empty()) == -1)
  {
    send_to_connection(connection_p, "Error: client list table is full!");
    return NULL;
  }

  init_list(index);
  strlcpy((char *)&client_lists[index].name, name, sizeof(client_lists[index].name));
  client_lists[index].creator = find_user_in_userlist(connection_p->username);
  client_lists[index].creation_time = time(NULL);

  return (struct client_list *) &client_lists[index];
}

int
add_client_to_list(struct user_entry *user, int idx)
{
  dlink_node *ptr;

  if (idx < 0 || idx > MAX_LISTS)
    return 0;

  if ((ptr = dlink_create()) == NULL)
    return 0;

  dlink_add(user, ptr, &client_lists[idx].dlink);
  return 1;
}

int
del_client_from_list(struct user_entry *user, int idx)
{
  dlink_node *ptr;

  if (idx < 0 || idx > MAX_LISTS)
    return 0;

  if ((ptr = dlink_find(user, &client_lists[idx].dlink)) == NULL)
    return 0;

  dlink_delete(ptr, &client_lists[idx].dlink);
  return 1;
}

void
del_client_from_all_lists(struct user_entry *user)
{
  int a;
  dlink_node *ptr;

  for (a=0; a<MAX_LISTS; ++a)
  {
    if (client_lists[a].name[0] == '\0')
      continue;

    if ((ptr = dlink_find(user, &client_lists[a].dlink)) == NULL)
      continue;

    dlink_delete(ptr, &client_lists[a].dlink);
  }
}

int
find_list(char *name)
{
  int a;

  if (BadPtr(name))
    return -1;

  for (a=0; a<MAX_LISTS; ++a)
  {
    if (strcasecmp(name, client_lists[a].name) == 0)
      return a;
  }

  return -1;
}
