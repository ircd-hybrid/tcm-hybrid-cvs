/*
 * client_list.c: contains routines for managing lists of clients
 *
 * $Id: client_list.c,v 1.3 2003/03/30 00:47:41 bill Exp $
 */

#include "tcm.h"
#include "config.h"
#include "tcm_io.h"
#include "tools.h"
#include "userlist.h"
#include "hash.h"
#include "client_list.h"
#include "handler.h"
#include "modules.h"

static int find_empty();
static void init_list(int index);
#ifdef CLIENT_LIST_LIFE
void expire_lists();
#endif
struct dcc_command remove_msgtab;

static int
find_empty()
{
  int idx = 0;

  for (idx=0; idx<MAX_LISTS; ++idx)
  {
    if (client_lists[idx].name[0] == '\0')
      return idx;
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

#ifdef CLIENT_LIST_LIFE
  eventAdd("expire_lists", expire_lists, NULL, 60);
#endif
  add_dcc_handler(&remove_msgtab);
}

#ifdef CLIENT_LIST_LIFE
void
expire_lists()
{
  time_t now = time(NULL);
  int idx;

  for (idx=0; idx<MAX_LISTS; ++idx)
  {
    if ((now - client_lists[idx].creation_time) > CLIENT_LIST_LIFE)
      init_list(idx);
  }
}
#endif

void
print_list(struct connection *connection_p, char *name)
{
  time_t now = time(NULL);
  dlink_node *ptr;
  struct user_entry *user;
  int index;

  if ((index = find_list(name)) == -1)
  {
    send_to_connection(connection_p, "No such list.");
    return;
  }

  if (client_lists[index].dlink.head == NULL)
  {
    send_to_connection(connection_p, "List is empty.");
    return;
  }

  send_to_connection(connection_p, "Clients in list \'%s\':", name);

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
                         user->ip_host, user->class, user->gecos);
  }

  send_to_connection(connection_p, "%s) %d entr%s -- created by %s lifetime: %ld",
                     client_lists[index].name, dlink_length(&client_lists[index].dlink),
                     (dlink_length(&client_lists[index].dlink) == 1) ? "y" : "ies",
                     client_lists[index].creator, (now - client_lists[index].creation_time));
}

void
print_lists(struct connection *connection_p, char *mask)
{
  int idx;
  time_t now = time(NULL);

  if (BadPtr(mask))
    return;

  for (idx=0; idx<MAX_LISTS; ++idx)
  {
    if (!match(mask, client_lists[idx].name))
      send_to_connection(connection_p, "%s) %d entr%s -- created by %s lifetime: %ld",
                         client_lists[idx].name, dlink_length(&client_lists[idx].dlink),
                         (dlink_length(&client_lists[idx].dlink) == 1) ? "y" : "ies",
                         client_lists[idx].creator, (now - client_lists[idx].creation_time));
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

  if (dlink_find(user, &client_lists[idx].dlink) != NULL)
    return 1;

  dlink_add(user, ptr, &client_lists[idx].dlink);
  return 1;
}

int
del_client_from_list(struct user_entry *user, int idx)
{
  struct user_entry *node;
  dlink_node *ptr;

  if (idx < 0 || idx > MAX_LISTS)
    return 0;

  DLINK_FOREACH(ptr, client_lists[idx].dlink.head)
  {
    node = ptr->data;

    if (!strcasecmp(user->nick, node->nick) &&
        !strcasecmp(user->username, node->username) &&
        !strcasecmp(user->host, node->host))
    {
      dlink_delete(ptr, &client_lists[idx].dlink);
      return 1;
    }
  }

  return 1;
}

void
del_client_from_all_lists(struct user_entry *user)
{
  int idx;
  struct user_entry *node;
  dlink_node *ptr;

  for (idx=0; idx<MAX_LISTS; ++idx)
  {
    if (client_lists[idx].name[0] == '\0')
      continue;

    DLINK_FOREACH(ptr, client_lists[idx].dlink.head)
    {
      node = ptr->data;

      if (!strcasecmp(user->nick, node->nick) &&
          !strcasecmp(user->username, node->username) &&
          !strcasecmp(user->host, node->host))
      {
        dlink_delete(ptr, &client_lists[idx].dlink);
        break;
      }
    }

  }
}

int
find_list(char *name)
{
  int idx;

  if (BadPtr(name))
    return -1;

  for (idx=0; idx<MAX_LISTS; ++idx)
  {
    if (strcasecmp(name, client_lists[idx].name) == 0)
      return idx;
  }

  return -1;
}

void
m_remove(struct connection *connection_p, int argc, char *argv[])
{
  struct user_entry *user;
  int idx;
  dlink_node *ptr;

  if (argc < 2)
  {
    send_to_connection(connection_p,
                       "Usage: %s <list name> <wildcard nick>",
                       argv[0]);
    return;
  }

  if ((idx = find_list(argv[1])) == -1)
  {
    send_to_connection(connection_p,
                       "No such list.");
    return;
  }

  DLINK_FOREACH(ptr, client_lists[idx].dlink.head)
  {
    user = ptr->data;

    if (match(argv[2], user->nick) == 0)
    {
      if (!del_client_from_list(user, idx))
      {
        send_to_connection(connection_p,
                           "Failed to remove %s (%s@%s) [%s] {%s} from the list",
                           user->nick, user->username, user->host, user->ip_host, user->class);
        continue;
      }
      else
        send_to_connection(connection_p,
                           "  - %s (%s@%s) [%s] {%s}",
                           user->nick, user->username, user->host, user->ip_host, user->class);
    }
  }
}

struct dcc_command remove_msgtab = {
 "remove", NULL, {m_unregistered, m_remove, m_remove}
};
