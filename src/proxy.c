/*
 *  tcm-hybrid: an advanced irc connection monitor
 *  proxy.c: libopm interface code
 *
 *  Copyright (C) 2004 by William Bierman and the Hybrid Development Team
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307
 *  USA
 *
 *    $Id: proxy.c,v 1.1 2004/06/15 22:36:47 bill Exp $
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "libopm/src/opm.h"
#include "libopm/src/opm_error.h"
#include "libopm/src/opm_types.h"

#include "setup.h"
#include "config.h"
#include "tcm.h"
#include "tools.h"
#include "tcm_io.h"
#include "hash.h"
#include "proxy.h"
#include "handler.h"
#include "match.h"

static dlink_list scanners;
static dlink_list queue;

static void m_check(struct connection *, int, char **);

struct dcc_command check_msgtab = {
 "check", NULL, {m_unregistered, m_check, m_check}
};

struct scanner_conf *
scanner_create()
{
  struct scanner_conf *ret = NULL;

  if ((ret = (struct scanner_conf *)malloc(sizeof(struct scanner_conf))) == NULL)
    exit(-1);

  return ret;
}

struct protocol_conf *
protocol_create()
{
  struct protocol_conf *ret = NULL;

  if ((ret = (struct protocol_conf *)malloc(sizeof(struct protocol_conf))) == NULL)
    exit(-1);

  return ret;
}

struct scan_queue *
scan_queue_create()
{
  struct scan_queue *ret = NULL;

  if ((ret = (struct scan_queue *)malloc(sizeof(struct scan_queue))) == NULL)
    exit(-1);

  return ret;
}

void
add_scanner(struct scanner_conf *sc)
{
  dlink_node *ptr;

  if ((ptr = dlink_create()) == NULL)
    exit(-1);

  ptr->data = sc;
  dlink_add(sc, ptr, &scanners);
}

void
add_protocol_to_scanner(struct protocol_conf *pc, struct scanner_conf *sc)
{
  dlink_node *ptr;

  if ((ptr = dlink_create()) == NULL)
    exit(-1);

  ptr->data = pc;
  dlink_add(pc, ptr, &sc->protocols);
}

void
init_proxy_detection()
{
  dlink_node *ptr, *ptr2;
  struct scanner_conf *sc;
  struct protocol_conf *pc;
  int max_read = BUFFERSIZE;

  DLINK_FOREACH(ptr, scanners.head)
  {
    sc = ptr->data;

    /* XXX - LOG */
    if (!sc->target_ip[0])
      continue;

    /* create scanner */
    sc->scanner = opm_create();

    /* configure scanner using configuration file settings */
    opm_config(sc->scanner, OPM_CONFIG_FD_LIMIT, &proxy_fds);
    opm_config(sc->scanner, OPM_CONFIG_BIND_IP, &proxy_vhost);
    opm_config(sc->scanner, OPM_CONFIG_TARGET_STRING, &sc->target_string);
    opm_config(sc->scanner, OPM_CONFIG_SCAN_IP, &sc->target_ip);
    opm_config(sc->scanner, OPM_CONFIG_SCAN_PORT, &sc->target_port);
    opm_config(sc->scanner, OPM_CONFIG_MAX_READ, &max_read);
    opm_config(sc->scanner, OPM_CONFIG_TIMEOUT, &proxy_timeout);

    DLINK_FOREACH(ptr2, sc->protocols.head)
    {
      pc = ptr2->data;

      if (opm_addtype(sc->scanner, pc->type, pc->port) == OPM_ERR_BADPROTOCOL)
        dlink_delete(ptr2, &sc->protocols);
    }
  }

  add_dcc_handler(&check_msgtab);
}

static struct scanner_conf *
find_scanner(const char *name)
{
  dlink_node *ptr;
  struct scanner_conf *sc;

  DLINK_FOREACH(ptr, scanners.head)
  {
    sc = ptr->data;

    if (!strcasecmp(sc->name, name))
      return sc;
  }

  return NULL;
}

static char *get_ip(const char *hostname)
{
  struct in_addr in;

  if (!inet_aton(hostname, &in))
  {
    struct hostent *h;

    if ((h = gethostbyname(hostname)) == NULL)
      return NULL;

    memcpy(&in, h->h_addr, sizeof(struct in_addr));
  }

  return inet_ntoa(in);
}

int
enqueue_proxy_scan(struct scanner_conf *sc, char *ip, unsigned int flags, void *arg)
{
  OPM_REMOTE_T *rt;
  struct scan_queue *sq;
  dlink_node *ptr;
  int ret;

  rt = opm_remote_create(ip);
  sq = scan_queue_create();

  strlcpy(sq->ip, ip, sizeof(sq->ip));

  sq->scanner_conf = sc;
  sq->flags        = flags;
  sq->remote       = rt;

  if (flags & QUEUE_DCC)
    sq->connection = (struct connection *)arg;
  else
    sq->connection = NULL;

  if (flags & QUEUE_CONNECTION)
    sq->user = (struct user_entry *)arg;
  else
    sq->user = NULL;

  ptr = dlink_create();
  ptr->data = sq;
  dlink_add(sq, ptr, &queue);

  opm_callback(sc->scanner, OPM_CALLBACK_OPENPROXY, &dequeue_proxy_scan, (void *)ptr);
  opm_callback(sc->scanner, OPM_CALLBACK_NEGFAIL, &dequeue_proxy_scan, (void *)ptr);
  opm_callback(sc->scanner, OPM_CALLBACK_TIMEOUT, &dequeue_proxy_scan, (void *)ptr);
  opm_callback(sc->scanner, OPM_CALLBACK_END, &free_check, (void *)ptr);
  opm_callback(sc->scanner, OPM_CALLBACK_ERROR, &proxy_scan_error, (void *)ptr);

  if ((ret = opm_scan(sc->scanner, rt)) != OPM_SUCCESS)
  {
    if (flags & QUEUE_DCC)
      send_to_connection(sq->connection, "Unknown Error");
  }

  return 1;
}

static void
m_check(struct connection *connection_p, int argc, char *argv[])
{
  char *hostname, *scanner, *ip;
  struct scanner_conf *sc;

  if (argc < 2)
  {
    send_to_connection(connection_p, "Usage: %s <hostname> [scanner name]", argv[0]);
    return;
  }

  hostname = argv[1];
  scanner = argc > 2 ? argv[2] : "default";

  if ((sc = find_scanner(scanner)) == NULL)
  {
    send_to_connection(connection_p, "Unknown scanner \'%s\'", scanner);
    return;
  }

  if ((ip = get_ip(hostname)) == NULL)
  {
    send_to_connection(connection_p, "Cannot resolve %s", hostname);
    return;
  }

  send_to_connection(connection_p, "Scanning %s [%s]", hostname, ip);

  enqueue_proxy_scan(sc, ip, QUEUE_DCC, connection_p);
}

void
dequeue_proxy_scan(OPM_T *scanner, OPM_REMOTE_T *rt, int type, void *data)
{
  dlink_node *ptr;
  struct scan_queue *sq;
  struct user_entry *user;

  ptr = (dlink_node *)data;
  sq = (struct scan_queue *)ptr->data;
  user = sq->user;

  if (type == OPM_CALLBACK_OPENPROXY)
  {
    if (sq->flags & QUEUE_DCC)
      send_to_connection(sq->connection, "Found proxy %s", sq->ip);
    if (sq->flags & QUEUE_CONNECTION)
      handle_action(act_proxy, user->nick, user->username, user->host, user->ip_host, NULL);

    /* finding one is good enough */
    opm_end(scanner, rt);
  }
  else if (type == OPM_CALLBACK_NEGFAIL)
  {
    if (sq->flags & QUEUE_DCC)
      send_to_connection(sq->connection, "Negotiation of %s failed", sq->ip);
  }
  else if (type == OPM_CALLBACK_TIMEOUT)
  {
    if (sq->flags & QUEUE_DCC)
      send_to_connection(sq->connection, "Timed out on check for %s", sq->ip);
  }
}

void
free_check(OPM_T *scanner, OPM_REMOTE_T *rt, int type, void *data)
{
  dlink_node *ptr;
  struct scan_queue *sq;

  ptr = (dlink_node *)data;
  sq = (struct scan_queue *)ptr->data;

  opm_remote_free(rt);
  dlink_delete(ptr, &queue);
  free(sq);
}

void
proxy_scan_error(OPM_T *scanner, OPM_REMOTE_T *rt, int type, void *data)
{
  dlink_node *ptr;
  struct scan_queue *sq;

  ptr = (dlink_node *)data;
  sq = (struct scan_queue *)ptr->data;

  if (sq->flags & QUEUE_DCC)
  {
    send_to_connection(sq->connection, "Error scanning %s", sq->ip);
  }
}

void
cycle_scanners()
{
  dlink_node *ptr;
  struct scanner_conf *sc; 

  DLINK_FOREACH(ptr, scanners.head)
  {
    sc = ptr->data;

    opm_cycle(sc->scanner);
  }
}

void
logon_proxy_check(struct user_entry *user)
{
  dlink_node *ptr, *ptr2;
  char *pattern;
  char userhost[MAX_USER + 1 + MAX_HOST + 1];
  struct scanner_conf *sc;

  DLINK_FOREACH(ptr, scanners.head)
  {
    sc = ptr->data;

    DLINK_FOREACH(ptr2, sc->targets.head)
    {
      pattern = ptr2->data;

      snprintf(userhost, sizeof(userhost), "%s@%s", user->username, user->host);

      if (match(userhost, pattern))
      {
        enqueue_proxy_scan(sc, user->ip_host, QUEUE_CONNECTION, user);
        break;
      }
    }
  }
}
