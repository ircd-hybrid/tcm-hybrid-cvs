/* dcc.c
 *
 * handles dcc connections.
 *
 * $Id: dcc.c,v 1.19 2002/06/24 14:56:09 leeh Exp $
 */

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>

#ifdef HAVE_SYS_STREAM_H
# include <sys/stream.h>
#endif

#ifdef HAVE_SYS_SOCKETVAR_H
# include <sys/socketvar.h>
#endif

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include "config.h"
#include "tcm.h"
#include "parse.h"
#include "event.h"
#include "bothunt.h"
#include "userlist.h"
#include "modules.h"
#include "tcm_io.h"
#include "dcc.h"
#include "numeric.h"
#include "hash.h"
#include "logging.h"
#include "stdcmds.h"
#include "match.h"
#include "wild.h"
#include "serno.h"
#include "patchlevel.h"

static void finish_outgoing_dcc_chat(struct connection *);
static void finish_incoming_dcc_chat(struct connection *);
static void timeout_dcc_chat(struct connection *);
static void finish_dcc_chat(struct connection *);
static void close_dcc_connection(struct connection *);

/*
 * initiate_dcc_chat
 *
 * inputs       - nick
 *              - host
 * output       - none
 * side effects - initiate a dcc chat =to= a requester
 */

void
initiate_dcc_chat(struct source_client *source_p)
{
  int    dcc_port;                         /* dcc port to use */
  struct sockaddr_in socketname;
  int	flags;
  int	result = -1;
  struct connection *new_conn;

  if ((new_conn = find_free_connection()) == NULL)
    {
      notice(source_p->name, "Max users on tcm, dcc chat rejected");
      return;
    }

  notice(source_p->name, "Chat requested");
  strlcpy(new_conn->nick, source_p->name, MAX_NICK);
  strlcpy(new_conn->username, source_p->username, MAX_USER);
  strlcpy(new_conn->host, source_p->host, MAX_HOST);

  if ((new_conn->socket = socket(PF_INET,SOCK_STREAM,0)) < 0)
  {
    notice(source_p->name, "Error on open");
    return;
  }

  for (dcc_port = LOWEST_DCC_PORT; dcc_port < HIGHEST_DCC_PORT; dcc_port++ )
  {
    memset(&socketname,0, sizeof(struct sockaddr));
    socketname.sin_family = AF_INET;
    socketname.sin_addr.s_addr = INADDR_ANY;
    socketname.sin_port = htons(dcc_port);

    if ((result = bind(new_conn->socket,(struct sockaddr *)&socketname,
                       sizeof(socketname)) >= 0))
      break;
  }

  if (result < 0)
  {
    close(new_conn->socket);
    notice(source_p->name, "Cannot DCC chat");
    return;
  }

  flags = fcntl(new_conn->socket, F_GETFL, 0);
  flags |= O_NONBLOCK;
  (void) fcntl(new_conn->socket, F_SETFL, flags);

  if (listen(new_conn->socket,4) < 0)
  {
    close(new_conn->socket);
    notice(source_p->name, "Cannot DCC chat");
    return;
  }

  privmsg (source_p->name, "\001DCC CHAT chat %lu %d\001",
	   local_ip(tcm_status.my_hostname), dcc_port);

  if (config_entries.debug && outfile)
    (void)fprintf(outfile, "DEBUG: dcc socket = %d\n",
		  new_conn->socket);

  new_conn->state = S_CONNECTING;
  new_conn->io_read_function = finish_outgoing_dcc_chat;
  new_conn->io_write_function = NULL;
  new_conn->io_close_function = close_connection;
  new_conn->last_message_time = current_time;
  new_conn->time_out = DCC_TIMEOUT;
  new_conn->io_timeout_function = timeout_dcc_chat;
  FD_SET(new_conn->socket, &readfds);
}

/*
 * accept_dcc_connection()
 *
 * inputs	- hostport
 * 		- nick making the connection
 *		- userhost
 * output	- 
 * side effects	- Makes another connection
 */

int
accept_dcc_connection(struct source_client *source_p,
		      const char *host_ip, const int port)
{
  unsigned long remoteaddr;
  struct sockaddr_in socketname;
  struct connection *new_conn;

  if ((new_conn = find_free_connection()) == NULL)
    {
      notice(source_p->name, "Max users on tcm, dcc chat rejected");
      return(-1);
    }

  new_conn->set_modes = 0;
  strlcpy(new_conn->nick, source_p->name, MAX_NICK);
  strlcpy(new_conn->username, source_p->username, MAX_USER);
  strlcpy(new_conn->host, source_p->host, MAX_HOST);
  new_conn->last_message_time = current_time;

  (void)sscanf(host_ip, "%lu", &remoteaddr);
  /* Argh.  Didn't they teach byte order in school??? --cah */

  socketname.sin_addr.s_addr = htonl(remoteaddr);
  new_conn->socket = connect_to_given_ip_port(&socketname, port);
  if (new_conn->socket == INVALID)
    {
      close_connection(new_conn);
      return (0);
    }
  new_conn->state = S_CONNECTING;
  new_conn->io_write_function = NULL;
  new_conn->io_read_function = finish_incoming_dcc_chat;
  new_conn->io_close_function = close_connection;
  new_conn->last_message_time = current_time;
  new_conn->time_out = DCC_TIMEOUT; 
  new_conn->io_timeout_function = timeout_dcc_chat;
  FD_SET(new_conn->socket, &readfds);
  return (1);
}

/*
 * finish_outgoing_dcc_chat()
 *
 * inputs 	- index
 * output       - none
 * side effects -
 */

static void
finish_outgoing_dcc_chat(struct connection *new_conn)
{
  struct sockaddr_in incoming_addr;
  int addrlen;
  int sock = new_conn->socket;
  int accept_sock;

  addrlen = sizeof(struct sockaddr);
  errno=0;

  if((accept_sock = accept(new_conn->socket,
			   (struct sockaddr *)&incoming_addr,
			   (socklen_t *)&addrlen)) < 0 )
  {
    if (errno == EAGAIN)
      return;

    notice(new_conn->nick, "Error in DCC chat");
    close_connection(new_conn);
    return;
  }

  /* close the listening socket, I've got a working socket now */
  close(sock);

  new_conn->socket = accept_sock;
  new_conn->last_message_time = current_time;
  new_conn->io_write_function = finish_dcc_chat;
  new_conn->nbuf = 0;
  FD_SET(new_conn->socket, &writefds);
}

/*
 * timeout_dcc_chat()
 *
 * inputs 	- index
 * output       - none
 * side effects -
 */

static void
timeout_dcc_chat(struct connection *new_conn)
{
  notice(new_conn->nick, "DCC chat timedout");
  close_connection(new_conn);
}

/*
 * finish_incoming_dcc_chat()
 *
 * inputs 	- index
 * output       - none
 * side effects - 
 *
 */

static void
finish_incoming_dcc_chat(struct connection *new_conn)
{
  new_conn->io_write_function = finish_dcc_chat;
  new_conn->io_read_function = NULL;
  new_conn->state = S_CLIENT;
  FD_SET(new_conn->socket, &writefds);
}

/*
 * finish_dcc_chat()
 *
 * inputs 	- index
 * output       - none
 * side effects - 
 */

static void
finish_dcc_chat(struct connection *new_conn)
{
  dlink_node *ptr;
  struct oper_entry *user;

  report(FLAGS_ALL,
         "Oper %s (%s@%s) has connected",
         new_conn->nick, new_conn->username, new_conn->host);

  for(ptr = user_list.head; ptr; ptr = ptr->next)
  {
    user = ptr->data;

    if((match(user->username, new_conn->username) == 0) &&
       (wldcmp(user->host, new_conn->host) == 0))
    {
      strlcpy(new_conn->registered_nick, user->usernick,
              sizeof(new_conn->registered_nick));
      new_conn->type = (user->type|FLAGS_ALL);
      break;
    }
  }

  new_conn->state = S_CLIENT;
  new_conn->io_read_function = parse_client;
  new_conn->io_write_function = NULL;
  new_conn->io_close_function = close_dcc_connection;
  new_conn->time_out = 0;
  FD_SET(new_conn->socket, &readfds);
  print_motd(new_conn);
  send_to_connection(new_conn, "Connected.  Send '.help' for commands.");
}

/*
 * close_dcc_connection()
 *
 * inputs	- connection number
 * output	- NONE
 * side effects	- connection on connection number connnum is closed.
 */

static void
close_dcc_connection(struct connection *close_p)
{
  report(FLAGS_ALL,
         "Oper %s (%s@%s) has disconnected",
         close_p->nick, close_p->username, close_p->host);

  close_connection(close_p);
}

