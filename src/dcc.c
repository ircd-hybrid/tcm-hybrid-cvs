/* dcc.c
 *
 * handles dcc connections.
 *
 * $Id: dcc.c,v 1.7 2002/06/05 00:10:56 leeh Exp $
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
#include "serno.h"
#include "patchlevel.h"

static void finish_outgoing_dcc_chat(int i);
static void finish_incoming_dcc_chat(int i);
static void timeout_dcc_chat(int i);
static void finish_dcc_chat(int i);
static void close_dcc_connection(int connnum);

/*
 * initiate_dcc_chat
 *
 * inputs       - nick
 *              - host
 * output       - none
 * side effects - initiate a dcc chat =to= a requester
 */

void
initiate_dcc_chat(const char *nick, const char *user, const char *host)
{
  int    dcc_port;                         /* dcc port to use */
  struct sockaddr_in socketname;
  int	flags;
  int	result = -1;
  int	i;

  if ((i = find_free_connection_slot()) < 0)
    {
      notice(nick,"Max users on tcm, dcc chat rejected\n");
      return;
    }

  notice(nick, "Chat requested");
  strlcpy(connections[i].nick, nick, MAX_NICK);
  strlcpy(connections[i].user, user, MAX_USER);
  strlcpy(connections[i].host, host, MAX_HOST);

  if ((connections[i].socket = socket(PF_INET,SOCK_STREAM,0)) < 0)
  {
    notice(nick,"Error on open");
    return;
  }

  for (dcc_port = LOWEST_DCC_PORT; dcc_port < HIGHEST_DCC_PORT; dcc_port++ )
  {
    memset(&socketname,0, sizeof(struct sockaddr));
    socketname.sin_family = AF_INET;
    socketname.sin_addr.s_addr = INADDR_ANY;
    socketname.sin_port = htons(dcc_port);

    if ((result = bind(connections[i].socket,(struct sockaddr *)&socketname,
                       sizeof(socketname)) < 0))
    {
      continue;
    }
    break;
  }

  if (result < 0)
  {
    close(connections[i].socket);
    notice(nick,"Cannot DCC chat");
    return;
  }

  flags = fcntl(connections[i].socket, F_GETFL, 0);
  flags |= O_NONBLOCK;
  (void) fcntl(connections[i].socket, F_SETFL, flags);

  if (listen(connections[i].socket,4) < 0)
  {
    close(connections[i].socket);
    notice(nick,"Cannot DCC chat");
    return;
  }

  privmsg (nick,"\001DCC CHAT chat %lu %d\001",
	   local_ip(tcm_status.my_hostname),
	   dcc_port);

  if (config_entries.debug && outfile)
      (void)fprintf(outfile, "DEBUG: dcc socket = %d\n",
		    connections[i].socket);

  connections[i].state = S_CONNECTING;
  connections[i].io_read_function = finish_outgoing_dcc_chat;
  connections[i].io_write_function = NULL;
  connections[i].io_close_function = close_connection;
  connections[i].last_message_time = current_time;
  connections[i].time_out = DCC_TIMEOUT;
  connections[i].io_timeout_function = timeout_dcc_chat;
  FD_SET(connections[i].socket, &readfds);
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
		      const char *host_ip, const char *port)
{
  unsigned long remoteaddr;
  struct sockaddr_in socketname;
  int  i;               /* index variable */
  int  i_port;

  if ((i = find_free_connection_slot()) < 0)
    {
      notice(source_p->name, "Max users on tcm, dcc chat rejected");
      return(-1);
    }

  if(is_an_oper(source_p->username, source_p->host) == 0)
  {
    notice(source_p->name, "You are not an operator");
    return (-1);
  }

  connections[i].set_modes = 0;
  strlcpy(connections[i].nick, source_p->name, MAX_NICK);
  strlcpy(connections[i].user, source_p->username, MAX_USER);
  strlcpy(connections[i].host, source_p->host, MAX_HOST);
  connections[i].last_message_time = time(NULL);

  (void)sscanf(host_ip, "%lu", &remoteaddr);
  /* Argh.  Didn't they teach byte order in school??? --cah */

  socketname.sin_addr.s_addr = htonl(remoteaddr);
  i_port = atoi(port);
  if (i_port < 1024)
    {
      notice(source_p->name, "Invalid port specified for DCC CHAT.  Not funny.");
      return (INVALID);
    }
  connections[i].socket = connect_to_given_ip_port(&socketname, i_port);
  if (connections[i].socket == INVALID)
    {
      close_connection(i);
      return (0);
    }
  connections[i].state = S_CONNECTING;
  connections[i].io_write_function = NULL;
  connections[i].io_read_function = finish_incoming_dcc_chat;
  connections[i].io_close_function = close_connection;
  connections[i].last_message_time = current_time;
  connections[i].time_out = DCC_TIMEOUT; 
  connections[i].io_timeout_function = timeout_dcc_chat;
  FD_SET(connections[i].socket, &readfds);
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
finish_outgoing_dcc_chat(int i)
{
  struct sockaddr_in incoming_addr;
  int addrlen;
  int sock = connections[i].socket;
  int accept_sock;

  addrlen = sizeof(struct sockaddr);
  errno=0;

  if((accept_sock = accept(connections[i].socket,
			   (struct sockaddr *)&incoming_addr,
			   (socklen_t *)&addrlen)) < 0 )
  {
    if (errno == EAGAIN)
      return;

    notice(connections[i].nick, "Error in DCC chat\n");
    close_connection(i);
    return;
  }

  /* close the listening socket, I've got a working socket now */
  close(sock);

  connections[i].socket = accept_sock;
  connections[i].last_message_time = current_time;
  connections[i].io_write_function = finish_dcc_chat;
  connections[i].nbuf = 0;
  FD_SET(connections[i].socket, &writefds);
}

/*
 * timeout_dcc_chat()
 *
 * inputs 	- index
 * output       - none
 * side effects -
 */

static void
timeout_dcc_chat(int i)
{
  notice(connections[i].nick, "DCC chat timedout\n");
  close_connection(i);
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
finish_incoming_dcc_chat(int i)
{
  connections[i].io_write_function = finish_dcc_chat;
  connections[i].io_read_function = NULL;
  connections[i].state = S_CLIENT;
  FD_SET(connections[i].socket, &writefds);
}

/*
 * finish_dcc_chat()
 *
 * inputs 	- index
 * output       - none
 * side effects - 
 */

static void
finish_dcc_chat(int i)
{
  report(FLAGS_ALL,
         CHANNEL_REPORT_ROUTINE,
         "Oper %s (%s@%s) has connected\n",
         connections[i].nick,
         connections[i].user,
         connections[i].host);

  connections[i].io_read_function = parse_client;
  connections[i].state = S_CLIENT;
  connections[i].io_read_function = parse_client;
  connections[i].io_write_function = NULL;
  connections[i].io_close_function = close_dcc_connection;
  connections[i].time_out = 0;
  FD_SET(connections[i].socket, &readfds);
  print_motd(connections[i].socket);
  print_to_socket(connections[i].socket,
                  "Connected.  Send '.help' for commands.");
}

/*
 * close_dcc_connection()
 *
 * inputs	- connection number
 * output	- NONE
 * side effects	- connection on connection number connnum is closed.
 */

static void
close_dcc_connection(int connnum)
{
  report(FLAGS_ALL,
         CHANNEL_REPORT_ROUTINE,
         "Oper %s (%s@%s) has disconnected",
         connections[connnum].nick, connections[connnum].user,
         connections[connnum].host);

  close_connection(connnum);
}

