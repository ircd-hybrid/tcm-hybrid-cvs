/* tcm_io.c
 *
 * handles the I/O for tcm
 *
 * $Id: tcm_io.c,v 1.100 2002/09/11 17:55:39 db Exp $
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
#include <assert.h>

#ifdef HAVE_SYS_STREAM_H
# include <sys/stream.h>
#endif

#ifdef HAVE_SYS_SOCKETVAR_H
# include <sys/socketvar.h>
#endif

#ifdef HAVE_SYS_SELECT_H
# include <sys/select.h>
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
#include "numeric.h"
#include "hash.h"
#include "logging.h"
#include "stdcmds.h"
#include "wild.h"
#include "wingate.h"
#include "serno.h"
#include "patchlevel.h"
#include "tools.h"

static int get_line(char *inbuf,int *len, struct connection *connections_p);
static void va_send_to_connection(struct connection *,
				  const char *format, va_list va);
static void va_send_to_server(const char *format, va_list va);
static void signon_to_server(struct connection *uplink);
static void reconnect(void);

fd_set readfds;		/* file descriptor set for use with select */
fd_set writefds;	/* file descriptor set for use with select */

dlink_list connections;
int pingtime;
static struct connection *server_p;

void
init_connections(void)
{
  memset(&connections, 0, sizeof(connections));
}

/*
 * read_packet()
 *
 * inputs	- NONE
 * output	- NONE
 * side effects	- Read incoming data off one of the sockets and process it
 */
void
read_packet(void)
{
  dlink_node *ptr;
  dlink_node *next_ptr;
  struct connection *connection_p;
  int  select_result;
  int  nscanned;		/* number scanned from one get_line */
  int  tscanned;		/* total scanned from successive get_line */
  char incomingbuff[BUFFERSIZE];
  int  nread=0;
  struct timeval read_time_out;

  FOREVER
  {
    current_time = time(NULL);

    FD_ZERO (&readfds);
    FD_ZERO (&writefds);

    DLINK_FOREACH_SAFE(ptr, next_ptr, connections.head)
    {
      connection_p = ptr->data;

      if (connection_p->state != S_IDLE)
      {
	if(connection_p->time_out != 0)
	{
	  if(current_time > (connection_p->last_message_time
			     + connection_p->time_out))
	  {
	    if(connection_p->io_timeout_function != NULL)
	      (connection_p->io_timeout_function)(connection_p);
	    else if(connection_p->io_close_function != NULL)
	      (connection_p->io_close_function)(connection_p);
	    else
	      close_connection(connection_p);
	    continue;	/* connection_p->socket is now invalid */
	  }

	  /* not sent a ping, and we've actually
	   * connected to the server
	   */
	  else if(tcm_status.ping_state != S_PINGSENT &&
		  connection_p->state == S_SERVER)
	  {
	    /* no data, send a PING */
	    if(current_time > (connection_p->last_message_time
			       + (connection_p->time_out / 2)))
	    {
	      send_to_server("PING tcm");
	      tcm_status.ping_state = S_PINGSENT;
	    }
	  }
	}

	FD_SET(connection_p->socket, &readfds);
	if(connection_p->io_write_function != NULL)
	  FD_SET(connection_p->socket, &writefds);
      }
    }

    read_time_out.tv_sec = 1L;
    read_time_out.tv_usec = 0L;

    select_result = select(FD_SETSIZE, &readfds, &writefds, NULL,
                           &read_time_out);

    eventRun();

    if (select_result == 0)     /* timeout on read */
      continue;

    if (select_result > 0)
    {
      DLINK_FOREACH(ptr, connections.head)
      {
        connection_p = ptr->data;

	if (connection_p->state != S_IDLE &&
	    FD_ISSET(connection_p->socket, &writefds))
	{
	  if (connection_p->io_write_function != NULL)
	    (connection_p->io_write_function)(connection_p);
	}

	if (connection_p->state != S_IDLE &&
	    FD_ISSET(connection_p->socket, &readfds))
        {
	  if (connection_p->state == S_CONNECTING)
	  {
	    (connection_p->io_read_function)(connection_p);
	    continue;
	  }

	  nread = read(connection_p->socket,
		       incomingbuff, sizeof(incomingbuff));

	  if (nread == 0)
	  {
	    (connection_p->io_close_function)(connection_p);
	  }
	  else if (nread > 0)
	  {
	    tscanned = 0;
	    connection_p->last_message_time = current_time;

	    if(tcm_status.ping_state == S_PINGSENT)
	      tcm_status.ping_state = 0;

	    while ((nscanned =
		    get_line(incomingbuff+tscanned,
			     &nread, connection_p)))
	    {
#ifdef DEBUGMODE
	      printf("<- %s\n", connection_p->buffer);
#endif
	      /* io_read_function e.g. server_parse()
	       * can call close_connection(i), hence
	       * making io_read_function NULL
	       */
	      if (connection_p->io_read_function == NULL)
		break;
	      (connection_p->io_read_function)(connection_p);
	      tscanned += nscanned;
	    }
	  }
	}
      }
    }
    else /* -ve */
    {
      if (errno != EINTR)
      {
	tcm_log(L_ERR, "fatal error in select() errno=%d", errno);
	exit(-1);	/* XXX select error is fatal! */
      }
    }
  }
}

/*
 * get_line
 *
 * inputs       - pointer to position in input buffer
 *              - number of chars left in input buffer to scan
 *              - pointer to current struct connection
 * output       - if parsable buffer return number scanned
 *                if no parsable buffer, output is 0
 * side effects -
 *
 * nscanned keeps track of the total scanned input bytes
 * 
 * If there is a partial read line without a terminating \r\n (EOL)
 * connections_p->nbuf keeps track of how many bytes were scanned,
 * connections_p->buffer keeps those bytes scanned for the next read.
 * I then return a 0 to the caller so it knows there is nothing to parse.
 *
 * I alway reset connections_p->nbuf to 0 if I found a complete line
 * in the input buffer. i.e. one terminated with an EOL. I then return
 * to the caller the number of bytes available to parse.
 *
 * WARNING: the input buffer (*in) has to be larger than the output
 * this code will not handle needing three reads to produce one 
 * output buffer to parse for example. Since this code is dealing
 * with RFC irc buffer sizes (512) input size of 1024 or greater is fine.
 */

static int
get_line(char *in, int *len, struct connection *connections_p)
{
  char *p;
  int  nscanned=0;

  /* sanity test. if length read is already 0 or worse, -ve, ignore input */
  if (*len <= 0)
    {
      connections_p->nbuf = 0;
      return(0);
    }

  /* If there was an incomplete buffer, from last read,
   * continue from that point.
   */
  p = connections_p->buffer + connections_p->nbuf;

  /* Now, keep stuffing the read input buffer into
   * the connections buffer until either run out of bytes to stuff (*len==0),
   * or hit an EOL character or have a buffer overrun.
   */

  while (!EOL(*in))
    {
      *p++ = *in++;
      (*len)--;
      nscanned++;
      if (*len <= 0)
        {
	  connections_p->nbuf = nscanned;
          return(0);
        }

      /* Eeek! if this happens, then I have scanned all of the input
       * buffer without finding an EOL. Worse, the line is > BUFFERSIZE
       * i.e. its run on. This should be very rare.
       */
      if (connections_p->nbuf >= BUFFERSIZE) 
	{
	  connections_p->nbuf = 0;
	  return (0);
	}
    }

  /* At this point, there is an EOL char found, pull the EOL
   * chars out of the input buffer, tell caller how many bytes were
   * looked at and return.
   * Note again, that since there is a complete buffer here,
   * connections_p->nbuf is again set to 0.
   */

  if (EOL(*in))
    {
      in++;
      *p++ = '\0';
      nscanned++;
      if (*len != 0)
        (*len)--;
      while (EOL(*in))
        {
          in++;
          if (*len != 0)
            (*len)--;
	  nscanned++;
          if (*len == 0)
            break;
        }
      connections_p->nbuf = 0;
      return(nscanned);
    }

  return (0);
}

/*
 * server_link_closed()
 *
 * inputs	- connection id
 * output	- none
 * side effects	-
 *
 *   Called when an error has causes the server to close our link.
 *   Close the old dead socket. Try to reconnect to server.
 */
void
server_link_closed(struct connection *uplink_p)
{
  if (uplink_p != NULL)
    close_connection(uplink_p);
  tcm_log(L_ERR, "server_link_closed()");
  tcm_status.am_opered = NO;
  eventAdd("reconnect", (EVH *)reconnect, NULL, 30);
}

/*
 * reconnect
 *
 * inputs	- none
 * output	- none
 * side effects	- tiny function started as an event
 *		  to reconnect to server when necessary.
 */

void
reconnect(void)
{
  eventDelete((EVH *)reconnect, NULL);

  if (connect_to_server(config_entries.server_name,
			atoi(config_entries.server_port)) == NULL)
    {
      /* This one is fatal folks */
      tcm_log(L_ERR, "server_link_closed() invalid socket quitting");
      exit(-1);
    }
}

/*
 * find_free_connection
 *
 * inputs       - none
 *              - host
 * output       - none
 * side effects - finds a free connection to use, NULL if none found
 */
struct connection *
find_free_connection(void)
{
  dlink_node *ptr;
  struct connection *connection_p;

  if ((tcm_status.n_of_fds_open + 1) > tcm_status.max_fds)
    return (NULL);
  tcm_status.n_of_fds_open++;

  connection_p = (struct connection *) xmalloc(sizeof(struct connection));
  memset(connection_p, 0, sizeof(connection_p));

  ptr = dlink_create();
  dlink_add_tail(connection_p, ptr, &connections);
  
  return(connection_p);
}

/*
 * send_to_connection()
 *
 * inputs	- socket to output on
 *		- format string to output
 * output	- NONE
 * side effects	- NONE
 */
void
send_to_connection(struct connection *connection_p, const char *format, ...)
{
  va_list va;
  va_start(va,format);
  va_send_to_connection(connection_p, format, va);
  va_end(va);
}

/*
 * send_to_server()
 *
 * inputs	- format string to output to server
 * output	- NONE
 * side effects	- NONE
 */
void
send_to_server(const char *format, ...)
{
  va_list va;
  va_start(va,format);
  va_send_to_server(format, va);
  va_end(va);
}

/*
 * notice
 *
 * inputs	- nick to notice
 *		- format string to use
 * 		- var args to send
 * output	- none
 * side effects	- nick is notice'd
 */

void
notice(const char *nick, const char *format, ...)
{
  char	command[MAX_BUFF];
  va_list va;
  snprintf(command, MAX_BUFF, "NOTICE %s :%s", nick, format);
  va_start(va,format);
  va_send_to_server(command, va);
  va_end(va);
}

/*
 * privmsg
 *
 * inputs	- target to privmsg (nick/channel)
 * 		- format string to use
 *		- var args to send
 * output	- none
 * side effects	- target is privmsg'd
 */

void
privmsg(const char *target, const char *format, ...)
{
  char command[MAX_BUFF];
  va_list va;

  snprintf(command, MAX_BUFF, "PRIVMSG %s :%s", target, format);
  va_start(va,format);
  va_send_to_server(command, va);
  va_end(va);
}

/*
 * va_send_to_server()
 *
 * inputs	- format string to output to server
 * output	- NONE
 * side effects	- NONE
 */
static void
va_send_to_server(const char *format, va_list va)
{
  if (server_p != NULL)
    va_send_to_connection(server_p, format, va);
}

/*
 * va_send_to_connection() (helper function for above two)
 *
 * inputs	- struct connection to use
 *		- format string to output
 * output	- NONE
 * side effects	- NONE
 */
static void
va_send_to_connection(struct connection *connection_p,
		      const char *format, va_list va)
{
  char msgbuf[MAX_BUFF];

  vsnprintf(msgbuf, sizeof(msgbuf)-2, format, va);
  if (msgbuf[strlen(msgbuf)-1] != '\n')
    strcat(msgbuf, "\n");
  send(connection_p->socket, msgbuf, strlen(msgbuf), 0);
#ifdef DEBUGMODE
  printf("-> %s", msgbuf);
#endif
}

/*
 * send_to_all
 *
 * inputs	- pointer to originator of this message or NULL
 *		- flag bits of where to send message to
 *		- actual message
 * output	- NONE
 * side effects	- message is sent on /dcc link
 */
void
send_to_all(struct connection *from_p, int send_umode, const char *format,...)
{
  dlink_node *ptr;
  struct connection *connection_p;
  va_list va;

  va_start(va,format);
  DLINK_FOREACH(ptr, connections.head)
  {
    connection_p = ptr->data;
    if (from_p == connection_p)
      continue;
    if((connection_p->state == S_CLIENT) &&
       (connection_p->type & send_umode))
      va_send_to_connection(connection_p, format, va);
  }
  va_end(va);
}

/*
 * close_connection()
 *
 * inputs	- struct connection pointer
 * output	- NONE
 * side effects	- connection on connection number connnum is closed.
 */
void
close_connection(struct connection *connection_p)
{
  dlink_node *ptr;

  if (connection_p->socket != INVALID)
    close(connection_p->socket);

  tcm_status.n_of_fds_open--;
  assert (tcm_status.n_of_fds_open >= 0);

  ptr = dlink_find(connection_p, &connections);

  assert(ptr != NULL);
  if(ptr != NULL)
  {
    dlink_delete(ptr, &connections);
    xfree(ptr->data);
    xfree(ptr);
  }
}

/*
 * connect_to_server
 *
 * inputs	- pointer to string giving hostname
 *		- port #
 * output	- socket or -1 if no socket
 * side effects	- Sets up a socket and connects to the given host and port
 */
struct connection *
connect_to_server(const char *server, const int port)
{
  struct sockaddr_in socketname;
  struct hostent *remote_hostent;

  if ((server_p = find_free_connection()) == NULL)
    {
      tcm_log(L_ERR, "Could not find a free connection slot!");
      return (NULL);
    }

  if ((remote_hostent = gethostbyname (server)) == NULL)
    {
      printf("error: unknown host: %s\n", server);
      return (NULL);
    }

  memcpy ((void *) &socketname.sin_addr,
	  (void *) remote_hostent->h_addr,
	  remote_hostent->h_length);

  server_p->state = S_CONNECTING;
  server_p->io_read_function = signon_to_server;
  server_p->io_write_function = NULL;
  server_p->io_close_function = server_link_closed;
  server_p->io_timeout_function = server_link_closed;
  server_p->socket = connect_to_given_ip_port(&socketname, port);
  server_p->time_out = SERVER_TIME_OUT_CONNECT;
  current_time = time(NULL);
  server_p->last_message_time = current_time;
  return(server_p);
}

/*
 * signon_to_server
 *
 * inputs       - unused
 * output       - NONE
 * side effects - does signon to server
 */

static void
signon_to_server (struct connection *uplink_p)
{
  uplink_p->io_read_function = parse_server;
  uplink_p->io_write_function = NULL;
  uplink_p->state = S_SERVER;
  uplink_p->nbuf = 0;
  tcm_status.ping_state = S_PINGSENT;

  if (tcm_status.ping_time != 0)
    uplink_p->time_out = tcm_status.ping_time;
  else
    uplink_p->time_out = SERVER_TIME_OUT;

  if (tcm_status.my_nick[0] == '\0')
    strcpy (tcm_status.my_nick, config_entries.dfltnick);

  if (config_entries.server_pass[0] != '\0')
    send_to_server("PASS %s", config_entries.server_pass);

  send_to_server("USER %s %s %s :%s",
		  config_entries.username_config,
		  tcm_status.my_hostname,
		  config_entries.server_name,
		  config_entries.ircname_config);
  
  send_to_server("NICK %s", tcm_status.my_nick);
}

/*
 * connect_to_given_ip_port
 *
 * inputs	- pointer to struct sockaddr_in entry
 *		- port number to use
 * output	- INVALID if cannot connect, otherwise a socket
 * side effects	- try to connect to host ip given blocking connect for now...
 */

int
connect_to_given_ip_port(struct sockaddr_in *socketname, int port)
{
  int sock;
  struct sockaddr_in localaddr;
  struct hostent *local_host;
  int optval;
  int flags;

  /* open an inet socket */
  if ((sock = socket (AF_INET, SOCK_STREAM, 0)) < 0)
    {
      send_to_all(NULL, FLAGS_ALL, "Can't assign fd for socket");
      return(INVALID);
    }

  optval = 1;
  setsockopt(sock, SOL_SOCKET,SO_REUSEADDR, (char *)&optval, sizeof(optval));

  /* virtual host support  */
  if (config_entries.virtual_host_config[0])
    {
      if ((local_host = gethostbyname (config_entries.virtual_host_config)) )
	{
	  if(config_entries.debug && outfile)
	    {
	      fprintf(outfile,
		      "virtual host [%s]\n",
		      config_entries.virtual_host_config);
	      fprintf(outfile, "found official name [%s]\n",
		      local_host->h_name);
	    }

	  (void) memset(&localaddr, 0, sizeof(struct sockaddr_in));
	  (void) memcpy ((void *) &localaddr.sin_addr,
			 (void *) local_host->h_addr,
			 local_host->h_length);
	  localaddr.sin_family = AF_INET;
	  localaddr.sin_port = 0;

	  if(bind(sock,(struct sockaddr *)&localaddr,
	       sizeof(localaddr)) < 0)
	    {
	      if(config_entries.debug && outfile)
		{
		  fprintf(outfile, "unable to bind virtual host");
		}
	    }
	  else
	    {
	      if(config_entries.debug && outfile)
		{
		  fprintf(outfile, "bound to virtual host\n");
		}
	    }
	}
    }
      
  socketname->sin_family = AF_INET;
  socketname->sin_port = htons (port);

  /* set non blocking, the POSIX way */

  flags = fcntl(sock,F_GETFL,0);
  flags |= O_NONBLOCK;
  (void) fcntl(sock,F_SETFL,flags);
  connect (sock, (struct sockaddr *) socketname, sizeof *socketname);
  return (sock);
}

struct connection *
find_user_in_connections(const char *username)
{
  dlink_node *ptr;
  struct connection *connection_p;

  DLINK_FOREACH(ptr, connections.head)
  {
    connection_p = ptr->data;

    if(connection_p->state != S_CLIENT)
      continue;

    if(strcasecmp(connection_p->registered_nick, username) == 0)
      return (connection_p);
  }

  return (NULL);
}

/*
 * show_stats_p
 *
 * inputs	- nick to send stats p towards
 * output	- NONE
 * side effects	- NONE
 */
void
show_stats_p(const char *nick)
{
  dlink_node *ptr;
  struct connection *connection_p;
  int number_of_tcm_opers=0;

  DLINK_FOREACH(ptr, connections.head)
  {
    connection_p = ptr->data;

    /* ignore non clients */
    if (connection_p->state != S_CLIENT)
      continue;

    /* ignore invisible users/opers */
    if(connection_p->type & FLAGS_INVS)
      continue;
      
    /* display opers */
    if(connection_p->type & FLAGS_OPER)
    {
#ifdef HIDE_OPER_HOST
      notice(nick, "%s - idle %lu",
	     connection_p->nick, 
	     time(NULL) - connection_p->last_message_time);
#else 
      notice(nick,
	     "%s (%s@%s) idle %lu",
	     connection_p->nick, connection_p->username, connection_p->host,
	     time(NULL) - connection_p->last_message_time);
#endif
      number_of_tcm_opers++;
    }
  }

  notice(nick,"Number of tcm opers %d", number_of_tcm_opers);

  if (config_entries.statspmsg[0])
    notice(nick, config_entries.statspmsg);
}


/*
 * list_connections
 *
 * inputs	- socket
 * output	- NONE
 * side effects	- active connections are listed to socket
 */
void 
list_connections(struct connection *connection_p)
{
  dlink_node *ptr;
  struct connection *found_p;

  DLINK_FOREACH(ptr, connections.head)
  {
    found_p = ptr->data;

    if (found_p->state == S_CLIENT)
    {
      if(found_p->registered_nick[0] != 0)
      {
  	send_to_connection(connection_p,
			   "%s/%s %s (%s@%s) is connected - idle: %ld",
			   found_p->nick, found_p->registered_nick,
			   type_show(found_p->type), found_p->username,
			   found_p->host,
			   time((time_t *)NULL)-found_p->last_message_time);
      }
      else
      {
	send_to_connection(connection_p,
			   "%s O (%s@%s) is connected - idle: %ld",
			   found_p->nick, found_p->username,
			   found_p->host,
			   time(NULL) - found_p->last_message_time);
      }
    }
  }
}

