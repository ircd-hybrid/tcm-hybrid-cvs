/* tcm_io.c
 *
 * handles the I/O for tcm, including dcc connections.
 *
 * $Id: tcm_io.c,v 1.35 2002/05/26 02:12:46 db Exp $
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

#ifdef AIX
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
#include "serverif.h"
#include "commands.h"
#include "modules.h"
#include "tcm_io.h"
#include "numeric.h"
#include "logging.h"
#include "stdcmds.h"
#include "wild.h"
#include "wingate.h"
#include "serno.h"
#include "patchlevel.h"

static int get_line(char *inbuf,int *len, struct connection *connections_p);
static int connect_to_dcc_ip(const char *nick, const char *hostport);
static void va_print_to_socket(int sock, const char *format, va_list va);
static void va_print_to_server(const char *format, va_list va);
static int finish_accept_dcc_chat(int i);
static int finish_dcc_chat(int i);
static int signon_to_server(int unused);

fd_set readfds;            /* file descriptor set for use with select */
fd_set writefds;
struct connection connections[MAXDCCCONNS+1]; /*plus 1 for the server, silly*/

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
  int select_result;
  int nscanned;                 /* number scanned from one get_line */
  int tscanned;                 /* total scanned from successive get_line */
  char incomingbuff[BUFFERSIZE];
  char dccbuff[DCCBUFF_SIZE];
  int nread=0;
  int argc;
  char *argv[MAX_ARGV];
  int i;
  int server_time_out;
  struct timeval read_time_out;

  if (pingtime)
  {
    server_time_out = pingtime;
  }
  else
  {
    server_time_out = SERVER_TIME_OUT;
  }

  current_time = time(NULL);
  connections[0].last_message_time = current_time;

  eventAdd("check_clones", check_clones, NULL, CLONE_CHECK_TIME);

  FOREVER
  {
    current_time = time(NULL);

    if (current_time > (connections[0].last_message_time + server_time_out))
    {
      /* timer expired */
      send_to_all(SEND_ALL, "PING time out on server");
      log_problem("read_packet()", "ping time out");
      argv[0] = "ping time out";
      linkclosed(0, 1, argv);
      /* try reconnecting */
      return;
    }

    FD_ZERO (&readfds);

    _continuous(0, 0, NULL);

    for (i = 0; i < MAXDCCCONNS; i++)
      {
	if (connections[i].state != S_IDLE)
	  {
	    FD_SET(connections[i].socket, &readfds);
	    if (connections[i].state != S_IDLE)
	      FD_SET(connections[i].socket, &writefds);
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
      _scontinuous(0, 0, NULL);

      for (i=0; i < MAXDCCCONNS; i++)
      {
	if (connections[i].state != S_IDLE &&
	    FD_ISSET(connections[i].socket, &readfds))
          {
	    if (connections[i].state == S_CONNECTING)
	      {
		connections[i].state = S_ACTIVE;
		(connections[i].io_function)(i);
		continue;
	      }

            incoming_connnum = i;
            nread = read(connections[i].socket,
                        incomingbuff, sizeof(incomingbuff));

            if (nread == 0)
              {
                if (i == 0)
                  {
                    argv[0] = "Eof from server";
                    linkclosed(0, 1, argv);
                    /* try reconnecting */
                    return;
                  }
                else
                  {
                    close_connection(i);
                  }
              }
            else if (nread > 0)
              {
                tscanned = 0;
                connections[i].last_message_time = current_time;
		while ((nscanned =
			get_line(incomingbuff+tscanned,
				 &nread, &connections[i])))
		  {
#ifdef DEBUGMODE
		    printf("<- %s\n", connections[i].buffer);
#endif
		    (connections[i].io_function)(i);
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
        send_to_all(SEND_ALL, "Select error: %s (%d)",
                     strerror(errno), errno);
        (void)snprintf(dccbuff, sizeof(dccbuff) - 1,"select error %d", errno);
        log_problem("read_packet()", dccbuff);
        argv[0] = "select error";
        linkclosed(0, 1, argv);
	connections[0].state = S_IDLE;
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
  int nscanned=0;

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
 * linkclosed()
 *   Called when an error has causes the server to close our link.
 *   Parameters:
 *   Returns: void
 *
 *     Close the old dead socket.  If we haven't already reconnected
 *     5 times, wait 5 seconds, reconnect to the server, and re-signon.
 */
void
linkclosed(int connnum, int argc, char *argv[])
{
  char reason[MAX_BUFF];

  if (argc == 0)
  {
    log_problem("linkclosed()", "argc == 0 !");
    exit(0);
  }

  expand_args(reason, MAX_BUFF-1, argc, argv);

  (void)close(connections[0].socket);
  eventInit();                  /* event.c stolen from ircd */
  log_problem("linkclosed()", reason);

  amianoper = NO;

  log_problem("linkclosed()", "sleeping 30");
  sleep(30);

  connections[0].socket = connect_to_server(serverhost);

  if (connections[0].socket == INVALID)
    {
      log_problem("linkclosed()", "invalid socket quitting");
      quit = YES;
      return;
    }

/* XXX huh?*/
#if 0
  signon_to_server(0);
#endif
}



/*
 * find_free_connection_slot
 *
 * inputs       - nick
 *              - host
 * output       - none
 * side effects - finds a free connection slot to use
 */

int
find_free_connection_slot(const char *nick)
{
  int i;

  for (i=1; i < MAXDCCCONNS+1; ++i)
    {
      if (connections[i].state == S_IDLE)
	{
	  if (maxconns < i+1)
	    maxconns = i+1;
	  break;
	}
    }

  if(i > MAXDCCCONNS)
  {
    notice(nick,"Max users on tcm, dcc chat rejected\n");
    return(-1);
  }

  return(i);
}

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
  int dcc_port;                         /* dcc port to use */
  struct sockaddr_in socketname;
  int result = -1;
  int i;

  i = find_free_connection_slot(nick);
  if (i < 0)
    return;

  notice(nick, "Chat requested");
  strncpy(connections[i].nick, nick, MAX_NICK);
  strncpy(connections[i].user, user, MAX_USER);
  strncpy(connections[i].host, host, MAX_HOST);

  if ((connections[i].socket = socket(PF_INET,SOCK_STREAM,0)) < 0)
  {
    fprintf(stderr, "Error on open()\n");
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
    fprintf(stderr, "Cannot bind result = %d errno = %d\n", result, errno);
    notice(nick,"Cannot DCC chat");
    return;
  }

  if (listen(connections[i].socket,4) < 0)
  {
    fprintf(stderr,"Cannot listen\n");
    notice(nick,"Cannot DCC chat");
    return;
  }

  privmsg (nick,"\001DCC CHAT chat %lu %d\001", local_ip(ourhostname),
	   dcc_port);

  if (config_entries.debug && outfile)
      (void)fprintf(outfile, "DEBUG: dcc socket = %d\n",
		    connections[i].socket);

  connections[i].state = S_CONNECTING;
  connections[i].io_function = finish_accept_dcc_chat;
  connections[i].last_message_time = current_time;
}

/*
 * print_to_socket()
 *
 * inputs	- socket to output on
 *		- format string to output
 * output	- NONE
 * side effects	- NONE
 */
void
print_to_socket(int sock, const char *format, ...)
{
  va_list va;
  va_start(va,format);
  va_print_to_socket(sock, format, va);
  va_end(va);
}

/*
 * print_to_server()
 *
 * inputs	- format string to output to server
 * output	- NONE
 * side effects	- NONE
 */
void
print_to_server(const char *format, ...)
{
  va_list va;
  va_start(va,format);
  va_print_to_server(format, va);
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
  char command[MAX_BUFF];
  va_list va;
  snprintf(command, MAX_BUFF-1, "NOTICE %s :%s", nick, format);
  command[MAX_BUFF-1] = '\0';
  va_start(va,format);
  va_print_to_server(command, va);
  va_end(va);
}

/*
 * privmsg
 *
 * inputs	- nick to privmsg
 * 		- format string to use
 *		- var args to send
 * output	- none
 * side effects	- nick is privmsg'd
 */

void
privmsg(const char *nick,const char *format, ...)
{
  char command[MAX_BUFF];
  va_list va;
  snprintf(command, MAX_BUFF-1, "PRIVMSG %s :%s", nick, format);
  command[MAX_BUFF-1] = '\0';
  va_start(va,format);
  va_print_to_server(command, va);
  va_end(va);
}

/*
 * va_print_to_server()
 *
 * inputs	- format string to output to server
 * output	- NONE
 * side effects	- NONE
 */
static void
va_print_to_server(const char *format, va_list va)
{
  va_print_to_socket(connections[0].socket, format, va);
}

/*
 * va_print_to_socket() (helper function for above two)
 *
 * inputs	- socket to output on
 *		- format string to output
 * output	- NONE
 * side effects	- NONE
 */
static void
va_print_to_socket(int sock, const char *format, va_list va)
{
  char msgbuf[MAX_BUFF];

  vsnprintf(msgbuf, sizeof(msgbuf)-2, format, va);

  if (msgbuf[strlen(msgbuf)-1] != '\n')
    strcat(msgbuf, "\n");

  send(sock, msgbuf, strlen(msgbuf), 0);
}

/*
 * send_to_all
 *
 * inputs	- message to send
 *		- flag if message is to be sent only to all users or opers only
 * output	- NONE
 * side effects	- message is sent on /dcc link to all connected
 *		  users or to only opers on /dcc links
 *
 */

void
send_to_all(int type, const char *format,...)
{
  va_list va;
  int i;
  int echo;

  va_start(va,format);

  echo = (connections[incoming_connnum].type & TYPE_ECHO);

  for(i = 1; i < maxconns; i++)
    {
      if( !echo && (i == incoming_connnum) )
	continue;

      if (connections[i].socket != INVALID)
	{
	  switch(type)
	    {
	    case SEND_KLINE_NOTICES:
	      if (connections[i].type & TYPE_VIEW_KLINES)
		va_print_to_socket(connections[i].socket, format, va);
	      break;

	    case SEND_SPY:
	      if(connections[i].type & TYPE_SPY)
                va_print_to_socket(connections[i].socket, format, va);

	      break;

	    case SEND_WARN:
	      if (connections[i].type & TYPE_WARN)
		va_print_to_socket(connections[i].socket, format, va);
	      break;
	      
            case SEND_WALLOPS:
#ifdef ENABLE_W_FLAG
              if (connections[i].type & TYPE_WALLOPS)
                va_print_to_socket(connections[i].socket, format, va);
#endif
              break;

	    case SEND_LOCOPS:
	      if (connections[i].type & TYPE_LOCOPS)
		va_print_to_socket(connections[i].socket, format, va);
	      break;
	      
	    case SEND_PRIVMSG:
	      if(connections[i].set_modes & SET_PRIVMSG)
		va_print_to_socket(connections[i].socket, format, va);
	      break;

	    case SEND_NOTICES:
	      if(connections[i].set_modes & SET_NOTICES)
		va_print_to_socket(connections[i].socket, format, va);
	      break;

            case SEND_SERVERS:
              if(connections[i].type & TYPE_SERVERS)
                va_print_to_socket(connections[i].socket, format, va);
              break;

	    case SEND_ADMINS:
	      if(connections[i].type & TYPE_ADMIN)
                va_print_to_socket(connections[i].socket, format, va);
	      break;

	    case SEND_ALL:
	      va_print_to_socket(connections[i].socket, format, va);
	      break;

	    default:
	      break;
	    }
	}
    }
    va_end(va);
}

/*
 * accept_dcc_connection()
 *
 * inputs	- hostpost
 * 		- nick making the connection
 *		- userhost
 * output	- 
 * side effects	- Makes another connection
 */

int
accept_dcc_connection(const char *hostport, const char *nick, char *userhost)
{
  int  i;               /* index variable */
  char *p;              /* scratch pointer used for parsing */
  char *user;
  char *host;

  i = find_free_connection_slot(nick);
  if (i < 0)
    return(-1);

  if ((p = strchr(userhost,'@')) != NULL)
  {
    user = userhost;
    *p++ = '\0';
    host = p;
  }
  else
  {
    host = userhost;
    user = "*";
  }

  if ((p = strchr(host,' ')) != NULL)
    *p = '\0';

  if(isoper(user,host) == 0)
  {
    notice(nick,"You are not an operator");
    return (0);
  }

  connections[i].set_modes = 0;
  strncpy(connections[i].nick,nick,MAX_NICK-1);
  connections[i].nick[MAX_NICK-1] = '\0';
  strncpy(connections[i].user,user,MAX_USER-1);
  connections[i].user[MAX_USER-1] = '\0';
  strncpy(connections[i].host,host,MAX_HOST-1);
  connections[i].host[MAX_HOST-1] = '\0';
  connections[i].type = 0;

  connections[i].last_message_time = time(NULL);

  connections[i].socket = connect_to_dcc_ip(nick, hostport);
  if (connections[i].socket == INVALID)
    return (0);
  connections[i].state = S_CONNECTING;
  connections[i].io_function = finish_dcc_chat;
  FD_SET(connections[i].socket, &readfds);
}

/*
 * finish_accept_dcc_chat()
 *
 * inputs 	- index
 * output       - none
 * side effects -
 */

static int
finish_accept_dcc_chat(int i)
{
  struct sockaddr_in incoming_addr;
  int addrlen;
  int sock = connections[i].socket;

  addrlen = sizeof(struct sockaddr);
  if((connections[i].socket = accept(sock,
                     (struct sockaddr *)&incoming_addr,
                     (socklen_t *)&addrlen)) < 0 )
  {
    notice(connections[i].nick, "Error in DCC chat\n");
    fprintf(stderr, "Error in remote connect on accept()\n");
    close(sock);
    return;
  }

  (void)close(sock);

  connections[i].last_message_time = current_time;
  connections[i].nbuf = 0;
  connections[i].type = 0;

  finish_dcc_chat(i);
}

/*
 * finish_dcc_chat()
 *
 * inputs 	- index
 * output       - none
 * side effects -
 */

static int
finish_dcc_chat(int i)
{
  print_motd(connections[i].socket);

  report(SEND_ALL,
         CHANNEL_REPORT_ROUTINE,
         "Oper %s (%s@%s) has connected\n",
         connections[i].nick,
         connections[i].user,
         connections[i].host);

  print_to_socket(connections[i].socket,
		  "Connected.  Send '.help' for commands.");
  connections[i].io_function = parse_client;
}

/*
 * close_connection()
 *
 * inputs	- connection number
 * output	- NONE
 * side effects	- connection on connection number connnum is closed.
 */

void
close_connection(int connnum)
{
  int i;

  if (connections[connnum].socket != INVALID)
    close(connections[connnum].socket);

  connections[connnum].socket = INVALID;
  connections[connnum].state = S_IDLE;
  connections[connnum].io_function = NULL; /* blow up real good */

  if ((connnum + 1) == maxconns)
    {
      for (i=maxconns;i>0;--i)
	if (connections[i].state != S_IDLE)
	  break;
      maxconns = i+1;
    }
    
  send_to_all(SEND_ALL,
	       "Oper %s (%s@%s) has disconnected",
               connections[connnum].nick, connections[connnum].user,
               connections[connnum].host);

  connections[connnum].user[0] = '\0';
  connections[connnum].host[0] = '\0';
  connections[connnum].nick[0] = '\0';
  connections[connnum].registered_nick[0] = '\0';
}

/*
 * connect_to_server
 *
 * input	- pointer to string giving hostname:port OR
 * output	- socket or -1 if no socket
 * side effects	- Sets up a socket and connects to the given host and port
 *		  or given DCC chat IP
 */
int
connect_to_server(const char *hostport)
{
  struct sockaddr_in socketname;
  int port = 6667;
  char server[MAX_HOST];
  struct hostent *remote_hostent;
  char *p;

  /* Parse serverhost to look for port number */
  strcpy(server, hostport);

  if ((p = strchr(server,':')))
    {
      *p++ = '\0';
      port = atoi(p);
    }

  if ((remote_hostent = gethostbyname (server)) == NULL)
    {
      printf ("error: unknown host: %s\n", server);
      return (INVALID);
    }

  memcpy ((void *) &socketname.sin_addr,
	  (void *) remote_hostent->h_addr,
	  remote_hostent->h_length);

  connections[0].state = S_CONNECTING;
  connections[0].io_function = signon_to_server;
  return(connect_to_given_ip_port(&socketname, port));
}

/*
 * signon_to_server
 *
 * inputs       - unused
 * output       - NONE
 * side effects - does signon to server
 */

int
signon_to_server (int unused)
{
  connections[0].io_function = parse_server;
  connections[0].nbuf = 0;
  if (*mynick == '\0')
    strcpy (mynick,config_entries.dfltnick);

  if( config_entries.server_pass[0] )
    print_to_server("PASS %s", config_entries.server_pass);

  print_to_server("USER %s %s %s :%s",
		  config_entries.username_config,
		  ourhostname,
		  config_entries.server_name,
		  config_entries.ircname_config);
  
  print_to_server("NICK %s", mynick);
}

/*
 * connect_to_dcc_ip
 *
 * input	- pointer to nick
 *		- pointer to string giving dcc ip
 * output	- socket or -1 if no socket
 * side effects	- Sets up a socket and connects to the given host and port
 *		  or given DCC chat IP
 */
static int
connect_to_dcc_ip(const char *nick, const char *hostport)
{
  struct sockaddr_in socketname;
  char server[MAX_HOST];
  char *p;
  unsigned long remoteaddr;
  int port = 0;

  strcpy(server, hostport);

  /* kludge for DCC CHAT precalculated sin_addrs */
  if (*server == '#')
    {
       (void)sscanf(server+1,"%lu",&remoteaddr);
       /* Argh.  Didn't they teach byte order in school??? --cah */
       socketname.sin_addr.s_addr=htonl(remoteaddr);
    }
  else
    {
      return(INVALID);
    }

  if ((p = strchr(server,' ')))
    {
      *p++ = '\0';
      port = atoi(p);
    }

  if (port < 1024)
    {
      notice(nick, "Invalid port specified for DCC CHAT.  Not funny.");
      return (INVALID);
    }

  return(connect_to_given_ip_port(&socketname, port));
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

  /* open an inet socket */
  if ((sock = socket (AF_INET, SOCK_STREAM, 0)) < 0)
    {
      send_to_all(SEND_ALL,
		   "Can't assign fd for socket\n");
      return(INVALID);
    }

  optval = 1;
  setsockopt(sock, SOL_SOCKET,SO_REUSEADDR, (char *)&optval, sizeof(optval));

  /* virtual host support  */
  if(config_entries.virtual_host_config[0])
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

  fcntl(sock, F_SETFL, O_NONBLOCK);
  connect (sock, (struct sockaddr *) socketname, sizeof *socketname);
  return (sock);
}

/*
 * init_connections
 *
 * inputs	- NONE
 * output	- NONE
 * side effects	-
 */

void
init_connections(void)
{
  int i;

  for (i=0; i < MAXDCCCONNS+1; i++)
    {
      connections[i].socket = INVALID;
      connections[i].state = S_IDLE;
      connections[i].user[0] = '\0';
      connections[i].host[0] = '\0';
      connections[i].nick[0] = '\0';
      connections[i].registered_nick[0] = '\0';
    }
}
