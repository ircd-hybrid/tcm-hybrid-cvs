/* tcm_io.c
 *
 * handles the I/O for tcm, including dcc connections.
 *
 * $Id: tcm_io.c,v 1.4 2002/05/23 16:05:51 leeh Exp $
 */

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/errno.h>
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
#include "token.h"
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
#include "serno.h"
#include "patchlevel.h"

#define EOL(c) ((c=='\r')||(c=='\n'))

static int parse_args(char *, char *argv[]);
static int get_line(char *inbuf,int *len, struct connection *connections_p);
static void connect_remote_client(char *, char *, char *, int);

/* -1 indicates listening for connection */
int initiated_dcc_socket = -1;
time_t initiated_dcc_socket_time;

char initiated_dcc_nick[MAX_NICK];
char initiated_dcc_user[MAX_USER];
char initiated_dcc_host[MAX_HOST];

extern int errno;          /* The Unix internal error number */
fd_set readfds;            /* file descriptor set for use with select */
fd_set writefds;


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
  struct common_function *temp;

  if (pingtime)
  {
    server_time_out = pingtime;
  }
  else
  {
    server_time_out = SERVER_TIME_OUT;
  }

  CurrentTime = time(NULL);
  connections[0].last_message_time = CurrentTime;

#ifdef SERVICES
  eventAdd("check_services", check_services, NULL, SERVICES_CHECK_TIME);
#endif

  eventAdd("check_clones", check_clones, NULL, CLONE_CHECK_TIME);

  FOREVER
  {
    CurrentTime = time(NULL);

    if (CurrentTime > (connections[0].last_message_time + server_time_out))
    {
      /* timer expired */
      sendtoalldcc(SEND_ALL_USERS,"PING time out on server\n");
      log_problem("read_packet()", "ping time out");
      argv[0] = "ping time out";
      linkclosed(0, 1, argv);
      /* try reconnecting */
      return;
    }

    FD_ZERO (&readfds);
    for (temp=continuous;temp;temp=temp->next)
      temp->function(0, 0, NULL);

    for (i = 0; i < maxconns; i++)
      if (connections[i].socket != INVALID)
        FD_SET(connections[i].socket,&readfds);

    if (initiated_dcc_socket > 0)
      FD_SET(initiated_dcc_socket,&readfds);

    read_time_out.tv_sec = 1L;
    read_time_out.tv_usec = 0L;

    select_result = select(FD_SETSIZE, &readfds, &writefds, (fd_set *)NULL,
                           &read_time_out);

    eventRun();

    if (select_result == 0)     /* timeout on read */
      continue;

    if (select_result > 0)
    {
      if (initiated_dcc_socket > 0 && FD_ISSET(initiated_dcc_socket, &readfds))
      {
        connect_remote_client(initiated_dcc_nick,
                              initiated_dcc_user,
                              initiated_dcc_host,
                              initiated_dcc_socket);
        initiated_dcc_socket = (-1);
      }
      for (temp = scontinuous; temp; temp=temp->next)
        temp->function(0, 0, NULL);

      for (i=0; i < maxconns; i++)
      {
        if (connections[i].socket != INVALID)
        {
          if (FD_ISSET(connections[i].socket, &readfds))
          {
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
                    for (temp=dcc_signoff;temp;temp=temp->next)
                      temp->function(i, 0, NULL);
                  }
              }
            else if (nread > 0)
              {
                tscanned = 0;
                connections[i].last_message_time = CurrentTime;
                if (i == 0)
                  {
                    while ((nscanned =
                            get_line(incomingbuff+tscanned,
                                     &nread, &connections[i])))
                      {
#ifdef DEBUGMODE
                        printf("<- %s\n", connections[i].buffer);
#endif
                        parse_server();
                        tscanned += nscanned;
                      }
                  }
                else
                  {
                    while ((nscanned =
                            get_line(incomingbuff+tscanned,
                                     &nread, &connections[i])))
                      {
                        argc = parse_args(connections[i].buffer, argv);
                        if (argc != 0)
                          parse_client(i, argc, argv);
                        tscanned += nscanned;
                      }
                  }
              }
          }
        }
      }
    }
    else /* -ve */
    {
      if (errno != EINTR)
      {
        sendtoalldcc(SEND_ALL_USERS,"Select error: %s (%d)\n",
                     strerror(errno), errno);
        (void)snprintf(dccbuff, sizeof(dccbuff) - 1,"select error %d", errno);
        log_problem("read_packet()", dccbuff);
        argv[0] = "select error";
        linkclosed(0, 1, argv);
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
 * connections_p->nbuf keeps track of how many bytes scanned,
 * connections_p->buffer keeps those bytes scanned for the next read.
 * I then return a 0 to the caller so it knows there is nothing to parse.
 *
 * I alway reset connections_p->nbuf to 0 if I found a complete line
 * in the input buffer. i.e. one terminated with an EOL. I then return
 * to the caller the number of bytes available to parse.
 * 
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
 * parse_args
 *
 * inputs       - input buffer to parse into argvs
 *              - array of pointers to char *
 * outputs      - number of argvs (argc)
 *              - passed argvs back in input argv
 * side effects - none
 */

static int
parse_args(char *buffer, char *argv[])
{
  int argc = 0;
  char *r;
  char *s;

  /* sanity test the buffer first */

  if (*buffer == '\0')
    return(0);

  if (EOL(*buffer))
    return(0);

  r = buffer;
  s = strchr(r, ' ');

  for (; (argc < MAX_ARGV-1) && s; s=strchr(r, ' '))
  {
    *s = '\0';
    argv[argc++] = r;
    r = s+1;
  }

  if (*r != '\0')
    argv[argc++] = r;

  return(argc);
}

/*
 * toserv
 *
 * inputs       - msg to send directly to server
 * output       - NONE
 * side effects - server executes command.
 */
void
toserv(char *format, ... )
{
  char msgbuf[MAX_BUFF];
  va_list va;

  va_start(va,format);

  if (connections[0].socket != INVALID)
  {
    vsnprintf(msgbuf,sizeof(msgbuf),format, va);
    send(connections[0].socket, msgbuf, strlen(msgbuf), 0);
  }

#ifdef DEBUGMODE
  printf("-> %s", msgbuf);
#endif

  va_end(va);
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
  struct common_function *temp;
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

  connections[0].socket = bindsocket(serverhost);
  if (connections[0].socket == INVALID)
  {
    log_problem("linkclosed()", "invalid socket quitting");
    quit = YES;
    return;
  }

  for (temp=signon;temp;temp=temp->next)
    temp->function(0, 0, NULL);
}


/*
 * connect_remote_client()
 *
 * inputs       - nick
 *              - username
 *              - hostname
 *              - incoming socket
 * output       - none
 * side effects -
 */

static void
connect_remote_client(char *nick,char *user,char *host,int sock)
{
  int i;
  struct sockaddr_in incoming_addr;
  int addrlen;

  for (i=1; i<MAXDCCCONNS+1; ++i)
  {
    if (connections[i].socket == INVALID)
    {
      if (maxconns < i+1)
        maxconns = i+1;
      break;
    }
  }

  if(i > MAXDCCCONNS)
  {
    notice(nick,"Max users on tcm, dcc chat rejected\n");
    (void)close(sock);
    return;
  }

  addrlen = sizeof(struct sockaddr);
  if((connections[i].socket = accept(sock,
                     (struct sockaddr *)&incoming_addr,
                     (socklen_t *)&addrlen)) < 0 )
  {
    notice(nick,"Error in DCC chat\n");
    (void)fprintf(stderr,"Error in remote connect on accept()\n");
    (void)close(sock);
    return;
  }
  connections[i].last_message_time = time(NULL);
  connections[i].nbuf = 0;
  connections[i].type = 0;
  connections[i].type |= isoper(user,host);

  if (config_entries.opers_only && !isoper(user,host))
  {
    notice(nick, "You are not an operator");
    return;
  }

  strncpy(connections[i].nick,initiated_dcc_nick,MAX_NICK);
  strncpy(connections[i].user,initiated_dcc_user,MAX_USER);
  strncpy(connections[i].host,initiated_dcc_host,MAX_HOST);

  print_motd(connections[i].socket);
  prnt(connections[i].socket,"Connected.  Send '.help' for commands.\n");
  report(SEND_ALL_USERS, CHANNEL_REPORT_ROUTINE, "%s %s (%s@%s) has connected\n",
         connections[i].type & TYPE_OPER ? "Oper" : "User", connections[i].nick,
         connections[i].user, connections[i].host);

  log("OPER DCC connection from %s!%s@%s",
      nick,
      user,
      connections[i].host);
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
initiate_dcc_chat(char *nick, char *user, char *host)
{
  int dcc_port;                         /* dcc port to use */
  struct sockaddr_in socketname;
  int result = -1;

  notice(nick,"Chat requested");
  strncpy(initiated_dcc_nick,nick,MAX_NICK);
  strncpy(initiated_dcc_user,user,MAX_USER);
  strncpy(initiated_dcc_host,host,MAX_HOST);

  if( (initiated_dcc_socket = socket(PF_INET,SOCK_STREAM,6)) < 0)
  {
    fprintf(stderr, "Error on open()\n");
    notice(nick,"Error on open");
    return;
  }

  for(dcc_port = LOWEST_DCC_PORT; dcc_port < HIGHEST_DCC_PORT; dcc_port++ )
  {
    memset(&socketname,0, sizeof(struct sockaddr));
    socketname.sin_family = AF_INET;
    socketname.sin_addr.s_addr = INADDR_ANY;
    socketname.sin_port = htons(dcc_port);

    if( (result = bind(initiated_dcc_socket,(struct sockaddr *)&socketname,
                       sizeof(socketname)) < 0) )
    {
      continue;
    }
    break;
  }

  if(result < 0)
  {
    (void)close(initiated_dcc_socket);
    initiated_dcc_socket = (-1);
    (void)fprintf(stderr, "Cannot bind result = %d errno = %d\n",
                  result, errno);
    notice(nick,"Cannot DCC chat");
    return;
  }

  if (listen(initiated_dcc_socket,4) < 0)
  {
    (void)close(initiated_dcc_socket);
    initiated_dcc_socket = (-1);
    (void)fprintf(stderr,"Cannot listen\n");
    notice(nick,"Cannot DCC chat");
    return;
  }

  privmsg(nick,"\001DCC CHAT chat %lu %d\001\n",
          local_ip(ourhostname),dcc_port);

  if (config_entries.debug && outfile)
      (void)fprintf(outfile, "DEBUG: initiated_dcc_socket = %d\n",
                    initiated_dcc_socket);

  initiated_dcc_socket_time = time(NULL);
}

