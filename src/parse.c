/* parse.c
 * 
 * handles all functions related to parsing
 *
 * $Id: parse.c,v 1.34 2002/05/27 21:02:35 db Exp $
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

#include "config.h"
#include "tcm.h"
#include "event.h"
#include "bothunt.h"
#include "userlist.h"
#include "parse.h"
#include "numeric.h"
#include "logging.h"
#include "stdcmds.h"
#include "commands.h"
#include "wild.h"
#include "tcm_io.h"
#include "serno.h"
#include "patchlevel.h"
#include "modules.h"

static void do_init(void);
static void process_server(int conn_num,
			   char *source, char *function, char *body);
static void process_privmsg(char *nick, char *userhost,
			    int argc, char *argv[]);
static void send_umodes(char *nick);
static void on_join(char *nick, char *channel);
static void on_kick(char *nick);
static void on_nick(char *old_nick, char *new_nick);
static void on_ctcp(int connnum, int argc, char *argv[]);
static void wallops(int connnum, int argc, char *argv[]);
static void on_nick_taken(void);
static void cannot_join(char *channel);

int  maxconns = 0;

/*
 * parse_server()
 *
 * inputs       - NONE
 * output       - NONE
 * side effects - process server message
 */

void
parse_server(int conn_num)
{
  char *buffer = connections[conn_num].buffer;
  char *p;
  char *source;
  char *function;
  char *body = NULL;

  if (*buffer == ':')
  {
    source = buffer+1;
    if ((p = strchr(buffer,' ')) != NULL)
    {
      *p++ = '\0';
      function = p;

      if ((p = strchr(function, ' ')) != NULL)
      {
        *p++ = '\0';
        body = p;
      }
    }
    else
      return;
  }
  else
  {
    source = "";

    function = buffer;

    if ((p = strchr(function,' ')) != NULL)
    {
      *p++ = '\0';
      body = p;
    }
    else
      return;
  }

  if (config_entries.debug && outfile)
  {
    fprintf(outfile, ">source=[%s] function=[%s] body=[%s]\n",
            source, function, body);        /* - zaph */
    fflush(outfile);
  }

  process_server(conn_num, source, function, body);
}

/*
 * parse_client
 *
 * inputs       - index into connections array
 *              - integer argument count
 *              - array of pointers to split up argvs
 * output       - none
 * side effects -
 */

void
parse_client(int i)
{
  struct dcc_command *ptr;
  int argc;
  char *argv[MAX_ARGV];

  if ((argc = parse_args(connections[i].buffer, argv)) == 0)
    return;

  /* command */
  if(argv[0][0] == '.')
  {
    if((ptr = find_dcc_handler(argv[0] + 1)) != NULL)
    {
      if(connections[i].type & TYPE_ADMIN)
        ptr->handler[2](i, argc, argv);
      else if(connections[i].type & TYPE_OPER)
        ptr->handler[1](i, argc, argv);
      else
        ptr->handler[0](i, argc, argv);
    }
    /* command not found */
    else
      print_to_socket(connections[i].socket,
		      "Unknown command [%s]", argv[0] + 1);

  }
  /* message to partyline */
  else
  {
    if(connections[i].type & TYPE_PARTYLINE)
    {
      char buff[MAX_BUFF];

      expand_args(buff, MAX_BUFF-1, argc, argv);

      send_to_partyline(i, "<%s> %s", connections[i].nick, buff);
    }
    else
      print_to_socket(connections[i].socket,
		      "You are not +p, not sending to chat line");
  }
}

/*
 * expand_args
 *
 * inputs       - pointer to output
 *              - max length of output
 *              - argc
 *              - *argv[]
 * output       - none
 * side effects - This function takes a set of argv[] and expands
 *                it back out. basically the reverse of parse_args().
 */
void
expand_args(char *output, int maxlen, int argc, char *argv[])
{
  int curlen=0;
  int len;
  int i;

  for (i = 0; i < argc; i++)
  {
    len = strlen(argv[i]) + 1;
    if ((len + curlen) >= maxlen)
      {
        *output = '\0';
        return;
      }
    sprintf(output,"%s ", argv[i]);
    output += len;
    curlen += len;
  }
  /* blow away last ' ' */
  *--output = '\0';
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
int
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
 * process_server()
 *   Parse server messages based on the function and handle them.
 *   Parameters:
 *     source   - nick!user@host or server host that sent the message
 *     function - function for the server msgs (e.g. PRIVMSG, MODE, etc.)
 *     param    - The remainder of the server message
 *   Returns: void
 *
 *     If the source is in nick!user@host format, split the nickname off
 *     from the userhost.  Split the body off from the parameter for the
 *     message.  The parameter is generally either our nickname or the
 *     nickname directly affected by this message.  You can kind of figure
 *     the rest of the giant 'if' statement out.  Occasionally we need to
 *     parse additional parameters out of the body.  
 *     ADDED: watch out for partial PRIVMSGs received from the
 *     server... hold them up and make sure to stay synced with the timer
 *     signals that may be ongoing.
 */
static void
process_server(int conn_num, char *source, char *function, char *param)
{
  struct serv_command *ptr;
  char *userhost;
  int numeric=0;      /* if its a numeric */
  int argc=0;
  char *p;
  char *q;
  char *argv[MAX_ARGV];

  if (source && *source)
    argv[argc++] = source;
  if (function && *function)
    argv[argc++] = function;
  
  p = param;
  if (*p == ':')
    argv[argc++] = p;
  else
  {
    q = strchr(p, ' ');

    for (; (argc < MAX_ARGV-1) && q; q=strchr(p, ' '))
    {
      *q++ = '\0';
      if (*q == ':')
      {
        argv[argc++] = p;
        argv[argc++] = q+1;
        numeric = 1;
        break;
      }
      
      argv[argc++] = p;
      p = q;
    }

    if (*p != '\0' && !numeric)
      argv[argc++] = p;
  }

  numeric=0;

  if (strcmp(argv[1],"PRIVMSG") == 0)
  {
    if(strcasecmp(argv[2],mynick) == 0)
    {
      if ((userhost = strchr(argv[0], '!')) != NULL)
        *userhost++ = '\0';
      if (argv[3][0] == '\001')       /* it's a CTCP something */
        on_ctcp(0, argc, argv);
      else
        process_privmsg(source,userhost,argc,argv);
    }
  }

  /* PING doesnt have a prefix */
  else if (strcmp(argv[0], "PING") == 0)
    print_to_server("PONG %s", argv[1]);

  /* error doesnt have a prefix either */
  else if (strcmp(argv[0],"ERROR") == 0)
  {
    if (strncmp(argv[1], ":Closing Link: ", 15) == 0)
    {
      if (strstr(argv[1], "collision)"))
        on_nick_taken();
      server_link_closed(conn_num);
    }
  }

  else if ((strcmp(argv[1],"WALLOPS")) == 0)
  {
    wallops(0, argc, argv);
  }
  else if ((strcmp(argv[1],"JOIN")) == 0)
  {
    on_join(argv[0], argv[2]);
  }
  else if ((strcmp(argv[1],"KICK")) == 0)
  {
    on_kick(argv[3]);
  }
  else if (strcmp(argv[1],"NICK") == 0)
  {
    on_nick(source,argv[2]);
  }
  else if (strcmp(function,"NOTICE") == 0)
  {
    if(strcasecmp(source,config_entries.rserver_name) == 0)
    {
      onservnotice(0, argc, argv);
    }
  }

  if(isdigit((int) function[0]) && isdigit((int) function[1]) &&
     isdigit((int) function[2]))
    numeric = atoi(function);

  switch(numeric)
  {
    case RPL_STATSYLINE:
      if (!strcasecmp(argv[4], myclass))
        pingtime = atoi(argv[5]) * 2 + 15;
      break;

    case ERR_NICKNAMEINUSE:
      on_nick_taken();
      break;

    case  ERR_NOTREGISTERED:
      server_link_closed(conn_num);
      break;
	
    case ERR_CHANNELISFULL: case ERR_INVITEONLYCHAN:
    case ERR_BANNEDFROMCHAN: case ERR_BADCHANNELKEY:
      cannot_join(argv[3]);
      break;
	
    case RPL_MYINFO:
      strncpy(config_entries.rserver_name, argv[3], MAX_CONFIG);

      if ((p = strstr(argv[4],"hybrid")))
      {
        config_entries.hybrid = YES;

        p += 7;
        if(*p == '5')
          config_entries.hybrid_version = 5;
        else if(*p == '6')
          config_entries.hybrid_version = 6;
        else if(*p == '7')
          config_entries.hybrid_version = 7;
      }
      else
         config_entries.hybrid = NO;

      if (!amianoper)
        do_init();
      else
        send_umodes(mynick);
      break;

    case RPL_YOUREOPER:
      amianoper = YES;
      oper_time = time(NULL);
      send_umodes(mynick);
      inithash();
      print_to_server("STATS Y");
      break;
	
    case RPL_TRACEOPERATOR:
    case RPL_TRACEUSER:
      _ontraceuser(0, argc, argv);
      break;
	
    case RPL_TRACECLASS:
      _ontraceclass(0, argc, argv);
      break;
	
    case RPL_STATSILINE:
      on_stats_i(0, argc, argv);
      break;
	
    case RPL_STATSOLINE:
      on_stats_o(0, argc, argv);
      break;
	
    case RPL_VERSION:
      /* version_reply(body); */
      break;

    /* cant oper */
    case ERR_PASSWDMISMATCH:
    case ERR_NOOPERHOST:
      server_link_closed(conn_num);
      break;
	
    case RPL_STATSELINE:
    case RPL_STATSFLINE:
      on_stats_e(0, argc, argv);
      break;

    default:
      break;
  }
}

/*
 * process_privmsg()
 *
 * inputs       - nick
 *              - user@host string
 *              - message body
 * output       - none
 * side effects -
 */

static void
process_privmsg(char *nick, char *userhost, int argc, char *argv[])
{
  char *user;   /* user portion */
  char *host;   /* host portion */
  char *p;

  user = userhost;
  if ((p = strchr(userhost,'@')) == NULL)
    return;

  *p++ = '\0';

  host = p;

  if (argv[3][0] != '.')
  {
    send_to_all(SEND_PRIVMSG, "[%s!%s@%s] %s", nick, user, host, argv[3]);
    return;
  }

  if (!isoper(user,host))
  {
    notice(nick,"You are not an operator");
    return;
  }

  if(strncmp(argv[3], ".chat", 5) == 0)
  {
     initiate_dcc_chat(nick, user, host);
  }
}

/*
 * do_init()
 *
 * inputs       - none
 * output       - none
 * side effects - attempt to oper up, get version of server.
 */

static void
do_init(void)
{
  oper();

  print_to_server("VERSION");
  join(config_entries.defchannel, config_entries.defchannel_key);
  set_modes(config_entries.defchannel, config_entries.defchannel_mode,
            config_entries.defchannel_key);
}

/*
 * wallops()
 * inputs       - source, params, body as char string pointers
 * outputs      - sends messages to appropriate DCC users
 * side effects -
 */

void
wallops(int connnum, int argc, char *argv[])
{
  char *nick=argv[0], *p;

  if ((p = strchr(nick, '!')) == NULL)
    return;
  *p = '\0';

  if (*nick == ':')
    ++nick;

  if (!strncmp(argv[2], ":OPERWALL - ", 12))
    send_to_all(SEND_WALLOPS, "OPERWALL %s -> %s", nick, argv[2]+12);
  else if (!strncmp(argv[2], ":LOCOPS - ", 9))
    send_to_all(SEND_LOCOPS, "LOCOPS %s -> %s", nick, argv[2]+9);
  else
    send_to_all(SEND_WALLOPS, "WALLOPS %s -> %s", nick, argv[2]+11);
}

/*
 * send_umodes()
 *
 * inputs       - Nick to change umodes for
 * output       - NONE
 * side effects - Hopefully, set proper umodes for this tcm
 */

static void
send_umodes(char *nick)
{
  if (config_entries.hybrid && (config_entries.hybrid_version >= 6))
    print_to_server("MODE %s :+bcdfknrswxyzl\nSTATS I", nick );
  else
    print_to_server("FLAGS +ALL\nSTATS E\nSTATS F");
  initopers();
}

/*
 * on_join()
 *
 * inputs       - nick, channel, as char string pointers
 * output       - NONE
 * side effects -
 */

void
on_join(char *nick, char *channel)
{
  char *p;

  if (*channel == ':')
    ++channel;
  if (*nick == ':')
    ++nick;
  if ((p = strchr(nick, '!')) == NULL)
    return;
  *p = '\0';
  if (strcmp(mynick, nick) == 0)
  {
    strlcpy(mychannel,channel,MAX_CHANNEL);
  }
}

/*
 * on_kick
 *
 * inputs       - nick being kicked
 * output       - none
 * side effects - note kicked off of channel if it is us
 */

static void
on_kick(char *nick)
{
  if (strcmp(mynick,nick) == 0)
  {
    join(config_entries.defchannel,config_entries.defchannel_key);
    set_modes(config_entries.defchannel, config_entries.defchannel_mode,
              config_entries.defchannel_key);
  }
}

/*
 * on_nick
 *
 * inputs       - old nick
 *		- new nick
 * output       - none
 * side effects - change nick
 */

static void
on_nick(char *old_nick,char *new_nick)
{
  char *p;

  if (*new_nick == ':')
    ++new_nick;
  if (*old_nick == ':')
    ++old_nick;

  if ((p = strchr(old_nick, '!')) != NULL)
    *p = '\0';

  if (strcmp(old_nick,mynick) == 0)
    strcpy(mynick,new_nick);
}

/*
 * on_nick_taken
 *
 * inputs       - NONE
 * output       - NONE
 * side effects -
 */

static void
on_nick_taken(void)
{
  char randnick[MAX_NICK];

  (void)snprintf(randnick,MAX_NICK,"%s%1d",
		 config_entries.dfltnick,
                 (int) random() % 10);

  if (*mychannel == '\0')
  {
    newnick(randnick);
    strcpy(mynick,randnick);

    join(config_entries.defchannel,config_entries.defchannel_key);
    set_modes(config_entries.defchannel, config_entries.defchannel_mode,
              config_entries.defchannel_key);
  }
  else if (strncmp(randnick,config_entries.dfltnick,
                   strlen(config_entries.dfltnick)))
  {
    newnick(randnick);
    strcpy(mynick,randnick);
  }
}

/*
 * cannot_join
 *
 * inputs       - channel name
 * output       - none
 * side effects -
 */

static void
cannot_join(char *channel)
{
  char newchan[MAX_CHANNEL];
  int i;

  if (strcmp(channel,config_entries.defchannel) == 0)
    (void)snprintf(newchan,sizeof(newchan) - 1,"%.78s2",
                  config_entries.defchannel);
  else
  {
    channel += strlen(config_entries.defchannel);
    i = atoi(channel);
    (void)snprintf(newchan,sizeof(newchan) - 1,"%.78s%1d",
                   config_entries.defchannel,i+1);
  }

  join(newchan, config_entries.defchannel_key);
  set_modes(newchan, config_entries.defchannel_mode,
            config_entries.defchannel_key);
}

/*
 * on_ctcp
 * inputs	- nick
 *		- user@host
 * 		- text argument
 * output	- NONE
 *
 */

static void
on_ctcp(int connnum, int argc, char *argv[])
{
  char *hold, *nick, *port, *a;
  char *msg=argv[3]+1;
  char dccbuff[MAX_BUFF];

  nick = argv[0];
  hold = nick + strlen(nick) + 1;
  if (strncasecmp(msg,"PING",4) == 0)
  {
    notice(nick, "%s", argv[3]);
    return;
  }
  else if (strncasecmp(msg,"VERSION",7) == 0)
  {
    notice(nick,"\001VERSION %s(%s)\001",VERSION,SERIALNUM);
  }
  else if (strncasecmp(msg, "DCC CHAT", 8) == 0)
  {
    /* the -6 saves room for the :port */
    snprintf(dccbuff, MAX_BUFF-7, "#%s", argv[3]+15);
    if ((port = strrchr(argv[3], ' ')) == NULL)
    {
      notice(nick, "Invalid port specified for DCC CHAT.  Not funny.");
      return;
    }
    ++port;
    if ((a = strrchr(port, '\001')) != NULL)
      *a = '\0';

    strcat(dccbuff, ":");
    strcat(dccbuff, port);

    if (accept_dcc_connection(dccbuff, nick, hold) < 0)
    {
      notice(nick, "\001DCC REJECT CHAT chat\001");
      notice(nick,"DCC CHAT connection failed");
      return;
    }
  }
}

