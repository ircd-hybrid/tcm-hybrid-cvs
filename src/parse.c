/* parse.c
 * 
 * handles all functions related to parsing
 *
 * $Id: parse.c,v 1.67 2002/06/06 12:06:15 leeh Exp $
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
#include "hash.h"
#include "logging.h"
#include "stdcmds.h"
#include "wild.h"
#include "tcm_io.h"
#include "serno.h"
#include "patchlevel.h"
#include "modules.h"
#include "handler.h"
#include "dcc.h"

static void do_init(void);
static int  split_args(char *, char *argv[]);
static void process_server(struct source_client *, char *function, char *body);
static void process_privmsg(struct source_client *, int argc, char *argv[]);
static void send_umodes(char *nick);
static void on_ctcp(struct source_client *source_p, int argc, char *argv[]);
static void on_nick_taken(void);

struct t_tcm_status tcm_status;

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
  struct source_client source_p;
  char *buffer = connections[conn_num].buffer;
  char *p;
  char *source = NULL;
  char *function;
  char *body = NULL;

  memset(&source_p, 0, sizeof(struct source_client));

  if (*buffer == ':')
  {
    source = buffer+1;

    if ((p = strchr(buffer,' ')) == NULL)
      return;

    *p++ = '\0';
    function = p;

    /* nick!user@host */
    if((p = strchr(source, '!')) != NULL)
    {
      *p++ = '\0';

      source_p.name = source;
      get_user_host(&source_p.username, &source_p.host, p);
    }
    else
      source_p.name = source;
  }
  else
  {
    source_p.name = config_entries.server_name;
    function = buffer;
  }
  
  if ((p = strchr(function,' ')) != NULL)
  {
    *p++ = '\0';
    body = p;
  }
  else
    return;

  if (config_entries.debug && outfile)
  {
    fprintf(outfile, ">source=[%s] function=[%s] body=[%s]\n",
            (source == NULL) ? "<NULL>" : source, function, body); /* - zaph */
    fflush(outfile);
  }

  process_server(&source_p, function, body);
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

  if ((argc = split_args(connections[i].buffer, argv)) == 0)
    return;

  /* command */
  if(argv[0][0] == '.')
  {
    if((ptr = find_dcc_handler(argv[0] + 1)) != NULL)
    {
      if(has_umode(i, FLAGS_ADMIN))
        ptr->handler[2](i, argc, argv);
      else if(has_umode(i, FLAGS_OPER))
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
    if(has_umode(i, FLAGS_PARTYLINE))
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
 *                it back out. basically the reverse of split_args().
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
 * split_args
 *
 * inputs       - input buffer to parse into argvs
 *              - array of pointers to char *
 * outputs      - number of argvs (argc)
 *              - passed argvs back in input argv
 * side effects - none
 */
static int
split_args(char *buffer, char *argv[])
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
process_server(struct source_client *source_p, char *function, char *param)
{
  struct serv_command *ptr;
  struct serv_numeric *nptr;
  int numeric=0;      /* if its a numeric */
  int argc=0;
  char *p;
  char *q;
  char *argv[MAX_ARGV];

  argv[argc++] = source_p->name;
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

  if ((ptr = find_serv_handler(function)) != NULL)
  {
    ptr->handler(source_p, argc, argv);
    return;
  }

  if (strcmp(function, "PRIVMSG") == 0)
  {
    if(strcasecmp(argv[2], tcm_status.my_nick) == 0)
    {
      if (argv[3][0] == '\001')       /* it's a CTCP something */
        on_ctcp(source_p, argc, argv);
      else
        process_privmsg(source_p, argc, argv);

      return;	/* done */
    }
  }
  else if (strcmp(function, "PING") == 0)
  {
    print_to_server("PONG %s", argv[2]);
    return;	/* done */
  }
  else if(strcmp(function, "ERROR") == 0)
  {
    /* error doesnt have a prefix either */
    if (strncmp(argv[2], ":Closing Link: ", 15) == 0)
    {
      if (strstr(argv[2], "collision)"))
        on_nick_taken();
      server_link_closed(0);
      return;	/* done */
    }
  }

  if(isdigit((int)function[0]) && isdigit((int)function[1]) &&
     isdigit((int)function[2]))
  {
    numeric = atoi(function);
  }
  else
  {
    return;	/* Already handled */
  }

  for(nptr = serv_numeric_table; nptr; nptr = nptr->next)
    nptr->handler(numeric, argc, argv);

  switch(numeric)
  {
    case RPL_WELCOME:
      if((p = strrchr(argv[argc-1], ' ')) != NULL)
        *p++ = '\0';

      q = p;

      if((p = strchr(q, '!')) != NULL)
        *p = '\0';

      strlcpy(tcm_status.my_nick, q, MAX_NICK);
      break;

    case RPL_YOURHOST:
      /* Your host is foo[bar/6667], ...
       * Your host is foo, ...
       */
      q = argv[argc-1]+13;
      
      if((p = strchr(q, '[')) != NULL)
        *p = '\0';

      if((p = strchr(q, ',')) != NULL)
        *p = '\0';

      strlcpy(tcm_status.my_server, q, MAX_HOST);
      break;

    case RPL_STATSYLINE:
      if (!strcasecmp(argv[4], tcm_status.my_class))
        tcm_status.ping_time = atoi(argv[5]) * 2 + 15;
      break;

    case ERR_NICKNAMEINUSE:
      on_nick_taken();
      break;

    case  ERR_NOTREGISTERED:
      server_link_closed(0);
      break;
	
    case ERR_CHANNELISFULL: case ERR_INVITEONLYCHAN:
    case ERR_BANNEDFROMCHAN: case ERR_BADCHANNELKEY:
      tcm_status.my_channel[0] = '\0';
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

      if (!tcm_status.am_opered)
        do_init();
      else
        send_umodes(tcm_status.my_nick);
      break;

    case RPL_YOUREOPER:
      tcm_status.am_opered = YES;
      oper_time = time(NULL);
      send_umodes(tcm_status.my_nick);
      clear_hash();
      print_to_server("STATS Y");
      tcm_status.doing_trace = YES;
      print_to_server("TRACE");
      break;
	
    case RPL_TRACEOPERATOR:
    case RPL_TRACEUSER:
      on_trace_user(argc, argv);
      break;
	
    case RPL_TRACECLASS:
      tcm_status.doing_trace = NO;
      break;
	
    case RPL_STATSILINE:
      on_stats_i(argc, argv);
      break;
	
    case RPL_STATSOLINE:
      add_an_oper(argc, argv);
      break;
	
    case RPL_VERSION:
      /* version_reply(body); */
      break;

    /* cant oper */
    case ERR_PASSWDMISMATCH:
    case ERR_NOOPERHOST:
      server_link_closed(0);
      break;
	
    case RPL_STATSELINE:
    case RPL_STATSFLINE:
      on_stats_e(argc, argv);
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
process_privmsg(struct source_client *source_p, int argc, char *argv[])
{
  if (argv[3][0] != '.')
  {
    send_to_all(FLAGS_PRIVMSG, "[%s!%s@%s] %s",
                source_p->name, source_p->username, source_p->host, argv[3]);
    return;
  }

  if (!is_an_oper(source_p->username, source_p->host))
  {
    notice(source_p->name, "You are not an operator");
    return;
  }

  if(strncmp(argv[3], ".chat", 5) == 0)
  {
    initiate_dcc_chat(source_p);
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
  join();
  clear_bothunt();
  clear_hash();
  tcm_status.doing_trace = YES;
  print_to_server("TRACE");
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
  {
    print_to_server("MODE %s :+bcdfknrswxyzl");
    print_to_server("STATS I", nick);
  }
  else
  {
    print_to_server("FLAGS +ALL");
    print_to_server("STATS E");
    print_to_server("STATS F");
  }

  init_opers();
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

  if (tcm_status.my_channel[0] == '\0')
  {
    newnick(randnick);
    strcpy(tcm_status.my_nick, randnick);
  }
  else if (strncmp(randnick,config_entries.dfltnick,
                   strlen(config_entries.dfltnick)))
  {
    newnick(randnick);
    strcpy(tcm_status.my_nick, randnick);
  }
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
on_ctcp(struct source_client *source_p, int argc, char *argv[])
{
  char *nick;
  char *port;
  int  i_port;
  char *p;
  char *msg=argv[3]+1;

  nick = argv[0];

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
    if(is_an_oper(source_p->username, source_p->host) == 0)
    {
      notice(source_p->name, "You are not an operator");
      return;
    }

    if ((port = strrchr(argv[3], ' ')) == NULL)
    {
      notice(nick, "Invalid port specified for DCC CHAT.  Not funny.");
      return;
    }
    ++port;

    if ((p = strrchr(port, '\001')) != NULL)
      *p = '\0';

    i_port = atoi(port);
    if (i_port < 1024)
    {
      notice(source_p->name,
	     "Invalid port specified for DCC CHAT.  Not funny.");
      return;
    }

    if (accept_dcc_connection(source_p, argv[3]+15, i_port) < 0)
    {
      notice(nick, "\001DCC REJECT CHAT chat\001");
      notice(nick,"DCC CHAT connection failed");
      return;
    }
  }
}

