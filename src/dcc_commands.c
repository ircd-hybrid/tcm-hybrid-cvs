/* $Id: dcc_commands.c,v 1.76 2002/05/25 02:37:36 db Exp $ */

#include "setup.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <stdarg.h>
#include <time.h>

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
#include "event.h"
#include "token.h"
#include "bothunt.h"
#include "userlist.h"
#include "serverif.h"
#include "logging.h"
#include "commands.h"
#include "stdcmds.h"
#include "modules.h"
#include "tcm_io.h"
#include "wild.h"
#include "match.h"

#ifdef DMALLOC
#include "dmalloc.h"
#endif

#ifdef HAVE_CRYPT_H
#include <crypt.h>
#endif

static void set_actions(int sock, char *key, char *act, int duration, char *reason);
static void save_umodes(char *registered_nick, unsigned long type);
static void load_umodes(int connect_id);
static unsigned long find_user_umodes(char *nick);
static void set_umode(int connnum, char *flags, char *registered_nick);
static void show_user_umodes(int sock, char *registered_nick);
static void register_oper(int connnum, char *password, char *who_did_command);
static void list_opers(int sock);
static void list_connections(int sock);
static void list_exemptions(int sock);
static void handle_disconnect(int sock,char *param2,char *who_did_command);
static void handle_save(int sock,char *nick);
static int  islegal_pass(int connect_id,char *password);
static void print_help(int sock,char *text);

extern struct s_testline testlines;
extern char * get_method_names(int method);
extern int get_method_number(char * name);

void
m_vlist(int connnum, int argc, char *argv[])
{
#ifdef HAVE_REGEX_H
  if ((argc < 2) || (argc > 2 && strcasecmp(argv[1], "-r")))
    print_to_socket(connections[connnum].socket,
		    "Usage: %s <wildcarded/regexp ip>",
		    argv[0]);
  else if (argc == 2)
    list_virtual_users(connections[connnum].socket, argv[1], NO);
  else
    list_virtual_users(connections[connnum].socket, argv[2], YES);
#else
  if (argc < 2)
    print_to_socket(connections[connnum].socket, 
		    "Usage %s <wildcarded ip>", argv[0]);
  else
    list_virtual_users(connections[connnum].socket, argv[1], NO);
#endif
}

void
m_class(int connnum, int argc, char *argv[])
{
  if (argc < 2)
    print_to_socket(connections[connnum].socket,
		    "Usage: %s <class name>", argv[0]);
  else
    list_class(connections[connnum].socket, argv[1], NO);
}

void
m_classt(int connnum, int argc, char *argv[])
{
  if (argc < 2)
    print_to_socket(connections[connnum].socket,
		    "Usage: %s <class name>", argv[0]);
  else
    list_class(connections[connnum].socket, argv[1], YES);
}

void
m_killlist(int connnum, int argc, char *argv[])
{
  char reason[MAX_REASON];

#ifdef HAVE_REGEX_H
  if ((argc < 2) || (argc > 2 && strcasecmp(argv[1], "-r")))
  {
    print_to_socket(connections[connnum].socket,
		    "Usage: %s [-r] <wildcarded/regex userhost>", argv[0]);
    return;
  }
  if (argc >= 4)
  {
    expand_args(reason, MAX_REASON-1, argc-3, argv+3);
  }
#else
  if (argc < 2)
  {
    print_to_socket(connections[connnum].socket,
         "Usage: %s <wildcarded userhost>", argv[0]);
    return;
  }
  if (argc >= 3)
  {
    expand_args(reason, sizeof(reason)-1, argc-3, argv+3);
  }
  else
    snprintf(reason, sizeof(reason), "No reason");
#endif
  if (!(connections[connnum].type & (TYPE_INVS|TYPE_INVM)))
  {
    strncat(reason, " (requested by ", sizeof(reason)-strlen(reason));
    strncat(reason, connections[connnum].registered_nick,
            sizeof(reason)-strlen(reason));
    strncat(reason, ")", sizeof(reason)-strlen(reason));
  }
#ifdef HAVE_REGEX_H
  if (strcasecmp(argv[1], "-r"))
  {
    send_to_all( SEND_ALL, "*** killlist %s :%s by %s", argv[1],
                 reason, connections[connnum].registered_nick);
    kill_list_users(connections[connnum].socket, argv[1], reason, NO);
  }
  else
  {
    send_to_all( SEND_ALL, "*** killlist %s :%s by %s", argv[2],
                 reason, connections[connnum].registered_nick);
    kill_list_users(connections[connnum].socket, argv[2], reason, YES);
  }
#else
  send_to_all( SEND_ALL, "*** killlist %s :%s by %s", argv[1],
               reason, connections[connnum].registered_nick);
  kill_list_users(connections[connnum].socket, argv[1], reason, NO);
#endif
}

void
m_kline(int connnum, int argc, char *argv[])
{
  char buff[MAX_BUFF];
  int kline_time;

  if (argc < 3)
    print_to_socket(connections[connnum].socket,
         "Usage: %s [time] <[nick]|[user@host]> [reason]", argv[0]);
  else
  {
    if ((kline_time = atoi(argv[1])))
    {
      if (argc >= 4)
      {
	expand_args(buff, MAX_BUFF-1, argc-3, argv+3);
      }
      else
        snprintf(buff, sizeof(buff), "No reason");
      do_a_kline("kline", kline_time, argv[2], buff, 
                 connections[connnum].registered_nick);
    }
    else
    {
      if (argc >= 3)
      {
	expand_args(buff, MAX_BUFF-1, argc-3, argv+3);
      }
      do_a_kline("kline", 0, argv[1], buff,
		 connections[connnum].registered_nick);
    }
  }
}

void
m_kperm(int connnum, int argc, char *argv[])
{
  if (argc < 2)
    print_to_socket(connections[connnum].socket,
         "Usage: %s [time] <[nick]|[user@host]>", argv[0]);
  else
    do_a_kline("kperm", 0, argv[1], REASON_KPERM, 
               connections[connnum].registered_nick);
}

void
m_kill(int connnum, int argc, char *argv[])
{
  char reason[1024];

  if (argc < 2)
  {
    print_to_socket(connections[connnum].socket,
         "Usage: %s <nick|user@host> [reason]", argv[0]);
    return;
  }
  else if (argc == 2)
    snprintf(reason, sizeof(reason), "No reason");
  else
  {
    expand_args(reason, sizeof(reason)-1, argc-2, argv+2);
  }
  send_to_all( SEND_KLINE_NOTICES, "*** kill %s :%s by %s",
               argv[1], reason, connections[connnum].registered_nick);
  log_kline("KILL", argv[1], 0, connections[connnum].registered_nick, reason);
  if (!(connections[connnum].type & (TYPE_INVS|TYPE_INVM)))
  {
    strncat(reason, " (requested by ", sizeof(reason)-strlen(reason));
    strncat(reason, connections[connnum].registered_nick,
            sizeof(reason)-strlen(reason));
    strncat(reason, ")", sizeof(reason)-strlen(reason));
  }
  print_to_server("KILL %s :%s", argv[1], reason);
}

void
m_use_kaction(int connnum, int argc, char *argv[])
{
  print_to_socket(connections[connnum].socket,
		  "%s is deprecated, please use .kaction", argv[0]);

}

void
m_kaction(int connnum, int argc, char *argv[])
{
  int actionid;
  int kline_time = 0;
  char *who, *host;

  if (argc < 3)
    {
      print_to_socket(connections[connnum].socket,
		      "Usage: %s action [time] <[nick]|[user@host]>",
		      argv[0]);
      return;
    } 

  actionid = find_action(argv[1]);
  if (actionid < 0)
    {
      print_to_socket(connections[connnum].socket,
		      "%s is not a valid action", argv[1]);
      return;
    }
  
  if (argc == 4)
    {
      if (actions[actionid].method & METHOD_TKLINE)
	{
	  kline_time = atoi(argv[2]);
	  if (!kline_time)
	    {
	      print_to_socket(connections[connnum].socket,
			      "%s is not a valid k-line time", argv[2]);
	      return;
	    }
	}
      else
	{
	  print_to_socket(connections[connnum].socket,
 "The %s action is not configured to use temporary k-lines, k-line time will be ignored\n", argv[1]);
	}
      who = argv[3];
    }
  else
    who = argv[2];
  
  if ((host = strchr(who, '@')))
    *host++=0;

  handle_action(actionid, 0, host ? "" : who, host ? who : 0, host ? host : 0, 0, "Manually set");
}


void
m_hmulti(int connnum, int argc, char *argv[])
{
  int t;

  if (argc >= 2)
  {
    if ((t = atoi(argv[1])) < 3)
    {
      print_to_socket(connections[connnum].socket,
           "Using a threshold less than 3 is forbidden, changed to 3\n");
      t = 3;
    }
  }
  else
    t = 3;
  report_multi_host(connections[connnum].socket, t);
}

void
m_umulti(int connnum, int argc, char *argv[])
{
  int t;

  if (argc >= 2)
  {
    if ((t = atoi(argv[1])) < 3)
    {
      print_to_socket(connections[connnum].socket,
           "Using a threshold less than 3 is forbidden, changed to 3\n");
      t = 3;
    }
  }
  else
    t = 3;
  report_multi_user(connections[connnum].socket, t);
}

void
m_register(int connnum, int argc, char *argv[])
{
  if (connections[connnum].type & TYPE_OPER)
  {
    print_to_socket(connections[connnum].socket, 
		    "You are already registered.");
    return;
  }

  if (argc != 2)
    print_to_socket(connections[connnum].socket,
		    "Usage: %s <password>", argv[0]);
  else
    register_oper(connnum, argv[1], connections[connnum].nick);
}

void m_opers(int connnum, int argc, char *argv[])
{
  list_opers(connections[connnum].socket);
}

void
m_testline(int connnum, int argc, char *argv[])
{
  if (argc < 2)
  {
    print_to_socket(connections[connnum].socket,
		    "Usage: %s <mask>", argv[0]);
    return;
  }
  if (strcasecmp(argv[1], testlines.umask) == 0)
  {
    print_to_socket(connections[connnum].socket,
		    "Already pending %s", argv[1]);
    return;
  }
  snprintf(testlines.umask, sizeof(testlines.umask), "%s", argv[1]);
  testlines.index = connnum;
  print_to_server("TESTLINE %s", argv[1]);
}

void
m_actions(int connnum, int argc, char *argv[])
{
  print_to_socket(connections[connnum].socket,
		  "%s is deprecated, use .action", argv[0]);
}

void
m_action(int connnum, int argc, char *argv[])
{
  int kline_time, i;
  char methods[MAX_BUFF], reason[MAX_BUFF];

  switch (argc)
  {
    /* .action */
    case 1:
      set_actions(connections[connnum].socket, NULL, NULL, 0, NULL);
      break;
    /* .action clone */
    /* .action *c* */
    case 2:
      set_actions(connections[connnum].socket, argv[1], NULL, 0, NULL);
      break;
    /* .action clone :Cloning is prohibited */
    /* .action clone kline */
    /* .action clone kline :Cloning */
    /* .action clone kline 1440 ircwarn dccwarn :Cloning is prohibited*/        
    default:
      /* Scan up to first ':' (extracting first found number if any)
	 and make two strings; methods & reason */
      kline_time = 0;
      methods[0] = 0;
      reason[0] = 0;
      for (i=2;i<argc;i++)
	{
	  if (argv[i][0]==':')
	    {
	      snprintf(reason, sizeof(reason), "%s ", argv[i]+1);
	      for (;i<argc;i++)
		{
		  strncat(reason, argv[i], sizeof(reason));
		  strncat(reason, " ", sizeof(reason));
		}
	      break;
	    }
	  if ((!kline_time) && (atoi(argv[i])>0))
	    {
	      kline_time = atoi(argv[i]);
	    }
	  else
	    {
	      strncat(methods, argv[i], sizeof(methods));
	      strncat(methods, " ", sizeof(methods));
	    }
	}
      i = strlen(methods);
      if (i && (methods[i-1]==' '))
	methods[i-1] = 0;
      i = strlen(reason);
      if (i && (reason[i-1]==' '))
	reason[i-1] = 0;
      set_actions(connections[connnum].socket, argv[1], 
		  methods[0] ? methods : NULL, 
		  kline_time, 
		  reason[0] ? reason : NULL);
      break;
  }
}

void
m_set(int connnum, int argc, char *argv[])
{
  if (argc < 2)
  {
    if (connections[connnum].set_modes & SET_PRIVMSG)
      print_to_socket(connections[connnum].socket, "MESSAGES");
    else
      print_to_socket(connections[connnum].socket, "NOMESSAGES");
    if (connections[connnum].set_modes & SET_NOTICES)
      print_to_socket(connections[connnum].socket, "NOTICES");
    else
      print_to_socket(connections[connnum].socket, "NONOTICES");
    return;
  }
  if ((strcasecmp(argv[1],"MESSAGES")) == 0)
  {
    connections[connnum].set_modes |= SET_PRIVMSG;
    print_to_socket(connections[connnum].socket,
		    "You will see privmsgs sent to tcm");
  }
  else if ((strcasecmp(argv[1],"NOMESSAGES")) == 0)
  {
    connections[connnum].set_modes &= ~SET_PRIVMSG;
    print_to_socket(connections[connnum].socket,
		    "You will not see privmsgs sent to tcm");
  }
  else if ((strcasecmp(argv[1],"NOTICES")) == 0)
  {
    connections[connnum].set_modes |= SET_NOTICES;
    print_to_socket(connections[connnum].socket,
		    "You will see selected server notices");
  }
  else if ((strcasecmp(argv[1],"NONOTICES")) == 0)
  {
    connections[connnum].set_modes &= ~SET_NOTICES;
    print_to_socket(connections[connnum].socket,
		    "You will not see server notices");
  }
  else
  {
    print_to_socket(connections[connnum].socket,
		    "Usage: .set [MESSAGES|NOMESSAGES]");
    print_to_socket(connections[connnum].socket,
		    "Usage: .set [NOTICES|NONOTICES]");
  }
}

void
m_uptime(int connnum, int argc, char *argv[])
{
  report_uptime(connections[connnum].socket);
}

void m_exemptions(int connnum, int argc, char *argv[])
{
  list_exemptions(connections[connnum].socket);
}

void
m_umode(int connnum, int argc, char *argv[])
{
  if (argc < 2)
  {
    print_to_socket(connections[connnum].socket,
		    "Your current flags are: %s",
         type_show(connections[connnum].type));
    return;
  }
  if (argc >= 3)
  {
    if (!(connections[connnum].type & TYPE_ADMIN))
    {
      print_to_socket(connections[connnum].socket, "You aren't an admin");
      return;
    }
    if ((argv[2][0] == '+') || (argv[2][0] == '-'))
      set_umode(connnum,argv[2],argv[1]);
    else
        print_to_socket(connections[connnum].socket,
             ".umode [user flags] | [user] | [flags]");
  }
  else
  {
    if ((argv[1][0] == '+') || (argv[1][0] == '-'))
      set_umode(connnum, argv[1], NULL);
    else
    {
      if (!(connections[connnum].type & TYPE_ADMIN))
        {
          print_to_socket(connections[connnum].socket,
			  "You aren't an admin");
          return;
        }
      show_user_umodes(connections[connnum].socket,argv[1]);
    }
  }
}

void
m_connections(int connnum, int argc, char *argv[])
{
  list_connections(connections[connnum].socket);
}

void
m_disconnect(int connnum, int argc, char *argv[])
{
  if (argc < 2)
    print_to_socket(connections[connnum].socket,
		    "Usage: %s <nick>", argv[0]);
  else
    handle_disconnect(connections[connnum].socket, argv[1],
                      connections[connnum].registered_nick);
}

void
m_help(int connnum, int argc, char *argv[])
{
  if (argc < 2)
    print_to_socket(connections[connnum].socket, 
		    "Usage: %s ?", argv[0]);
  else
    print_help(connections[connnum].socket, argv[1]);
}

void
m_motd(int connnum, int argc, char *argv[])
{
  print_motd(connections[connnum].socket);
}

void
m_save(int connnum, int argc, char *argv[])
{
  handle_save(connections[connnum].socket, 
              connections[connnum].registered_nick);
}

void
m_close(int connnum, int argc, char *argv[])
{
  print_to_socket(connections[connnum].socket, "Closing connection");
  closeconn(connnum, 0, NULL);
}

void
m_op(int connnum, int argc, char *argv[])
{
  if (argc < 2)
    print_to_socket(connections[connnum].socket,
		    "Usage: %s <nick>", argv[0]);
  else
    op(config_entries.defchannel, argv[1]);
}

void
m_cycle(int connnum, int argc, char *argv[])
{
  leave(config_entries.defchannel);
  send_to_all( SEND_ALL, "I'm cycling.  Be right back.\n");
  sleep(1);
  /* probably on a cycle, we'd want the tcm to set
   * the key as well...
   */
  join(config_entries.defchannel, config_entries.defchannel_key);
  set_modes(config_entries.defchannel, config_entries.defchannel_mode,
            config_entries.defchannel_key);
}

void
m_die(int connnum, int argc, char *argv[])
{
  send_to_all( SEND_ALL, "I've been ordered to quit irc, goodbye.");
  print_to_server("QUIT :Dead by request!");
  log("DIEd by oper %s\n", connections[connnum].registered_nick);
  exit(1);
}

void
m_restart(int connnum, int argc, char *argv[])
{
  send_to_all( SEND_ALL, "I've been ordered to restart.");
  print_to_server("QUIT :Restart by request!");
  log("RESTART by oper %s", connections[connnum].registered_nick);
  sleep(1);
  execv(SPATH, NULL);
}

void
m_info(int connnum, int argc, char *argv[])
{
  print_to_socket(connections[connnum].socket, "real server name [%s]",
       config_entries.rserver_name);
  if (config_entries.hybrid)
    print_to_socket(connections[connnum].socket, "Hybrid server version %d",
         config_entries.hybrid_version);
  else
    print_to_socket(connections[connnum].socket, "Non hybrid server");
}

void
m_locops(int connnum, int argc, char *argv[])
{
  char *p, dccbuff[MAX_BUFF];
  int i, len;

  if(argc >= 2)
  {
    p = dccbuff;
    for (i = 1; i < argc; i++)
    {
      len = sprintf(p, "%s ", argv[i]);
      p += len;
    }
    /* blow away last ' ' */
    *--p = '\0';
    if (dccbuff[0] == ':')
      print_to_server("LOCOPS :(%s) %s", connections[connnum].nick, dccbuff+1);
    else
      print_to_server("LOCOPS :(%s) %s", connections[connnum].nick, dccbuff);
  }
  else
    print_to_socket(connections[connnum].socket,
         "Really, it would help if you said something");
}

void
m_unkline(int connnum, int argc, char *argv[])
{
  if (argc < 2)
    print_to_socket(connections[connnum].socket, 
		    "Usage: %s <user@host>", argv[0]);
  else
  {
    log("UNKLINE %s attempted by oper %s", argv[1],
        connections[connnum].registered_nick);
    send_to_all( SEND_KLINE_NOTICES, "UNKLINE %s attempted by oper %s", 
                 argv[1], connections[connnum].registered_nick);
    print_to_server("UNKLINE %s",argv[1]);
  }
}

void
m_vbots(int connnum, int argc, char *argv[])
{
  if (argc >= 2)
    report_vbots(connections[connnum].socket, atoi(argv[1]));
  else
    report_vbots(connections[connnum].socket, 3);
}

#ifndef NO_D_LINE_SUPPORT
void
m_dline(int connnum, int argc, char *argv[])
{
  char *p, reason[MAX_BUFF];
  int i, len;

  if (!(connections[connnum].type & TYPE_DLINE))
  {
    print_to_socket(connections[connnum].socket,
		    "You do not have access to .dline");
    return;
  }
  if (argc >= 3)
  {
    p = reason;
    for (i = 2; i < argc; i++)
    {
      len = sprintf(p, "%s ", argv[i]);
      p += len;
    }
    /* blow away last ' ' */
    *--p = '\0';
    if (reason[0] == ':')
      log_kline("DLINE", argv[1], 0, connections[connnum].registered_nick, 
                reason+1);
    else
      log_kline("DLINE", argv[1], 0, connections[connnum].registered_nick,
                reason);
    send_to_all( SEND_ALL, "*** dline %s :%s by %s", argv[1],
                 reason, connections[connnum].registered_nick);
    if (!connections[connnum].type & (TYPE_INVS|TYPE_INVM))
    {
      strncat(reason, " (requested by ", sizeof(reason)-strlen(reason));
      strncat(reason, connections[connnum].nick,
              sizeof(reason)-strlen(reason));
      strncat(reason, ")", sizeof(reason)-strlen(reason));
    }
    print_to_server("DLINE %s :%s", argv[1], reason);
  }
}
#endif

#ifdef ENABLE_QUOTE
void
m_quote(int connnum, int argc, char *argv[])
{
  char *p, dccbuff[MAX_BUFF];
  int i, len;

  if (argc < 2)
  {
    print_to_socket(connections[connnum].socket,
		    "Usage: %s <server message>", 
         argv[0]);
    return;
  }
  p = dccbuff;
  for (i = 1; i < argc; i++)
  {
    len = sprintf(p, "%s ", argv[i]);
    p += len;
  }
  /* blow away last ' ' */
  *--p = '\0';
  print_to_server("%s", dccbuff);
}
#endif

void
m_mem(int connnum, int argc, char *argv[])
{
  report_mem(connections[connnum].socket);
}

void
m_clones(int connnum, int argc, char *argv[])
{
  report_clones(connections[connnum].socket);
}

void m_nflood(int connnum, int argc, char *argv[])
{
  report_nick_flooders(connections[connnum].socket);
}

void
m_rehash(int connnum, int argc, char *argv[])
{
  send_to_all( SEND_ALL,
	       "*** rehash requested by %s", 
               connections[connnum].registered_nick[0] ?
               connections[connnum].registered_nick :
               connections[connnum].nick);

  if (config_entries.hybrid && (config_entries.hybrid_version >= 6))
    {
      print_to_server("STATS I");
      print_to_server("STATS Y");
    }
  else
    {
      print_to_server("STATS E");
      print_to_server("STATS F");
      print_to_server("STATS Y");
    }

  initopers();
}

void
m_trace(int connnum, int argc, char *argv[])
{
  send_to_all( SEND_ALL,
	       "Trace requested by %s",
               connections[connnum].registered_nick[0] ?
               connections[connnum].registered_nick :
               connections[connnum].nick);

  inithash();
  print_to_server("STATS Y");
}

void
m_failures(int connnum, int argc, char *argv[])
{
  if (argc < 2)
    report_failures(connections[connnum].socket, 7);
  else if (atoi(argv[1]) < 1)
    print_to_socket(connections[connnum].socket,
		    "Usage: %s [min failures]", argv[0]);
  else
    report_failures(connections[connnum].socket, atoi(argv[1]));
}

void
m_domains(int connnum, int argc, char *argv[])
{
  if (argc < 2)
    report_domains(connections[connnum].socket, 5);
  else if (atoi(argv[1]) < 1)
    print_to_socket(connections[connnum].socket,
		    "Usage: %s [min users]", argv[0]);
  else
    report_domains(connections[connnum].socket, atoi(argv[1]));
}

void
m_bots(int connnum, int argc, char *argv[])
{
  if (argc >= 2)
    report_multi(connections[connnum].socket, atoi(argv[1]));
  else
    report_multi(connections[connnum].socket, 3);
}

void
m_events(int connnum, int argc, char *argv[])
{
  show_events(connections[connnum].socket);
}

#ifdef VIRTUAL
void m_vmulti(int connnum, int argc, char *argv[])
{
  if (argc >= 2)
    report_multi_virtuals(connections[connnum].socket, atoi(argv[1]));
  else
    report_multi_virtuals(connections[connnum].socket, 3);
}
#endif

void
m_nfind(int connnum, int argc, char *argv[])
{
#ifdef HAVE_REGEX_H
  if ((argc < 2) || (argc > 2 && strcasecmp(argv[1], "-r")))
    print_to_socket(connections[connnum].socket,
		    "Usage: %s [-r] <wildcarded/regexp nick>", argv[0]);
  else if (argc == 2)
    list_nicks(connections[connnum].socket, argv[1], NO);
  else
    list_nicks(connections[connnum].socket, argv[2], YES);
#else
  if (argc <= 2)
    print_to_socket(connections[connnum].socket,
		    "Usage: %s <wildcarded nick>", argv[0]);
  else
    list_nicks(connections[connnum].socket, argv[1], NO);
#endif
} 

void
m_list(int connnum, int argc, char *argv[])
{
#ifdef HAVE_REGEX_H
  if ((argc < 2) || (argc > 2 && strcasecmp(argv[1], "-r")))
    print_to_socket(connections[connnum].socket,
         "Usage: %s [-r] <wildcarded/regex userhost>", argv[0]);
  else if (argc == 2)
    list_users(connections[connnum].socket, argv[1], NO);
  else
    list_users(connections[connnum].socket, argv[2], YES);
#else
  if (argc < 2)
    print_to_socket(connections[connnum].socket,
		    "Usage: %s <wildcarded userhost>",
         argv[0]);
  else
    list_users(connections[connnum].socket, argv[1], NO);
#endif
}

#ifdef WANT_ULIST
void
m_ulist(int connnum, int argc, char *argv[])
{
  char buf[MAX_BUFF];

#ifdef HAVE_REGEX_H
  if ((argc < 2) || (argc > 2 && strcasecmp(argv[1], "-r")))
    print_to_socket(connections[connnum].socket,
         "Usage: %s [-r] <wildcarded/regex username>", argv[0]);
  else if (argc == 2)
  {
    snprintf(buf, MAX_BUFF, "%s@*", argv[1]);
    list_users(connections[connnum].socket, buf, NO);
  }
  else
  {
    snprintf(buf, MAX_BUFF, "%s@*", argv[2]);
    list_users(connections[connnum].socket, buf, YES);
  }
#else
  if (argc < 2)
    print_to_socket(connections[connnum].socket,
		    "Usage: %s <wildcarded username>",
         argv[0]);
  else
  {
    snprintf(buf, MAX_BUFF, "%s@*", argv[1]);
    list_users(connections[connnum].socket, argv[1], NO);
  }
#endif
}
#endif

#ifdef WANT_HLIST
void
m_hlist(int connnum, int argc, char *argv[])
{
  char buf[MAX_BUFF];

#ifdef HAVE_REGEX_H
  if ((argc < 2) || (argc > 2 && strcasecmp(argv[1], "-r")))
    print_to_socket(connections[connnum].socket,
         "Usage: %s [-r] <wildcarded/regex host>", argv[0]);
  else if (argc == 2)
  {
    snprintf(buf, MAX_BUFF, "*@%s", argv[1]);
    list_users(connections[connnum].socket, buf, NO);
  }
  else
  {
    snprintf(buf, MAX_BUFF, "*@%s", argv[2]);
    list_users(connections[connnum].socket, buf, YES);
  }
#else
  if (argc < 2)
    print_to_socket(connections[connnum].socket, 
		    "Usage: %s <wildcarded host>",
         argv[0]);
  else
  {
    snprintf(buf, MAX_BUFF, "*@%s", argv[1]);
    list_users(connections[connnum].socket, argv[1], NO);
  }
#endif
}
#endif

/*
** dccproc()
**   Handles processing of dcc chat commands
*/
void 
dccproc(int connnum, int argc, char *argv[])
{
  char buff[MAX_BUFF];
  char dccbuff[MAX_BUFF];
  char who_did_command[2*MAX_NICK];
  int len;
  int i;
  char *buffer, *p;

  if (argv[0][0] == '.')
  {
    print_to_socket(connections[connnum].socket, 
		    "Unknown command [%s]", argv[0]+1);
    return;
  }
  p = buff;
  for (i = 0; i < argc; i++)
  {
    len = sprintf(p, "%s ", argv[i]);
    p += len;
  }
  /* blow away last ' ' */
  *--p = '\0';

  buffer=buff;

  who_did_command[0] = '\0';

  snprintf(dccbuff, sizeof(dccbuff) - 1,"<%s@%s> %s",
           connections[connnum].nick, config_entries.dfltnick, buffer);

  if(connections[connnum].type & TYPE_PARTYLINE)
    send_to_all( SEND_ALL, "%s", dccbuff);
  else
  {
    print_to_socket(connections[connnum].socket,
                    "You are not +p, not sending to chat line");
  }

  return;
}

/*
 * set_actions
 *
 * inputs	- 
 * output	- NONE
 * side effects -
 */

static void 
set_actions(int sock, char *key, char *methods, int duration, char *reason)
{
  int i;
  char * p;
  int newmethods = 0;
  int changing = (methods || duration || reason);

  while (methods)
    {
      p = strchr(methods, ' ');
      if (p) 
	*p++ = 0;
      /* Lookup method constant based on method name */
      i = get_method_number(methods);
      if (i)
	{
	  newmethods |= i;
	}
      else
	{
	  print_to_socket(sock, "%s is not a valid method", methods);
	  return;
	}
      methods = p;
    }

  if (key == NULL)
    key = "*";
  if (changing)
    {
      print_to_socket(sock, "Updating actions matching '%s'", key);
    }
  else
    {
      print_to_socket(sock, "Listing actions matching '%s'", key);
    }

  for (i=0; i<MAX_ACTIONS; i++)
    {
      if (actions[i].name[0])
	{
	  if (!wldcmp(key, actions[i].name))
	    {
	      if (newmethods) 
		set_action_method(i, newmethods);
	      if (reason)
		set_action_reason(i, reason);
	      if (duration)
		set_action_time(i, duration);
	
	      if (changing)
		{
		  print_to_socket(
				  sock,
			  "%s action now: %s, duration %d, reason '%s'",
				  actions[i].name,
				  get_method_names(actions[i].method),
				  actions[i].klinetime,
				  actions[i].reason);
		}
	      else
		{
		  print_to_socket(
				  sock,
				  "%s action: %s, duration %d, reason '%s'",
				  actions[i].name,
				  get_method_names(actions[i].method),
				  actions[i].klinetime,
				  actions[i].reason);
		}
	    }
	}
    }
}

/*
 * set_umode
 *
 * inputs	- connection number
 * 		- flags as string
 * 		- nick to change, or NULL if self
 * output	- NONE
 * side effects	-
 */

static void 
set_umode(int connnum, char *flags, char *registered_nick)
{
  int i;
  int reversing = NO;
  int z;
  int found = NO;
  unsigned long type;
  unsigned long new_type;

  /* UMODE! -bill */
  
  if(!registered_nick)
  {
    for( i=0; flags[i]; i++ )
    {
      switch(flags[i])
      {
      case 'e': type = TYPE_ECHO; break;
      case 'i': type = TYPE_INVS; break;
      case 'k': type = TYPE_VIEW_KLINES; break;
      case 'y': type = TYPE_SPY; break;
      case 'o': type = TYPE_LOCOPS; break;
      case 'p': type = TYPE_PARTYLINE; break;
      case 'w': type = TYPE_WARN; break;
      case 'x': type = TYPE_SERVERS; break;

      case 'I':
	if (connections[connnum].type & TYPE_ADMIN)
	  type = TYPE_INVM ;
	else
	  type = 0;
	break;

#ifndef NO_D_LINE_SUPPORT
      case 'D':
	if (connections[connnum].type & TYPE_ADMIN)
	  type = TYPE_DLINE ;
	else
	  type = 0;
	break;
#endif

      case 'G':
	if (connections[connnum].type & TYPE_ADMIN)
	  type = TYPE_GLINE ;
	else
	  type = 0;
	break;

#ifdef ENABLE_W_FLAG
      case 'W':
        if (connections[connnum].type & TYPE_ADMIN)
          type = TYPE_OPERWALL ;
        else
          type = 0;
#endif

      case '-':
	type = 0;
	reversing=YES;
	break;

      case '+':
	type = 0;
	reversing=NO;
	break;

      default:
	type = 0;
	break;
      }

      if (reversing)
	connections[connnum].type &= ~type;
      else
	connections[connnum].type |= type;
    }

    print_to_socket(connections[connnum].socket,
	 "Your flags are now: +%s",
	 type_show(connections[connnum].type));

    save_umodes(connections[connnum].registered_nick,
		connections[connnum].type);
  }
  else /* only called if ADMIN */
  {
    for(z=0;z<MAXDCCCONNS;++z)
    {
      if(found)
	break;

      if (strcasecmp(registered_nick, connections[z].registered_nick) == 0)
      {
	found = YES;
	
	for(i=0; flags[i] ;i++)
	{
	  switch(flags[i])
	  {
#ifndef NO_D_LINE_SUPPORT
	  case 'D': type = TYPE_DLINE; break;
#endif
	  case 'G': type = TYPE_GLINE; break;
	  case 'I': type = TYPE_INVM; break;
	  case 'K': type = TYPE_KLINE; break;
	  case 'S': type = TYPE_SUSPENDED; break;
#ifdef ENABLE_W_FLAG
          case 'W': type = TYPE_OPERWALL; break;
#endif
	  case 'e': type = TYPE_ECHO; break;
	  case 'i': type = TYPE_INVS; break;
	  case 'k': type = TYPE_VIEW_KLINES; break;
          case 'y': type = TYPE_SPY; break;
	  case 'o': type = TYPE_LOCOPS; break;
	  case 'p': type = TYPE_PARTYLINE; break;
	  case 'w': type = TYPE_WARN; break;
          case 'x': type = TYPE_SERVERS; break;
	  case '-':
	    reversing=YES;
	    type = 0;
	    break;
	  case '+':
	    reversing=NO;
	    type = 0;
	    break;
	  default:
	    type = 0;
	    break;
	  }

	  /* don't let an admin suspend an admin */
	  
	  if( (connections[z].type & TYPE_ADMIN) &&
	      (type&TYPE_SUSPENDED))
	    continue;

	  if(type)
	  {
	    if (!reversing)
	      connections[z].type |= type;
	    else
	      connections[z].type &= ~type;
	  }
	}

	print_to_socket(connections[connnum].socket,
			"Flags for %s are now: +%s",
			registered_nick, type_show(connections[z].type));

	print_to_socket(connections[z].socket,
			"Flags for you changed by %s are now: +%s",
			connections[connnum].nick,
			type_show(connections[z].type));
      }
    }

    if(!found)
    {
      new_type=0;

      for(z=0;userlist[z].user[0];z++)
      {
	if(found)
	  break;

	if (strcasecmp(registered_nick, userlist[z].usernick) == 0)
	{
	  found = YES;

	  new_type = userlist[z].type;

	  /* default them to partyline */
	  new_type |= TYPE_PARTYLINE;

	  /* Only use user.pref if they exist */
	  if( (type = find_user_umodes(registered_nick)) )
	  {
	    new_type &= TYPE_ADMIN;
	    new_type |= type;
	    type = 0;
	  }

	  for(i=0; flags[i] ;i++)
	  {
	    switch(flags[i])
	    {
	    case 'I': type = TYPE_INVM; break;
	    case 'K': type = TYPE_KLINE; break;
	    case 'G': type = TYPE_GLINE; break;
#ifndef NO_D_LINE_SUPPORT
	    case 'D': type = TYPE_DLINE; break;
#endif
	    case 'S': type = TYPE_SUSPENDED; break;
#ifdef ENABLE_W_FLAG
            case 'W': type = TYPE_OPERWALL; break;
#endif
	    case 'k': type = TYPE_VIEW_KLINES; break;
	    case 'p': type = TYPE_PARTYLINE; break;
	    case 'w': type = TYPE_WARN; break;
	    case 'e': type = TYPE_ECHO; break;
	    case 'i': type = TYPE_INVS; break;
            case 'y': type = TYPE_SPY; break;
	    case 'o': type = TYPE_LOCOPS; break;
            case 'x': type = TYPE_SERVERS; break;
	    case '-':
	      reversing=YES;
	      type = 0;
	      break;
	    case '+':
	      reversing=NO;
	      type = 0;
	      break;
	    default:
	      type = 0;
	      break;
	    }
		      
	    if( (new_type & TYPE_ADMIN) &&
		(type&TYPE_SUSPENDED))
	      continue;

	    if (!reversing)
	      new_type |= type;
	    else
	      new_type &= ~type;
	  }
	  
	  print_to_socket(connections[connnum].socket,
	       "Startup flags for %s are now: +%s",
	       registered_nick, type_show(new_type));
	  save_umodes(registered_nick, new_type);
	}
      }
    }
  }
}

/*
 * save_umodes
 *
 * inputs	- registered nick
 *		- flags to save
 * output	- none
 * side effect	- 
 */

static void 
save_umodes(char *registered_nick, unsigned long type)
{
  FILE *fp;
  char user_pref[MAX_BUFF];

  (void)snprintf(user_pref,sizeof(user_pref) - 1,
		 "etc/%s.pref",registered_nick);

  if((fp = fopen(user_pref,"w")) == NULL)
  {
    send_to_all( SEND_ALL, "Couldn't open %s for write", user_pref);
    return;
  }

  fprintf(fp,"%lu\n",
	  type & ~(TYPE_ADMIN|TYPE_PENDING));
  (void)fclose(fp);
}

/*
 * load_umodes
 *
 * input	- connection id 
 * output	- none
 * side effect	- 
 */

static void 
load_umodes(int connect_id)
{
  FILE *fp;
  char user_pref[MAX_BUFF];
  char type_string[32];
  char *p;
  unsigned long type;

  (void)snprintf(user_pref,sizeof(user_pref) - 1,"etc/%s.pref",
                connections[connect_id].registered_nick);

  if((fp = fopen(user_pref,"r")) == NULL)
  {
    if((fp = fopen(user_pref,"w")) == NULL)
    {
      send_to_all( SEND_ALL, "Couldn't open %s for write", user_pref);
      return;
    }
    type = connections[connect_id].type;
    fprintf(fp,"%lu\n", type & ~(TYPE_ADMIN|TYPE_PENDING));
    (void)fclose(fp);
    return;
  }

  fgets(type_string,30,fp);
  (void)fclose(fp);

  if((p = strchr(type_string,'\n')) != NULL)
    *p = '\0';
  
  sscanf(type_string,"%lu",&type);
  type &= ~(TYPE_ADMIN|TYPE_PENDING);

  connections[connect_id].type &= TYPE_ADMIN;
  connections[connect_id].type |= type;

  if( type & TYPE_SUSPENDED )
  {
    type = type & TYPE_SUSPENDED;
  }

  print_to_socket(connections[connect_id].socket, 
		  "Set umodes from %s", user_pref );
  print_to_socket(connections[connect_id].socket,
		  "Your current flags are now: %s",
       type_show(connections[connect_id].type));
}

/*
 * find_user_umodes
 *
 * input	- registered nick
 * output	- none
 * side effect	- 
 */

static unsigned long 
find_user_umodes(char *registered_nick)
{
  FILE *fp;
  char user_pref[MAX_BUFF];
  char type_string[32];
  char *p;
  int  unsigned long type;

  (void)snprintf(user_pref,sizeof(user_pref) - 1,
		 "etc/%s.pref",registered_nick);

  if ((fp = fopen(user_pref,"r")) == NULL)
  {
    return 0L;
  }

  if ((fgets(type_string,30,fp)) == NULL)
  {
    (void)fclose(fp);
    return 0L;
  }

  (void)fclose(fp);

  if((p = strchr(type_string,'\n')) != NULL)
    *p = '\0';

  sscanf(type_string,"%lu",&type);

  type &= ~(TYPE_ADMIN|TYPE_PENDING);

  return type;
}

/*
 * show_user_umodes
 *
 * input	- registered nick
 * output	- none
 * side effect	- 
 */

static void 
show_user_umodes(int sock, char *registered_nick)
{
  FILE *fp;
  char user_pref[MAX_BUFF];
  char type_string[32];
  int  i;
  unsigned long type = 0;
  unsigned long pref_type;
  char *p;
  int  found = NO;

  for(i=0; userlist[i].user[0]; i++)
  {
    if (strcasecmp(registered_nick, userlist[i].usernick) == 0)
    {
      type = userlist[i].type;
      found = YES;
      break;
    }
  }

  if(!found)
  {
    print_to_socket(sock,"Can't find user [%s]", registered_nick );
    return;
  }
     
  (void)snprintf(user_pref,sizeof(user_pref) - 1,
		 "etc/%s.pref",registered_nick);

  if((fp = fopen(user_pref,"r")) == NULL)
  {
    print_to_socket(sock,"%s user flags are %s", 
	 registered_nick,
	 type_show(type));
    return;
  }

  type &= TYPE_ADMIN ;

  fgets(type_string,30,fp);
  (void)fclose(fp);

  if((p = strchr(type_string,'\n')) != NULL)
    *p = '\0';

  sscanf(type_string,"%lu",&pref_type);

  pref_type &= ~(TYPE_ADMIN|TYPE_PENDING);

  print_to_socket(sock,"%s user flags are %s", 
       registered_nick,
       type_show(type|pref_type));
}

/*
 * register_oper
 *
 * inputs	- socket
 * 		- password
 *		- who_did_command
 * output	- NONE
 * side effects	- user is warned they aren't an oper
 */

static void
register_oper(int connnum, char *password, char *who_did_command)
{
  if (password)
  {
    if (islegal_pass(connnum, password))
    {
      load_umodes(connnum);
	  
      if (connections[connnum].type & TYPE_SUSPENDED)
      {
	print_to_socket(connections[connnum].socket,
	     "You are suspended");
	send_to_all(SEND_ALL, "%s is suspended", who_did_command);
	if (connections[connnum].type & TYPE_PENDING)
	  connections[connnum].type &= ~TYPE_PENDING;
      }
      else
      {
	print_to_socket(connections[connnum].socket,
	                "You are now registered");
	send_to_all(SEND_ALL, "%s has registered", who_did_command);

	if (connections[connnum].type & TYPE_PENDING)
	  connections[connnum].type &= ~TYPE_PENDING;

	connections[connnum].type |= TYPE_OPER;
      }
    }
    else
    {
      print_to_socket(connections[connnum].socket,"illegal password");
      send_to_all(SEND_ALL, "illegal password from %s", who_did_command);
    }
  }
  else
  {
    print_to_socket(connections[connnum].socket,"missing password");
  }
}

/*
 * list_opers
 *
 * inputs	- socket
 * output	- NONE
 * side effects	- list current opers on socket
 */

static void 
list_opers(int sock)
{
  int i;
  
  for (i=0; i<MAXUSERS; i++)
  {
    if(userlist[i].user[0] == 0)
      break;

    print_to_socket(sock,
	 "(%s) %s@%s %s\n",
	 (userlist[i].usernick) ? userlist[i].usernick:"unknown",
	 userlist[i].user,
	 userlist[i].host,
	 type_show(userlist[i].type));
  }
}

/*
 * list_exemptions
 *
 * inputs	- socket
 * output	- NONE
 * side effects	- list current exemptions on socket
 */

static void 
list_exemptions(int sock)
{
  int i, n;
  char buf[512];

  for (i=0; i<MAXHOSTS; i++)
  {
    if(hostlist[i].host[0] == 0)
      break;
    sprintf(buf, "%s@%s is exempted for:", hostlist[i].user, hostlist[i].host);
    for (n=0;actions[n].name[0];n++)
      if ((1 << n) & hostlist[i].type)
	snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), " %s", actions[n].name);
    print_to_socket(sock,"%s", buf);
  }
}

/*
 * list_connections
 *
 * inputs	- socket
 * output	- NONE
 * side effects	- active connections are listed to socket
 */

static void 
list_connections(int sock)
{
  int i;

  for (i=1; i<maxconns; i++)
  {
    if (connections[i].socket != INVALID)
    {
      if(connections[i].registered_nick[0] != 0)
      {
	print_to_socket(sock,
	     "%s/%s %s (%s@%s) is connected - idle: %ld",
	     connections[i].nick,
	     connections[i].registered_nick,
	     type_show(connections[i].type),
	     connections[i].user,
	     connections[i].host,
	     time((time_t *)NULL)-connections[i].last_message_time );
      }
      else
      {
	print_to_socket(sock,
	     "%s %s (%s@%s) is connected - idle: %ld",
	     connections[i].nick,
	     type_show(connections[i].type),
	     connections[i].user,
	     connections[i].host,
	     time((time_t *)NULL)-connections[i].last_message_time  );
      }
    }
  }
}

/*
 * handle_disconnect
 *
 * inputs	- socket
 *		- who did the command
 * output	- NONE
 * side effects	- disconnect user
 */

static void 
handle_disconnect(int sock, char *nickname, char *who_did_command)
{
  int  i;

  if (nickname == NULL)
    print_to_socket(sock, "Usage: disconnect <nickname>");
  else
  {
    for (i=1; i<maxconns; i++)
      if (sock != INVALID && strcasecmp(nickname,connections[i].nick) == 0)
      {
	print_to_socket(sock, "Disconnecting oper %s", connections[i].nick);
	print_to_socket(sock, "You have been disconnected by oper %s", 
			who_did_command);
	closeconn(i, 0, NULL);
      }
  }
}

/*
 * handle_save
 *
 * inputs	- socket
 *		- nick who did the command
 * output	- NONE
 * side effects	- save tcm prefs
 */

static void 
handle_save(int sock,char *nick)
{
  print_to_socket(sock, "Saving %s file", CONFIG_FILE);
  send_to_all( SEND_ALL, "%s is saving %s", nick, CONFIG_FILE);
  save_prefs();
}

#ifdef IRCD_HYBRID
/*
 * ircd-hybrid-7 loadable module code goes here
 */
#else
struct TcmMessage vlist_msgtab = {
 ".vlist", 0, 0,
 {m_unregistered, m_vlist, m_vlist}
};
struct TcmMessage class_msgtab = {
 ".class", 0, 0,
 {m_unregistered, m_class, m_class}
};
struct TcmMessage classt_msgtab = {
 ".classt", 0, 0,
 {m_unregistered, m_classt, m_classt}
};
struct TcmMessage killlist_msgtab = {
 ".killlist", 0, 0,
 {m_unregistered, m_killlist, m_killlist}
};
struct TcmMessage kline_msgtab = {
 ".kline", 0, 0,
 {m_unregistered, m_kline, m_kline}
};
struct TcmMessage kclone_msgtab = {
 ".kclone", 0, 0,
 {m_unregistered, m_use_kaction, m_use_kaction}
};
struct TcmMessage kflood_msgtab = {
 ".kflood", 0, 0,
 {m_unregistered, m_use_kaction, m_use_kaction}
};
struct TcmMessage kperm_msgtab = {
 ".kperm", 0, 0,
 {m_unregistered, m_kperm, m_kperm}
};
struct TcmMessage klink_msgtab = {
 ".klink", 0, 0,
 {m_unregistered, m_use_kaction, m_use_kaction}
};
struct TcmMessage kdrone_msgtab = {
 ".kdrone", 0, 0,
 {m_unregistered, m_use_kaction, m_use_kaction}
};
struct TcmMessage kbot_msgtab = {
 ".kbot", 0, 0,
 {m_unregistered, m_use_kaction, m_use_kaction}
};
struct TcmMessage kill_msgtab = {
 ".kill", 0, 0,
 {m_unregistered, m_kill, m_kill}
};
struct TcmMessage kaction_msgtab = {
  ".kaction", 0, 0,
 {m_unregistered, m_kaction, m_kaction}
};
struct TcmMessage kspam_msgtab = {
 ".kspam", 0, 0,
 {m_unregistered, m_use_kaction, m_use_kaction}
};
struct TcmMessage hmulti_msgtab = {
 ".hmulti", 0, 0,
 {m_unregistered, m_hmulti, m_hmulti}
};
struct TcmMessage umulti_msgtab = {
 ".umulti", 0, 0,
 {m_unregistered, m_umulti, m_umulti}
};
struct TcmMessage register_msgtab = {
 ".register", 0, 0,
 {m_register, m_register, m_register}
};
struct TcmMessage opers_msgtab = {
 ".opers", 0, 0,
 {m_unregistered, m_opers, m_opers}
};
struct TcmMessage testline_msgtab = {
 ".testline", 0, 0,
 {m_unregistered, m_testline, m_testline}
};
struct TcmMessage actions_msgtab = {
 ".actions", 0, 0,
 {m_actions, m_actions, m_actions}
};
struct TcmMessage action_msgtab = {
 ".action", 0, 0,
 {m_unregistered, m_action, m_action}
};
struct TcmMessage set_msgtab = {
 ".set", 0, 0,
 {m_unregistered, m_set, m_set}
};
struct TcmMessage uptime_msgtab = {
 ".uptime", 0, 0,
 {m_uptime, m_uptime, m_uptime}
};
struct TcmMessage exemptions_msgtab = {
 ".exemptions", 0, 0,
 {m_unregistered, m_exemptions, m_exemptions}
};
struct TcmMessage umode_msgtab = {
 ".umode", 0, 0,
 {m_unregistered, m_umode, m_umode}
};
struct TcmMessage connections_msgtab = {
 ".connections", 0, 0,
 {m_connections, m_connections, m_connections}
};
struct TcmMessage whom_msgtab = {
 ".whom", 0, 0,
 {m_connections, m_connections, m_connections}
};
struct TcmMessage who_msgtab = {
 ".who", 0, 0,
 {m_connections, m_connections, m_connections}
};
struct TcmMessage disconnect_msgtab = {
 ".disconnect", 0, 0,
 {m_unregistered, m_not_admin, m_disconnect}
};
struct TcmMessage quit_msgtab = {
 ".quit", 0, 0,
 {m_close, m_close, m_close}
};
struct TcmMessage help_msgtab = {
 ".help", 0, 0,
 {m_help, m_help, m_help}
};
struct TcmMessage motd_msgtab = {
 ".motd", 0, 0,
 {m_motd, m_motd, m_motd}
};
struct TcmMessage save_msgtab = {
 ".save", 0, 0,
 {m_unregistered, m_not_admin, m_save}
};
struct TcmMessage close_msgtab = {
 ".close", 0, 0,
 {m_close, m_close, m_close}
};
struct TcmMessage op_msgtab = {
 ".op", 0, 0,
 {m_unregistered, m_op, m_op}
};
struct TcmMessage cycle_msgtab = {
 ".cycle", 0, 0,
 {m_unregistered, m_cycle, m_cycle}
};
struct TcmMessage die_msgtab = {
 ".die", 0, 0,
 {m_unregistered, m_not_admin, m_die}
};
struct TcmMessage restart_msgtab = {
 ".restart", 0, 0,
 {m_unregistered, m_not_admin, m_restart}
};
struct TcmMessage info_msgtab = {
 ".info", 0, 0,
 {m_info, m_info, m_info}
};
struct TcmMessage locops_msgtab = {
 ".locops", 0, 0,
 {m_unregistered, m_locops, m_locops}
};
struct TcmMessage unkline_msgtab = {
 ".unkline", 0, 0,
 {m_unregistered, m_unkline, m_unkline}
};
struct TcmMessage vbots_msgtab = {
 ".vbots", 0, 0,
 {m_unregistered, m_vbots, m_vbots}
};
#ifndef NO_D_LINE_SUPPORT
struct TcmMessage dline_msgtab = {
 ".dline", 0, 0,
 {m_unregistered, m_dline, m_dline}
};
#endif
#ifdef ENABLE_QUOTE
struct TcmMessage quote_msgtab = {
 ".quote", 0, 0,
 {m_unregistered, m_not_admin, m_quote}
};
#endif
struct TcmMessage mem_msgtab = {
 ".mem", 0, 0,
 {m_unregistered, m_not_admin, m_mem}
};
struct TcmMessage clones_msgtab = {
 ".clones", 0, 0,
 {m_unregistered, m_clones, m_clones}
};
struct TcmMessage nflood_msgtab = {
 ".nflood", 0, 0,
 {m_unregistered, m_nflood, m_nflood}
};
struct TcmMessage rehash_msgtab = {
 ".rehash", 0, 0,
 {m_unregistered, m_not_admin, m_rehash}
};
struct TcmMessage trace_msgtab = {
 ".trace", 0, 0,
 {m_unregistered, m_trace, m_trace}
};
struct TcmMessage failures_msgtab = {
 ".failures", 0, 0,
 {m_unregistered, m_failures, m_failures}
};
struct TcmMessage domains_msgtab = {
 ".domains", 0, 1,
 {m_unregistered, m_domains, m_domains}
};
struct TcmMessage bots_msgtab = {
 ".bots", 0, 1,
 {m_unregistered, m_bots, m_bots}
};
struct TcmMessage events_msgtab = {
 ".events", 0, 1,
 {m_unregistered, m_events, m_events}
};
#ifdef VIRTUAL
struct TcmMessage vmulti_msgtab = {
 ".vmulti", 0, 1,
 {m_unregistered, m_vmulti, m_vmulti}
};
#endif
struct TcmMessage nfind_msgtab = {
 ".nfind", 0, 1,
 {m_unregistered, m_nfind, m_nfind}
};
struct TcmMessage list_msgtab = {
 ".list", 0, 1,
 {m_unregistered, m_list, m_list}
};
#ifdef WANT_ULIST
struct TcmMessage ulist_msgtab = {
 ".ulist", 0, 1,
 {m_unregistered, m_ulist, m_ulist}
};
#endif
#ifdef WANT_HLIST
struct TcmMessage hlist_msgtab = {
 ".hlist", 0, 1,
 {m_unregistered, m_hlist, m_hlist}
};
#endif
#endif

void 
init_commands(void)
{
  int i;
  for (i=0;i<MAX_MSG_HASH;++i)
  {
    msg_hash_table[i].cmd = NULL;
    msg_hash_table[i].msg = NULL;
    msg_hash_table[i].next = NULL;
  }

  mod_add_cmd(&vlist_msgtab);
  mod_add_cmd(&class_msgtab);
  mod_add_cmd(&classt_msgtab);
  mod_add_cmd(&killlist_msgtab);
  mod_add_cmd(&kline_msgtab);
  mod_add_cmd(&kclone_msgtab);
  mod_add_cmd(&kflood_msgtab);
  mod_add_cmd(&kperm_msgtab);
  mod_add_cmd(&klink_msgtab);
  mod_add_cmd(&kdrone_msgtab);
  mod_add_cmd(&kbot_msgtab);
  mod_add_cmd(&kill_msgtab);
  mod_add_cmd(&kaction_msgtab);
  mod_add_cmd(&kspam_msgtab);
  mod_add_cmd(&hmulti_msgtab);
  mod_add_cmd(&umulti_msgtab);
  mod_add_cmd(&register_msgtab);
  mod_add_cmd(&opers_msgtab);
  mod_add_cmd(&testline_msgtab);
  mod_add_cmd(&action_msgtab);
  mod_add_cmd(&set_msgtab);
  mod_add_cmd(&exemptions_msgtab);
  mod_add_cmd(&umode_msgtab);
  mod_add_cmd(&connections_msgtab);
  mod_add_cmd(&whom_msgtab);
  mod_add_cmd(&who_msgtab);
  mod_add_cmd(&disconnect_msgtab);
  mod_add_cmd(&quit_msgtab);
  mod_add_cmd(&help_msgtab);
  mod_add_cmd(&motd_msgtab);
  mod_add_cmd(&save_msgtab);
  mod_add_cmd(&close_msgtab);
  mod_add_cmd(&op_msgtab);
  mod_add_cmd(&cycle_msgtab);
  mod_add_cmd(&die_msgtab);
  mod_add_cmd(&restart_msgtab);
  mod_add_cmd(&info_msgtab);
  mod_add_cmd(&locops_msgtab);
  mod_add_cmd(&unkline_msgtab);
  mod_add_cmd(&vbots_msgtab);
#ifndef NO_D_LINE_SUPPORT
  mod_add_cmd(&dline_msgtab);
#endif
#ifdef ENABLE_QUOTE
  mod_add_cmd(&quote_msgtab);
#endif
  mod_add_cmd(&mem_msgtab);
  mod_add_cmd(&clones_msgtab);
  mod_add_cmd(&nflood_msgtab);
  mod_add_cmd(&rehash_msgtab);
  mod_add_cmd(&trace_msgtab);
  mod_add_cmd(&failures_msgtab);
  mod_add_cmd(&domains_msgtab);
  mod_add_cmd(&bots_msgtab);
  mod_add_cmd(&events_msgtab);
#ifdef VIRTUAL
  mod_add_cmd(&vmulti_msgtab);
#endif
  mod_add_cmd(&nfind_msgtab);
  mod_add_cmd(&list_msgtab);
#ifdef WANT_ULIST
  mod_add_cmd(&ulist_msgtab);
#endif
#ifdef WANT_HLIST
  mod_add_cmd(&hlist_msgtab);
#endif
  mod_add_cmd(&uptime_msgtab);
}

/*
 * islegal_pass()
 *
 * inputs       - user
 *              - host
 *              - password
 *              - int connect id
 * output       - YES if legal NO if not
 * side effects - NONE
 */

static int islegal_pass(int connect_id,char *password)
{
  int i;

  for(i=0;userlist[i].user && userlist[i].user[0];i++)
    {
      if ((!match(userlist[i].user,connections[connect_id].user)) &&
          (!wldcmp(userlist[i].host,connections[connect_id].host)))
        {
          if(userlist[i].password)
            {
#ifdef USE_CRYPT
              if(!strcmp((char*)crypt(password,userlist[i].password),
                         userlist[i].password))
                {
                  strncpy(connections[connect_id].registered_nick,
                          userlist[i].usernick,
                          MAX_NICK);
                  connections[connect_id].type = userlist[i].type;
                  return userlist[i].type;
                }
              else
                return 0;
#else
              if(!strcmp(userlist[i].password,password))
                {
                  strncpy(connections[connect_id].registered_nick,
                          userlist[i].usernick,
                          MAX_NICK);
                  connections[connect_id].type = userlist[i].type;
                  return(userlist[i].type);
                }
              else
                return(0);
#endif
            }
        }
    }
  return(0);
}

/*
 * print_help()
 *
 * inputs       - socket, help_text to use
 * output       - none
 * side effects - prints help file to user
 */

static void
print_help(int sock,char *text)
{
  FILE *userfile;
  char line[MAX_BUFF];
  char help_file[MAX_BUFF];

  if(!text || (*text == '\0') || (*text == '?'))
    {
      if( (userfile = fopen(HELP_PATH "/" HELP_FILE,"r")) == NULL )
        {
          print_to_socket(sock,"Help is not currently available");
          return;
        }
    }
  else
    {
      while(*text == ' ')
        text++;

      if ((*text == '\0') || (*text == '?'))
        {
          if( (userfile = fopen(HELP_PATH "/" HELP_FILE,"r")) == NULL )
            {
              print_to_socket(sock,"Help is not currently available");
              return;
            }
        }

      (void)snprintf(help_file,sizeof(help_file) - 1,"%s/%s.%s",
                     HELP_PATH,HELP_FILE,text);
      if( (userfile = fopen(help_file,"r")) == NULL)
        {
          print_to_socket(sock,
			  "Help for '%s' is not currently available",text);
          return;
        }
    }

  while (fgets(line, MAX_BUFF-1, userfile))
    {
      print_to_socket(sock, "%s", line);
    }
  fclose(userfile);
}
