/*
 *
 *  - added clear_userlist()
 *  - make it actually use MAXUSERS defined in config.h
 *  - added config file for bot nick, channel, server, port etc.
 *  - rudimentary remote tcm linking added
 *
 * $Id: userlist.c,v 1.71 2002/05/25 15:57:56 db Exp $
 *
 */

#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include "config.h"
#include "token.h"
#include "tcm.h"
#include "tcm_io.h"
#include "serverif.h"
#include "userlist.h"
#include "logging.h"
#include "stdcmds.h"
#include "wild.h"
#include "commands.h"
#include "modules.h"
#include "match.h"

struct auth_file_entry userlist[MAXUSERS];
struct exception_entry hostlist[MAXHOSTS];

int  user_list_index;
int  tcm_list_index;
int  host_list_index;
int  ban_list_index;

static void load_a_user(char *);
static void load_e_line(char *);

int
get_method_number (char * methodname)
{
  if (!strcasecmp(methodname, "kline"))
    return METHOD_KLINE;
  else if (!strcasecmp(methodname, "tkline"))
    return METHOD_TKLINE;
  else if (!strcasecmp(methodname, "dline"))
    return METHOD_DLINE;
  else if (!strcasecmp(methodname, "ircwarn"))
    return METHOD_IRC_WARN;
  else if (!strcasecmp(methodname, "dccwarn"))
    return METHOD_DCC_WARN;
  else
    return 0;
}

char *
get_method_names(int method)
{
  static char namebuf[128];

  namebuf[0]= '\0';

  if (method & METHOD_IRC_WARN)
    strcat(namebuf, "ircwarn ");
  if (method & METHOD_DCC_WARN)
    strcat(namebuf, "dccwarn ");
  if (method & METHOD_TKLINE)
    strcat(namebuf, "tkline ");
  if (method & METHOD_KLINE)
    strcat(namebuf, "kline ");
  if (method & METHOD_DLINE)
    strcat(namebuf, "dline ");
  if (namebuf[0])
    namebuf[strlen(namebuf)-1] = '\0';
  return namebuf;
}

/*
 * load_config_file
 * 
 * inputs	- NONE
 * output	- NONE
 * side effects	- configuration items needed for tcm are loaded
 *	  from CONFIG_FILE
 *	  rudimentary error checking in config file are reported
 *	  and if any found, tcm is terminated...
 */

void 
load_config_file(char *file_name)
{
  FILE *fp;
  char line[MAX_BUFF];
  char *argv[MAX_ARGV];
  int  argc, a;
  char *p;
  char *q;
  int error_in_config;		/* flag if error was found in config file */

  error_in_config = NO;

  config_entries.hybrid = NO;
  config_entries.hybrid_version = 0;

  config_entries.tcm_pid_file[0] = '\0';
  config_entries.username_config[0] = '\0';
  config_entries.virtual_host_config[0] = '\0';
  config_entries.oper_nick_config[0] = '\0';
  config_entries.oper_pass_config[0] = '\0';
  config_entries.server_pass[0] = '\0';
  config_entries.ircname_config[0] = '\0';
  config_entries.defchannel[0] = '\0';
  config_entries.dfltnick[0] = '\0';
  config_entries.email_config[0] = '\0';

  config_entries.channel_report = 
    CHANNEL_REPORT_ROUTINE | CHANNEL_REPORT_CLONES;

  strncpy(config_entries.userlist_config,USERLIST_FILE,MAX_CONFIG-1);

  if((fp = fopen(file_name,"r")) == NULL)
  {
    fprintf(stderr,"GACK! I don't know who I am or anything!!\n");
    fprintf(stderr,"tcm can't find %s file\n",file_name);
    exit(1);
  }

  while(fgets(line, MAX_BUFF-1,fp))
  {
    if(line[0] == '#')
      continue;

    /* zap newlines */
    if ((p = strchr(line,'\n')) != NULL)
      *p = '\0';

    if (*line == '\0')
      continue;

    p = line;
    argc=0;

    for (q = strchr(p, ':'); q; q=strchr(p, ':'))
    {
      argv[argc++] = p;
      *q = '\0';
      p = q+1;
    }
    argv[argc++] = p;

    switch(argv[0][0])
    {
    case 'a':case 'A':
      {
	int act, met, klinetime=0;
	/* A:name:methods:reason */
	/* A:clone:tkline 360 ircwarn dccwarn:No clones kthx */
	if (argc < 3)
	  break;
	act = find_action(argv[1]);
	if (act<0)
	  break;
	actions[act].method = 0;
	actions[act].reason[0] = 0;
	actions[act].klinetime = 120;
	p = argv[2];
	q = p;
	while (p) {
	  q = strchr(p, ' ');
	  if (q)
	    *q++ = 0;
	  if (!klinetime && atoi(p))
	    klinetime = atoi(p);
	  else {
	    met = get_method_number(p);
	    if (met) 
	      actions[act].method |= met;
	  }
	  p=q;
	}
	if (klinetime)
	  actions[act].klinetime = klinetime;
	if (argc>=4)
	  set_action_reason(act, argv[3]);
      }
      break;

    /* deprecated option oper only */
    case 'd':case 'D':
      break;

    case 'e':case 'E':
      strncpy(config_entries.email_config,argv[1],MAX_CONFIG-1);
      break;

    case 'f':case 'F':
      if (config_entries.debug && outfile)
	(void)fprintf(outfile, "tcm.pid file name = [%s]\n", argv[1]);
      strncpy(config_entries.tcm_pid_file,argv[1],MAX_CONFIG-1);
      break;

    case 'l':case 'L':
      strncpy(config_entries.userlist_config,argv[1],MAX_CONFIG-1);
      break;

    case 'm':case 'M':
      strncpy(config_entries.statspmsg, argv[1],sizeof(config_entries.statspmsg));          
      for ( a = 2 ; a < argc ; ++a )
      {
	strcat(config_entries.statspmsg, ":");
	strcat(config_entries.statspmsg, argv[a]);
      }
      if (config_entries.statspmsg[strlen(config_entries.statspmsg)-1] == ':')
	config_entries.statspmsg[strlen(config_entries.statspmsg)-1] = '\0';
      break;

    case 'o':case 'O':
      strncpy(config_entries.oper_nick_config,argv[1],MAX_NICK);
      strncpy(config_entries.oper_pass_config,argv[2],MAX_CONFIG-1);
      break;

    case 'u':case 'U':
      if (config_entries.debug && outfile)
	fprintf(outfile, "user name = [%s]\n", argv[1]);
      strncpy(config_entries.username_config,argv[1],MAX_CONFIG-1);
      break;

    case 'v':case 'V':
      if (config_entries.debug && outfile)
	fprintf(outfile, "virtual host name = [%s]\n", argv[1]);
      strncpy(config_entries.virtual_host_config,argv[1],MAX_CONFIG-1);
      break;

    case 's':case 'S':
      if (config_entries.debug && outfile)
	fprintf(outfile, "server = [%s]\n", argv[1]);
      strncpy(config_entries.server_name,argv[1],MAX_CONFIG-1);

      if (argc > 2)
	strncpy(config_entries.server_port,argv[2],MAX_CONFIG-1);

      if (argc > 3)
	strncpy(config_entries.server_pass,argv[3],MAX_CONFIG-1);
      break;

    case 'n':case 'N':
      if (config_entries.debug && outfile)
	fprintf(outfile, "nick for tcm = [%s]\n", argv[1]);
      strncpy(config_entries.dfltnick,argv[1],MAX_NICK-1);
      break;

    case 'i':case 'I':
      if (config_entries.debug && outfile)
	fprintf(outfile, "IRCNAME = [%s]\n", argv[1]);
      strncpy(config_entries.ircname_config,argv[1],MAX_CONFIG-1);
      break;

    case 'c':case 'C':
      if (config_entries.debug && outfile)
	fprintf(outfile, "Channel = [%s]\n", argv[1]);

      if (argc > 3)
        strncpy(config_entries.defchannel_mode,argv[3],MAX_CONFIG-1);
      else
        config_entries.defchannel_mode[0] = '\0';

      if (argc > 2)
	strncpy(config_entries.defchannel_key,argv[2],MAX_CONFIG-1);
      else
	config_entries.defchannel_key[0] = '\0';
      strncpy(config_entries.defchannel,argv[1],MAX_CHANNEL-1);
      break;

    default:
      _config(0, argc, argv);
    }
  }

  if(config_entries.username_config[0] == '\0')
  {
    fprintf(stderr,"I need a username (U:) in %s\n",CONFIG_FILE);
    error_in_config = YES;
  }

  if(config_entries.oper_nick_config[0] == '\0')
  {
    fprintf(stderr,"I need an opernick (O:) in %s\n",CONFIG_FILE);
    error_in_config = YES;
  }

  if(config_entries.oper_pass_config[0] == '\0')
  {
    fprintf(stderr,"I need an operpass (O:) in %s\n",CONFIG_FILE);
    error_in_config = YES;
  }

  if(config_entries.server_name[0] == '\0')
  {
    fprintf(stderr,"I need a server (S:) in %s\n",CONFIG_FILE);
    error_in_config = YES;
  }

  if(config_entries.server_port[0] == '\0')
  {
    fprintf(stderr,"I need a port in the server line (S:) in %s\n",
	    CONFIG_FILE);
    error_in_config = YES;
  }

  if(config_entries.ircname_config[0] == '\0')
  {
    fprintf(stderr,"I need an ircname (I:) in %s\n",CONFIG_FILE);
    error_in_config = YES;
  }

  if(config_entries.dfltnick[0] == '\0')
  {
    fprintf(stderr,"I need a nick (N:) in %s\n", CONFIG_FILE);
    error_in_config = YES;
  }

  if(error_in_config)
    exit(1);
}

/*
 * save_prefs
 *
 * inputs	- NONE
 * output	- NONE
 * side effects - action table is affected
 */
void 
save_prefs(void)
{
  FILE *fp_in;
  FILE *fp_out;
  char *argv[MAX_ARGV];
  char frombuff[MAX_BUFF];
  char *p, *q, filename[80];
  int argc=0, a;

  if ((fp_in = fopen(CONFIG_FILE,"r")) == NULL)
    {
      send_to_all(SEND_ALL, "Couldn't open %s: %s",
		  CONFIG_FILE, strerror(errno));
      return;
    }

  snprintf(filename, sizeof(filename), "%s.%d", CONFIG_FILE, getpid());

  if ((fp_out = fopen(filename, "w")) == NULL)
    {
      send_to_all(SEND_ALL, "Couldn't open %s: %s", filename, strerror(errno));
      fclose(fp_in);
      return;
    }

  while (fgets(frombuff, MAX_BUFF-1, fp_in) != NULL)
    {
      /* zap newlines */
      if ((p = strchr(frombuff,'\n')) != NULL)
	*p = '\0';

      argc = 0;
      p = frombuff;

      for (q=strchr(p, ':'); q; q=strchr(p, ':'))
	{
	  argv[argc++] = p;
	  *q = '\0';
	  p = q+1;
	}
      argv[argc++] = p;
      
      switch (argv[0][0])
	{
	case 'A': case 'a':
	  a = find_action(argv[1]);
	  if (a>=0)
	    {
	      if (!(actions[a].method & 0x80000000))
		{
		  fprintf(fp_out, "A:%s:%s %d:%s\n",
			  actions[a].name,
			  get_method_names(actions[a].method),
			  actions[a].klinetime,
			  actions[a].reason);
		  actions[a].method |= 0x80000000;
		}
	      break;
	    }
	default:
	  for (a=0; a < argc - 1; a++)
	    {
	      fprintf (fp_out, "%s:", argv[a]);
	    }
	  fprintf (fp_out, "%s\n", argv[a]);
	  break;
	}
    }

  for (a=0;actions[a].name[0];a++)
    {
      if (actions[a].method & 0x80000000)
	actions[a].method &= 0x7FFFFFFF;
      else
	fprintf(fp_out, "A:%s:%s %d:%s\n",
		actions[a].name,
		get_method_names(actions[a].method),
		actions[a].klinetime,
		actions[a].reason);
    }
  fclose(fp_in);
  fclose(fp_out);

  if (rename(filename, CONFIG_FILE))
    send_to_all(SEND_ALL,
		 "Error renaming new config file.  Changes may be lost.  %s",
                 strerror(errno));
  chmod(CONFIG_FILE, 0600);
}

/*
 * load_userlist
 * 
 * inputs	- NONE
 * output	- NONE
 * side effects	- first part of oper list is loaded from file
 */

void
load_userlist()
{
  FILE *userfile;
  char line[MAX_BUFF];
  char *p;

  if ((userfile = fopen(config_entries.userlist_config,"r")) == NULL)
    {
      fprintf(stderr,"Cannot read %s\n",config_entries.userlist_config);
      return;
    }

/*
 * 
 * userlist.load looks like now
 * u@h:nick:password:ok o for opers, k for remote kline
 *
 * - or you can use a number 1 for opers, 2 for remote kline -
 * i.e.
 *  u@h:nick:password:3 for opers
 *
 * h:nick:password:ok o for opers, 2 for remote kline
 *
 */

  while (fgets(line, MAX_BUFF-1, userfile) )
    {
      char op_char;

      if(line[0] == '#')
	continue;

      if ((p = strchr(line, '\n')) != NULL)
	*p = '\0';

      op_char = line[0];

      if(line[1] == ':')
	{
	  switch(op_char)
	    {
            /* old user bans, now oper only so deprecated */
            case 'B':
	      break;

	    case 'E':
	      load_e_line(line+2);
	      break;

	    case 'O':
	      load_a_user(line+2);
	      break;

	    default:
	      break;
	    }
	}
      
    }
}

/*
 * load_a_user()
 * inputs	- rest of line past the 'O:' or 'o:'
 * output	- NONE
 * side effects	- userlist is updated
 */

static void
load_a_user(char *line)
  {
    char *userathost;
    char *user;
    char *host;
    char *usernick;
    char *password;
    char *type;
    char *p;

    if(config_entries.debug && outfile)
      {
	fprintf(outfile, "load_a_user() line =[%s]\n",line);
      }

    if(user_list_index == (MAXUSERS - 1))
	return;

    if ((userathost = strtok(line,":")) == NULL)
      return;

    user = userathost;
    if((p = strchr(userathost,'@')) != NULL)
      {
	*p++ = '\0';
	host = p;
      }
    else
      {
	user = "*";
	host = userathost;
      }

    if((p = strchr(host,' ')) != NULL)
      *p = '\0';

    /* Don't allow *@* or user@* O: lines */
    if (strcmp(host, "*") == 0)
      return;

    userlist[user_list_index].usernick[0] = 0;
    userlist[user_list_index].password[0] = 0;

    strncpy(userlist[user_list_index].user, user, 
	    sizeof(userlist[user_list_index].user));

    strncpy(userlist[user_list_index].host, host, 
	    sizeof(userlist[user_list_index].host));

    usernick = strtok(NULL,":");
    
    if(usernick != NULL)
      strncpy(userlist[user_list_index].usernick, usernick, 
	      sizeof(userlist[user_list_index].usernick));

    password = strtok(NULL,":");

    if(password != NULL)
      strncpy(userlist[user_list_index].password, password, 
	      sizeof(userlist[user_list_index].password));

    type = strtok(NULL,":");

    if(type != NULL)
      {
	unsigned long type_int;
	char *q;
	q = type;

	type_int = TYPE_ECHO;

	while(*q)
	  {
	    switch(*q)
	      {
              case 'e':
                type_int |= TYPE_ECHO;
                break;
	      case 'w':
		type_int |= TYPE_WARN;
		break;
	      case 'k':
		type_int |= TYPE_VIEW_KLINES;
		break;
	      case 'i':
		type_int |= TYPE_INVS;
		break;
	      case 'o':
		type_int |= TYPE_LOCOPS;
		break;
	      case 'M':
		type_int |= TYPE_ADMIN;
		break;
	      case 'I':
		type_int |= TYPE_INVM;
		break;
	      case 'D':
		type_int |= TYPE_DLINE;
		break;
#ifdef ENABLE_W_FLAG
              case 'W':
                type_int |= TYPE_WALLOPS;
                break;
#endif
	      case 'y':
		type_int |= TYPE_SPY;
		break;
	      case 'p':
		type_int |= TYPE_PARTYLINE;
		break;
              case 'x':
                type_int |= TYPE_SERVERS;
                break;
	      case 'G':
		type_int |= TYPE_GLINE;
		break;
	      case 'K':
		type_int |= TYPE_KLINE;
		break;

	      default:
		break;
	      }
	    q++;
	  }

	userlist[user_list_index].type = type_int;
      }

    user_list_index++;

    userlist[user_list_index].user[0] = 0;
    userlist[user_list_index].host[0] = 0;
    userlist[user_list_index].usernick[0] = 0;
    userlist[user_list_index].password[0] = 0;
    userlist[user_list_index].type = 0;
}

static void
load_e_line(char *line)
{
  char *vltn, *p, *uhost, *q;
  unsigned int type=0, i;
  /* E:actionmask[ actionmask]:user@hostmask */
  
  if ((p = strchr(line, ':')) == NULL)
    return;
  
  vltn = line;
  *p = '\0';
  uhost = p+1;
  while (vltn)
    {
      p=strchr(vltn, ' ');
      q=strchr(vltn, ',');
      if (p && q)
	p = (p<q)?p:q;
      else if (q)
	p=q;
      if (p)
	*p++=0;
      for (i=0;actions[i].name[0];i++)
	if (!wldcmp(vltn, actions[i].name))
	  type = type + (1 << i);
      vltn = p;
    }
      
  if ((p = strchr(uhost, '@')) != NULL)
    {
      *p = '\0';
      snprintf(hostlist[host_list_index].user,
	       sizeof(hostlist[host_list_index].user), "%s", uhost);
      snprintf(hostlist[host_list_index].host,
	       sizeof(hostlist[host_list_index].host), "%s", p+1);
    }
  else
    {
      snprintf(hostlist[host_list_index].user,
	       sizeof(hostlist[host_list_index].user), "*");
      snprintf(hostlist[host_list_index].host,
	       sizeof(hostlist[host_list_index].host), "%s", uhost);
    }

  hostlist[host_list_index].type = type;
  ++host_list_index;
  hostlist[host_list_index].user[0] = '\0';
  hostlist[host_list_index].host[0] = '\0';
}

/*
 * clear_userlist
 *
 * input	- NONE
 * output	- NONE
 * side effects - user list is cleared out prepatory to a userlist reload
 *
 */

void
clear_userlist()
{
  user_list_index = 0;
  host_list_index = 0;

  memset((void *)userlist, 0, sizeof(userlist));
  memset((void *)hostlist, 0, sizeof(hostlist));

}

/*
 * init_userlist
 *
 * input	- NONE
 * output	- NONE
 * side effects -
 *	  user list is cleared 
 *
 */

void
init_userlist()
{
  tcm_list_index = 0;
  ban_list_index = 0;

  clear_userlist();
}

/*
 * isoper()
 *
 * inputs	- user name
 * 		- host name
 * output	- 1 if oper, 0 if not
 * side effects	- NONE
 */

int
isoper(char *user,char *host)
{
  int i;

  for(i=0; userlist[i].user[0]; i++)
    {
      if ((!match(userlist[i].user,user)) &&
          (!wldcmp(userlist[i].host,host)))
        return 1;
    }
  return 0;
}

/* Checks for ok hosts to block auto-kline - Phisher */
/*
 * okhost()
 * 
 * inputs	- user
 * 		- host
 *		- type
 * output	- if this user@host is in the exception list or not
 * side effects	- none
 */

int
okhost(char *user,char *host, int type)
{
  int i, ok;

  for(i=0;hostlist[i].user[0];i++)
    {
      ok = 0;
      if (strchr(user, '?') || strchr(user, '*'))
      {
        if (!wldwld(hostlist[i].user, user))
          ok++;
      }
      else
        if (!wldcmp(hostlist[i].user, user))
          ok++;

      if (strchr(host, '?') || strchr(host, '*'))
      {
        if (!wldwld(hostlist[i].host, host))
          ok++;
      }
      else
        if (!wldcmp(hostlist[i].host, host))
          ok++;

      if (ok == 2 && (hostlist[i].type & (1 << type)))
        return YES;
    }
  return(NO);
}

/*
 * type_show()
 * 
 * inputs	- unsigned int type
 * output	- pointer to a static char * showing the char types
 * side effects	-
 */

char *
type_show(unsigned long type)
{
  static char type_string[SMALL_BUFF];
  char *p;

  memset(&type_string, 0, sizeof(type_string));
  p = type_string;

  *p++ = 'O';

  if(type & TYPE_KLINE)
    *p++ = 'K';
  if(type & TYPE_GLINE)
    *p++ = 'G';
  if(type & TYPE_SUSPENDED)
    *p++ = 'S';
  if(type & TYPE_ADMIN)
    *p++ = 'M';
  if(type & TYPE_INVM)
    *p++ = 'I';

#ifndef NO_D_LINE_SUPPORT
  if(type & TYPE_DLINE)
    *p++ = 'D';
#endif
#ifdef ENABLE_W_FLAG
  if(type & TYPE_WALLOPS)
    *p++ = 'W';
#endif

  if(type & TYPE_PARTYLINE)
    *p++ = 'p';
  if(type & TYPE_WARN)
    *p++ = 'w';
  if(type & TYPE_ECHO)
    *p++ = 'e';
  if(type & TYPE_INVS)
    *p++ = 'i';
  if(type & TYPE_LOCOPS)
    *p++ = 'o';
  if(type & TYPE_VIEW_KLINES)
    *p++ = 'k';
  if(type & TYPE_SPY)
    *p++ = 'y';
  if(type & TYPE_SERVERS)
    *p++ = 'x';

  *p = '\0';
  return(type_string);
}

/*
 * reload_user_list()
 *
 * Thanks for the idea garfr
 *
 * inputs - signal number
 * output - NONE
 * side effects -
 *             reloads user list without having to restart tcm
 *
 */

void
reload_user_list(int sig)
{
  if(sig != SIGHUP)     /* should never happen */
    return;

  _reload_bothunt(sig, 0, NULL);
  _reload_wingate(sig, 0, NULL);

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

  send_to_all(SEND_ALL, "*** Caught SIGHUP ***\n");
}

#ifdef DEBUGMODE
/*
 * exemption_summary()
 *
 * inputs - none
 * outputs - none
 * side effects - prints out summary of exemptions, indexed by action names
 */

void
exemption_summary()
{
  int i, j;

  for (i=0;i<MAX_ACTIONS;++i)
  {
    if (actions[i].name[0] == '\0')
     break;
    printf("%s:", actions[i].name);
    for (j=0;j<MAXHOSTS;++j)
    {
      if (hostlist[j].user[0] == '\0')
        break;
      if (hostlist[j].type & i)
        printf(" %s@%s", hostlist[j].user, hostlist[j].host);
    }
    printf("\n");
  }
}
#endif


/*
 * local_ip()
 *
 * inputs	- NONE
 * output	- ip of local host
 * side effects - NONE
 */
unsigned long 
local_ip(char *ourhostname)
{
  struct hostent *local_host;
  unsigned long l_ip;

  if(config_entries.virtual_host_config[0])
    {
      if ((local_host = gethostbyname (config_entries.virtual_host_config)))
        {
          if(config_entries.debug && outfile)
            {
              fprintf(outfile,
                      "virtual host [%s]\n",
                      config_entries.virtual_host_config);
              fprintf(outfile, "found official name [%s]\n",
                      local_host->h_name);
            }

          (void) memcpy((void *)&l_ip,(void *)local_host->h_addr,
                 sizeof(local_host->h_addr));

          if(config_entries.debug && outfile)
            {
              fprintf(outfile, "DEBUG: %lu %lX\n", l_ip, l_ip);
            }
          return(htonl(l_ip));
        }
    }
  else
    {
      if ((local_host = gethostbyname (ourhostname)) )
        {
          if(config_entries.debug && outfile)
            {
              fprintf(outfile, "found official name [%s]\n",
                      local_host->h_name);
            }

          (void) memcpy((void *) &l_ip,(void *) local_host->h_addr,
                        sizeof(local_host->h_addr));

          if(config_entries.debug && outfile)
            {
              fprintf(outfile, "DEBUG: %lu %lX\n", l_ip, l_ip);
            }
          return(htonl(l_ip));
        }
    }
  /* NOT REACHED */
  return 0L;
}
