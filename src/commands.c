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
#include "token.h"
#include "bothunt.h"
#include "userlist.h"
#include "serverif.h"
#include "logging.h"
#include "commands.h"
#include "abuse.h"
#include "stdcmds.h"

#ifdef DMALLOC
#include "dmalloc.h"
#endif

static char *version="$Id: commands.c,v 1.6 2000/12/05 00:54:47 bill Exp $";

char allow_nick[MAX_ALLOW_SIZE][MAX_NICK+4];

static int is_kline_time(char *p);
static int not_legal_remote(int);
static void set_actions(int socket, char *key, char *action, char *reason,
			char *message );
static void send_to_nick(char *to_nick,char *buffer);
static void setup_allow(char *nick);
static void save_umodes(char *registered_nick, unsigned long type);
static void load_umodes(int connect_id);
static unsigned long find_user_umodes(char *nick);
static int  test_ignore(char *line);
static void set_umode(int connnum, char *flags, char *registered_nick);
static void show_user_umodes(int socket, char *registered_nick);
static void not_authorized(int socket);
static void register_oper(int connnum, char *password, char *who_did_command);
static void list_opers(int socket);
static void list_tcmlist(int socket);
static void list_connections(int socket);
static void list_exemptions(int socket);
static void handle_allow(int socket, char *param, char *who_did_command);
static void handle_disconnect(int socket,char *param2,char *who_did_command);
static void handle_save(int socket,char *nick);
static void handle_gline(int socket,char *pattern,char *reason,
			 char *who_did_command);

/*
** dccproc()
**   Handles processing of dcc chat commands
*/
void dccproc(int connnum)
{

/* *sigh* maximum allow for MAXIMUM sprintf limit */
/* connnections[connnum].buffer can be larger than MAX_BUFF plus overhead */
/* connnum].buffer can be much larger than outgoing
*/

#define FLUFF_SIZE (4*MAX_NICK)+10

  char *buffer = connections[connnum].buffer;
  char dccbuff[MAX_BUFF];
  char who_did_command[2*MAX_NICK];
  char fulluh[MAX_HOST+MAX_DOMAIN];
  int i;
  int opers_only = SEND_ALL_USERS; 	/* Is it an oper only message ? */
  int ignore_bot = NO;
  char *param1;
  char *param2;
  char *param3;
  char *param2_orig;
  int kline_time;
  placed;

/* Make terribly sure that incoming buffer isn't larger than outgoing */
  if(strlen(buffer) > (MAX_BUFF - FLUFF_SIZE))
     buffer[MAX_BUFF-FLUFF_SIZE] = '\0';



  /* wot a kludge (to rhyme with sludge) */

  route_entry.to_nick[0] = '\0';
  route_entry.to_tcm[0] = '\0';
  route_entry.from_nick[0] = '\0';
  route_entry.from_tcm[0] = '\0';
  who_did_command[0] = '\0';

  /* remote message, either to a tcm command parser,
     or from a user meant to be sent on to another remote tcm,
     or, its from a remote tcm to be passed onto another tcm
  */

  if(*buffer == ':')
    {
      char *to;
      char *from;
      char *to_nick;
      char *to_tcm;
      char *from_nick;
      char *from_tcm;

      buffer++;	/* skip the ':' */

      if(connections[connnum].type & TYPE_TCM)
	{
	  if( !(to = strtok(buffer," ")) )
	    return;

	  if( !(from = strtok((char *)NULL," ")) ) 
	    return;

	  to_nick = to;

	  if( !(to_tcm = strchr(to,'@')) )
	    {
	      to_tcm = to;
	    }
	  else
	    {
	      *to_tcm = '\0';
	      to_tcm++;
	    }

	  from_nick = from;
	  strncpy(who_did_command,from,2*MAX_NICK);

	  if( !(from_tcm = strchr(from,'@')) )
	    return;

	  *from_tcm = '\0';
	  from_tcm++;

	  if( !(buffer = strtok((char *)NULL,"")) )
	    return;

	  while(*buffer == ' ')
	    buffer++;

	  if( !strcasecmp(to_tcm,config_entries.dfltnick) )	
	    {
	      /* Directed to someone on this tcm */
	      if( !strcasecmp(to_nick,config_entries.dfltnick) )
		{
		  /* Directed to the tcm itself */
		  /* Set up to let prnt return to this address */
		  strncpy(route_entry.to_nick,from_nick,MAX_NICK);
		  strncpy(route_entry.to_tcm,from_tcm,MAX_NICK);
		  strncpy(route_entry.from_nick,
			  config_entries.dfltnick,MAX_NICK);
		  strncpy(route_entry.from_tcm,
			  config_entries.dfltnick,MAX_NICK);
		}
	      else
		{
		  /* Directed to this nick on the tcm */
		  send_to_nick(to_nick,buffer);
		  return;
		}
	    }
	  else
	    {
	      /* Directed to someone on another tcm */
	      (void)sprintf(dccbuff,":%s@%s %s@%s %s\n",
			to_nick,
			to_tcm,
			from_nick,
			from_tcm,
			buffer);

	      sendto_all_linkedbots(dccbuff);
	      return;
	    }
	}
      else	/* Its user */
	{
	  /* :server .command */

	  if( !(to_nick = strtok(buffer," ")) )
	    return;

	  if( !(buffer = strtok((char *)NULL,"")) )
	    return;

	  while(*buffer == ' ')
	    buffer++;

	  (void)sprintf(dccbuff,":%s@%s %s@%s %s\n",
			to_nick,
			to_nick,
			connections[connnum].nick,
			config_entries.dfltnick,
			buffer);

	  sendto_all_linkedbots(dccbuff);
	  return;
	}
    }
  else
    {
      (void)sprintf(who_did_command,"%s@%s",
		    connections[connnum].nick,config_entries.dfltnick);

    }

  if(*buffer != '.')
    {	
      if((buffer[0] == 'o' || buffer[0] == 'O')
	 && buffer[1] == ':')
	{
	  opers_only = SEND_OPERS_ONLY;
	  if( (connections[connnum].type & TYPE_TCM))
	    {
	      strncpy(dccbuff,buffer,MAX_BUFF);
	    }
	  else
	    {
	      (void)sprintf(dccbuff,"o:<%s@%s> %s",
			    connections[connnum].nick,config_entries.dfltnick,
			    buffer+2);
	    }
	}
      else
	{
	  if((connections[connnum].type & TYPE_TCM))
	    {
	      ignore_bot = test_ignore(buffer);
	      strncpy(dccbuff,buffer,MAX_BUFF);
	    }
	  else
	    {
	      (void)sprintf(dccbuff,"<%s@%s> %s",
			    connections[connnum].nick,
			    config_entries.dfltnick,
			    buffer);
	    }
	}
      if(!ignore_bot)
	{
	  if(connections[connnum].type & TYPE_PARTYLINE )
	    {
	      sendtoalldcc(opers_only, dccbuff); /* Thanks Garfr, Talen */
	    }
	  else
	    {
	      if(opers_only == SEND_OPERS_ONLY)
		sendtoalldcc(opers_only, dccbuff);
	      else
		prnt(connections[connnum].socket,
		     "You are not +p, not sending to chat line\n");
	    }
	}
      return;
    }

  if((connections[connnum].type & TYPE_TCM) &&
     ( !(route_entry.to_nick[0]) ))
    {
      if(buffer[1] != 'T')	/* You didn't see this and
				 *  I won't admit to it
				 */
	{
	  if(connections[connnum].type & TYPE_REGISTERED)
	    {
	      strcat(buffer,"\n");
	      sendto_all_linkedbots(buffer);
	      toserv(buffer+1);
	    }
	  return;
	}
    }

  buffer++;	/* skip the '.' */

  if( !(param1 = strtok(buffer," ")) )
    return;

  if( (param2 = strtok((char *)NULL," ")) )
    {
      if(*param2 == '@')
	{
	  param3 = strtok((char *)NULL,"");

	  /* Directed to someone on another tcm */
	  if(param3)
	    {
	      (void)sprintf(dccbuff,":%s@%s %s .%s %s\n",
			    param2+1,
			    param2+1,
			    who_did_command,
			    param1,
			    param3);
	    }
	  else
	    {
	      (void)sprintf(dccbuff,":%s@%s %s .%s\n",
			    param2+1,
			    param2+1,
			    who_did_command,
			    param1);
	    }
	  sendto_all_linkedbots(dccbuff);
	  return;
	}
    }

  if(config_entries.hybrid)
    {
      param2_orig = param2;
      kline_time = 0;

      /* *sigh* less than clean IMO but oh well... */
      if(param2)
	{
	  if((kline_time = is_kline_time(param2)) != 0)
	    {
	      param2 = strtok((char *)NULL," "); /* new u@h or nick */
	    }
	}
    } else param2_orig = param2;

  param3 = strtok((char *)NULL,"");

  if(config_entries.debug)
    {
      if(param3)
	fprintf(outfile, "param3 = [%s]\n", param3);
    }

  switch(get_token(param1))
    {
    case K_UPTIME:
      report_uptime(connections[connnum].socket);
      break;

    case K_MEM:
      report_mem(connections[connnum].socket);
      break;

    case K_CLONES:
      report_clones(connections[connnum].socket);
      break;

    case K_NFLOOD:
      report_nick_flooders(connections[connnum].socket);
      break;

    case K_REHASH:
      sendtoalldcc(SEND_ALL_USERS,"rehash requested by %s\n",who_did_command);
      initopers();
      if(config_entries.hybrid && (config_entries.hybrid_version >= 6))
	{
	  toserv("STATS I\n");
	}
      else
	{
	  toserv("STATS E\n");
	  toserv("STATS F\n");
	}
      break;

    case K_TRACE:
      sendtoalldcc(SEND_OPERS_ONLY,
		   "trace requested by %s\n",
		   who_did_command);
      inithash();
      break;

    case K_FAILURES:

      if(config_entries.hybrid)
	{
	  if(kline_time)
	    param2 = param2_orig;
	}

      if (!param2)
	report_failures(connections[connnum].socket,10);
      else if (atoi(param2) < 1)
	prnt(connections[connnum].socket,"Usage: .failures [min failures]\n");
      else
	report_failures(connections[connnum].socket,atoi(param2));
      break;

    case K_DOMAINS:
      if(config_entries.hybrid)
	{
	  if(kline_time)
	    param2 = param2_orig;
	}

      if (!param2)
        report_domains(connections[connnum].socket,5);
      else if (atoi(param2) < 1)
        prnt(connections[connnum].socket,"Usage: .domains [min users]\n");
      else
        report_domains(connections[connnum].socket,atoi(param2));
      break;

    case K_BOTS:
      if(param2_orig)
	{
	  report_multi(connections[connnum].socket,atoi(param2_orig));
	}
      else
	{
	  report_multi(connections[connnum].socket,0);
	}
      break;

    case K_VBOTS:
      if(param2_orig)
	{
	  report_multi_virtuals(connections[connnum].socket,atoi(param2_orig));
	}
      else
	{
	  report_multi_virtuals(connections[connnum].socket,10);
	}
      break;
      
    case K_NFIND:
      if (connections[connnum].type & TYPE_OPER)
	{
	  if (!param2)
	    prnt(connections[connnum].socket,
	       "Usage: .nfind <wildcarded nick>\n");
	  else
	    list_nicks(connections[connnum].socket,param2);
	}
      else
	{
	  not_authorized(connections[connnum].socket);
	}
      break;

    case K_LIST:
      if (connections[connnum].type & TYPE_OPER)
	{
	  if (!param2)
	    prnt(connections[connnum].socket,
		 "Usage: .list <wildcarded userhost>\n");
	  else
	    list_users(connections[connnum].socket,param2);
	}
      else
	{
	  not_authorized(connections[connnum].socket);
	}
      break;

    case K_ULIST:
      if (connections[connnum].type & TYPE_OPER)
	{
	  if (!param2)
	    prnt(connections[connnum].socket,
		 "Usage: .list <wildcarded user>\n");
	  else
	    {
	      sprintf(fulluh,"%s@*", param2 );
	      list_users(connections[connnum].socket,fulluh);
	    }
	}
      else
	{
	  not_authorized(connections[connnum].socket);
	}
      break;

    case K_HLIST:
      if (connections[connnum].type & TYPE_OPER)
	{
	  if (!param2)
	    prnt(connections[connnum].socket,
		 "Usage: .list <wildcarded host>\n");
	  else
	    {
	      sprintf(fulluh,"*@%s", param2 );
	      list_users(connections[connnum].socket,fulluh);
	    }
	}
      else
	{
	  not_authorized(connections[connnum].socket);
	}
      break;

    case K_VLIST:
      if (connections[connnum].type & TYPE_OPER)
	{
	  if (!param2)
	    prnt(connections[connnum].socket,
		 "Usage: .vlist <ip_block>\n");
	  else
	    list_virtual_users(connections[connnum].socket,param2);
	}
      else
	{
	  not_authorized(connections[connnum].socket);
	}
      break;

    case K_CLASS:
      if (connections[connnum].type & TYPE_OPER)
	{
	  if(config_entries.hybrid)
	    {
	      if(kline_time)
		param2 = param2_orig;
	    }

	  if(param2)
	    {
	      list_class(connections[connnum].socket,param2,NO);
	    }
	  else
	    {
	      prnt(connections[connnum].socket,
		   "Usage: .class class_name\n");
	    }
	}
      else
	{
	  not_authorized(connections[connnum].socket);
	}
      break;

    case K_CLASST:
      if (connections[connnum].type & TYPE_OPER)
	{
	  if(config_entries.hybrid)
	    {
	      if(kline_time)
		param2 = param2_orig;
	    }

	  if(param2)
	    {
	      list_class(connections[connnum].socket,param2,YES);
	    }
	  else
	    {
	      prnt(connections[connnum].socket,
		   "Usage: .class class_name\n");
	    }
	}
      else
	{
	  not_authorized(connections[connnum].socket);
	}
      break;


    case K_KILLLIST:	/* - Phisher */
      if (connections[connnum].type & TYPE_REGISTERED)
	{
	  if(not_legal_remote(connections[connnum].type))
	    {
	      prnt(connections[connnum].socket,"You have no remote .killlist privs");
	      return;
	    }

	  if (!param2)
	    {
	      prnt(connections[connnum].socket,
		   "Usage: .killlist <wildcarded userhost> or\n");
	      prnt(connections[connnum].socket,
		   "Usage: .kl <wildcarded userhost>\n");
	    }
	  else
	    {
	      sendtoalldcc(SEND_OPERS_ONLY,
			   "killlist %s by %s\n",
			   param2,
			   who_did_command);
	      kill_list_users(connections[connnum].socket,
			      param2, "Too many connections, read MOTD");
	    }
	}
      else
	prnt(connections[connnum].socket,"You aren't registered\n");
      break;

/* - Phisher */
#ifdef REMOTE_KLINE

    case K_GLINE:
      {
	if( connections[connnum].type & TYPE_GLINE )
	  {
	    handle_gline(connections[connnum].socket, param2, param3,
			 who_did_command);
	  }
	else
	  prnt(connections[connnum].socket,"You don't have gline privilege\n");
      }
    break;

    case K_KLINE:
      if( connections[connnum].type & TYPE_REGISTERED )
	{
	  if(not_legal_remote(connections[connnum].type))
	    {
	      prnt(connections[connnum].socket,"You have no remote .kline privs");
	      return;
	    }

	  if( !param2 )
	    {
	      prnt(connections[connnum].socket,
	   "missing nick/user@host \".kline [nick]|[user@host] reason\"\n");
	      return;
	    }
	  
	  if( !param3 )
	    {
	      prnt(connections[connnum].socket,
		   "missing reason \"kline [nick]|[user@host] reason\"\n");
	      return;
	    }
	  do_a_kline("kline",kline_time,param2,param3,who_did_command);
	}
      else
	prnt(connections[connnum].socket,"You aren't registered\n");
    break;

/* Toast */
    case K_KCLONE:
      if( connections[connnum].type & TYPE_REGISTERED )
	{
	  if(not_legal_remote(connections[connnum].type))
	    {
	      prnt(connections[connnum].socket,"You have no remote .kclone privs");
	      return;
	    }

	  if( !param2 )
	    {
	      prnt(connections[connnum].socket,
		   "missing nick/user@host \".kclone [nick]|[user@host]\"\n");
	      return;
	    }
	  do_a_kline("kclone",kline_time,param2,
		     REASON_KCLONE,who_did_command);
	}
      else
	prnt(connections[connnum].socket,"You aren't registered\n");
    break;

/* Toast */
    case K_KFLOOD:
      if( connections[connnum].type & TYPE_REGISTERED )
	{
	  if(not_legal_remote(connections[connnum].type))
	    {
	      prnt(connections[connnum].socket,"You have no remote .kflood privs");
	      return;
	    }

	  if( !param2 )
	    {
	      prnt(connections[connnum].socket,
		   "missing nick/user@host \".kflood [nick]|[user@host]\"\n");
	      return;
	    }
	  do_a_kline("kflood",kline_time,param2,
		     REASON_KFLOOD,who_did_command);
	}
      else
	prnt(connections[connnum].socket,"You aren't registered\n");
    break;

    case K_KPERM:
      if( connections[connnum].type & TYPE_REGISTERED )
	{
	  if(not_legal_remote(connections[connnum].type))
	    {
	      prnt(connections[connnum].socket,"You have no remote .kperm privs");
	      return;
	    }

	  if( !param2 )
	    {
	      prnt(connections[connnum].socket,
		   "missing nick/user@host \".kperm [nick]|[user@host]\"\n");
	    }
	  do_a_kline("kperm",kline_time,param2,
		     REASON_KPERM,who_did_command);
	}
      else
	prnt(connections[connnum].socket,"You aren't registered\n");
    break;

    case K_KLINK:
      if( connections[connnum].type & TYPE_REGISTERED )
	{
	  if(not_legal_remote(connections[connnum].type))
	    {
	      prnt(connections[connnum].socket,"You have no remote .klink privs");
	      return;
	    }

	  if( !param2 )
	    {
	      prnt(connections[connnum].socket,
		   "missing nick/user@host \".klink [nick]|[user@host]\"\n");
	    }
	  do_a_kline("klink",kline_time,param2,
		     REASON_LINK,who_did_command);
	}
      else
	prnt(connections[connnum].socket,"You aren't registered\n");
    break;

    case K_KDRONE:
      if( connections[connnum].type & TYPE_REGISTERED )
	{
	  if(not_legal_remote(connections[connnum].type))
	    {
	      prnt(connections[connnum].socket,"You have no remote .kdrone privs");
	      return;
	    }

	  if( !param2 )
	    {
	      prnt(connections[connnum].socket,
		   "missing nick/user@host \".kdrone [nick]|[user@host]\"\n");
	      return;
	    }
	  do_a_kline("kdrone",kline_time,param2,
		     REASON_KDRONE,who_did_command);
	}
      else
	prnt(connections[connnum].socket,"You aren't registered\n");
    break;

    case K_KBOT:
      if( connections[connnum].type & TYPE_REGISTERED )
	{
	  if(not_legal_remote(connections[connnum].type))
	    {
	      prnt(connections[connnum].socket,"You have no remote .kbot privs");
	      return;
	    }

	  if( !param2 )
	    {
	      prnt(connections[connnum].socket,
		   "missing nick/user@host \".kbot [nick]|[user@host]\"\n");
	      return;
	    }
	  do_a_kline("kbot",kline_time,param2,
		     REASON_KBOT,who_did_command);
	}
      else
	prnt(connections[connnum].socket,"You aren't registered\n");
    break;

    case K_KILL:
      {
	char *reason;
        char *pattern;  /* u@h or nick */
	
	if( connections[connnum].type & TYPE_REGISTERED )
	  {
	    if(not_legal_remote(connections[connnum].type))
	      {
		prnt(connections[connnum].socket, "%s",
		     "You have no remote .kill privs");
		return;
	      }

	    if(param2)
	      {
		pattern = param2;
		reason = param3;
		    
		if(pattern && reason)
		  {
		    log_kline("KILL",
			      pattern,
			      0,
			      who_did_command,
			      reason);

		    sendtoalldcc(SEND_OPERS_ONLY,	
				 "kill %s : by oper %s@%s %s",
				 pattern,
				 connections[connnum].nick,
				 config_entries.dfltnick,
				 reason);

#ifdef HIDE_OPER_IN_KLINES
                    toserv("KILL %s : %s\n",
			   pattern,
			   reason);
#else
                    toserv("KILL %s : requested by %s reason- %s\n",
			   pattern,
			   who_did_command,
			   reason);
#endif
                  }
                else
                  {
                    prnt(connections[connnum].socket,
			 "missing nick/user@host reason \".kill [nick]|[user@host] reason\"\n");
                  }
              }
          }
	else
	  prnt(connections[connnum].socket,"You aren't registered\n");
      }
    break;

    case K_SPAM:

      if( connections[connnum].type & TYPE_REGISTERED )
	{
	  if(not_legal_remote(connections[connnum].type))
	    {
	      prnt(connections[connnum].socket,"You have no remote .kspam privs");
	      return;
	    }

	  if( !param2 )
	    {
	      prnt(connections[connnum].socket,
		   "missing nick/user@host \".kspam [nick]|[user@host]\"\n");
	      return;
	    }
	  do_a_kline("kflood",kline_time,param2,
		     REASON_KSPAM,who_did_command);
	}
      else
	prnt(connections[connnum].socket,"You aren't registered\n");
    break;

#endif	/* -- #ifdef REMOTE_KLINE */

    case K_HMULTI:
      if (connections[connnum].type & TYPE_OPER)
	{
	  int i;
	  if (param2_orig)
	    {
	      i=atoi(param2_orig);
	      if (i<3)
		{
		  prnt(connections[connnum].socket, "%s",
       "Using a threshold less than 3 is not recommended, changed to 3\n");
		  i=3;
		}
	    }
	  else
	    {
	      i=3;
	    }

	  report_multi_host(connections[connnum].socket,i);
	}
      else
	{
	  not_authorized(connections[connnum].socket);
	}
      break;

    case K_MULTI:
      if (connections[connnum].type & TYPE_OPER)
	{
	  int i;
	  if (param2)
	    {
	      i = atoi(param2);
	      if (i < 3)
		{
		  prnt(connections[connnum].socket, "%s",
           "Using a threshold less than 3 is not recommended, changed to 3\n");
		  i=3;
		}
	    }
	  else
	    {
	      i=3;
	    }
	  report_multi(connections[connnum].socket, i);
	}
      else
	{
	  not_authorized(connections[connnum].socket);
	}
      break;

    case K_UMULTI:
      if (connections[connnum].type & TYPE_OPER)
	{
	  int i;
	  if (param2_orig)
	    {
	      i=atoi(param2_orig);
	      if (i<3)
		{
		  prnt(connections[connnum].socket,
       "Using a threshold less than 3 is not recommended, changed to 3\n");
		  i=3;
		}
	    }
	  else
	    {
	      i=3;
	    }
	  report_multi_user(connections[connnum].socket,i);
	}
      else
	{
	  not_authorized(connections[connnum].socket);
	}
      break;


    case K_REGISTER:
      if( connections[connnum].type & TYPE_OPER )
	{
	  register_oper(connnum, param2, who_did_command);
	}
      else
	{
	  not_authorized(connections[connnum].socket);
	}
    break;

    case K_OPERS:
      list_opers(connections[connnum].socket);
    break;

    case K_ACTION:
      {
	char *p;
	char *reason;
	char *message;

	message = NULL;
	reason = NULL;

	if( param3 && (p = strchr(param3,':')) )
	  {
	    *p = '\0';
	    p++;
	    reason = p;
	    if((p = strchr(reason,':')))
	      {
		*p = '\0';
		p++;
		message = p;
	      }
	  }

	set_actions(connections[connnum].socket, param2, param3, 
		    reason, message);
      }
    break;

    case K_SET:
      {
	if(!param2)
	  {
	    if(connections[connnum].set_modes & SET_PRIVMSG)
	      {
		prnt(connections[connnum].socket,
		     "MESSAGES\n");
	      }
	    else
	      {
		prnt(connections[connnum].socket,
		     "NOMESSAGES\n");
	      }

	    if(connections[connnum].set_modes & SET_NOTICES)
	      {
		prnt(connections[connnum].socket,
		     "NOTICES\n");
	      }
	    else
	      {
		prnt(connections[connnum].socket,
		     "NONOTICES\n");
	      }
	    return;
	  }

	if( !(strcasecmp(param2,"MESSAGES")) )
	  {
	    connections[connnum].set_modes |= SET_PRIVMSG;
	    prnt(connections[connnum].socket,
		 "You will see privmsgs sent to tcm\n");
	  }
	else if( !(strcasecmp(param2,"NOMESSAGES")) )
	  {
	    connections[connnum].set_modes &= ~SET_PRIVMSG;
	    prnt(connections[connnum].socket,
		 "You will not see privmsgs sent to tcm\n");
	  }
	else if( !(strcasecmp(param2,"NOTICES")) )
	  {
	    connections[connnum].set_modes |= SET_NOTICES;
	    prnt(connections[connnum].socket,
		 "You will see selected server notices\n");
	  }
	else if( !(strcasecmp(param2,"NONOTICES")) )
	  {
	    connections[connnum].set_modes &= ~SET_NOTICES;
	    prnt(connections[connnum].socket,
		 "You will not see server notices\n");
	  }
	else
	  {
	    prnt(connections[connnum].socket,
		 "Usage: .set [MESSAGES|NOMESSAGES]\n");
	    prnt(connections[connnum].socket,
		 "Usage: .set [NOTICES|NONOTICES]\n");
	  }
      }
    break;

    case K_TCMLIST:
      list_tcmlist(connections[connnum].socket);
    break;

    case K_EXEMPTIONS:
      list_exemptions(connections[connnum].socket);
    break;

#ifndef OPERS_ONLY
    case K_BAN:
      {
	if(connections[connnum].type & TYPE_OPER)
	  {
	    int i;

	    if(param2)
	      {
		if(*param2 == '+')
		  ban_manipulate(connections[connnum].socket,'+',param2+1);
		else
		  ban_manipulate(connections[connnum].socket,'-',param2+1);
	      }
	    else
	      {
		prnt(connections[connnum].socket,"current bans\n");
		for(i=0; i < MAXBANS; i++)
		  {
		    if(!banlist[i].host[0]) break;
		    if(!banlist[i].user[0]) break;
		    if(banlist[i].host[0])
		      {
			prnt(connections[connnum].socket,
			     "%s@%s\n", banlist[i].user, banlist[i].host);
		      }
		  }
	      }
	  }
	else
	  {
	    not_authorized(connections[connnum].socket);
	  }
      }
      break;
#endif
      
    case K_TCMCONN:
      {
	if(connections[connnum].type & TYPE_OPER)
	  {
	    int i;
	    int new_connnum;

	    if( !param2 )
	      {
		prnt(connections[connnum].socket,
		     "You must specify a tcm nick to connect\n");
		return;
	      }

	    for(i=0; i < MAXTCMS;i++)
	      {
		int socket;
		
		if(!tcmlist[i].host[0]) break;

		if( !(strcasecmp(tcmlist[i].theirnick, param2)) )
		  continue;

		if(tcmlist[i].port == 0)
		  (void)sprintf(dccbuff,"%s:%d",
				tcmlist[i].host,
				TCM_PORT);
		else
		  (void)sprintf(dccbuff,"%s:%d",
				tcmlist[i].host,
				tcmlist[i].port);

		if((socket = bindsocket(dccbuff)) > 0)
		  {
		    new_connnum = add_connection(socket,i);
		    if(new_connnum == INVALID)
		      {
			sendtoalldcc(SEND_ALL_USERS,
				     "Failed tcm connection to %s\n",
				     param2);
			(void)close(socket);
		      }
		    else
		      {
			int j;

			/* Extra paranoia doesn't hurt at all */
			if(tcmlist[i].theirnick[0] && tcmlist[i].password[0])
			  {
			    prnt(socket,"%s %s %s\n",
				 tcmlist[i].theirnick,
				 config_entries.dfltnick,
				 tcmlist[i].password);
			    (void)sprintf(dccbuff,".TCMINTRO %s %s ",
					  config_entries.dfltnick,
					  tcmlist[i].theirnick);

			    for (j=1;j<maxconns;++j)
			      if (connections[i].socket != INVALID)
				{
				  if(connections[j].type & TYPE_TCM)
				    {
				      (void)strcat(dccbuff," ");
				      (void)strcat(dccbuff,
						   connections[i].nick);
				    }
				}
			    strcat(dccbuff,"\n");
			    sendto_all_linkedbots(dccbuff);
			    sendtoalldcc(SEND_ALL_USERS,
					 "tcm connecting to %s\n", param2);
			  }
		      }
		  }
		else
		  {
		    sendtoalldcc(SEND_ALL_USERS,
				 "tcm failed to connect to %s\n",
				 param2);
		    (void)close(socket);
		  }
	      }
	  }
	else
	  {
	    not_authorized(connections[connnum].socket);
	  }
      }
    break;

    case K_TCMINTRO:
      {
	/* param2 param3 are possibly already set up for tcm nicks... */
	/* I pick up any more after param3 using tcmnick */

	char *tcmnick;
	char *newtcm;

	if(param2)
	  {
	    if(config_entries.debug)
	      {
		fprintf(outfile, "DEBUG: tcmnick [%s] ", param2);
	      }
	  }
	else
	  return;

	newtcm = strtok(param3," ");;
	if(newtcm)
	  {
	    if(config_entries.debug)
	      {
		fprintf(outfile, "linking [%s]\n", newtcm);
	      }
	  }
	else
	  return;

	tcmnick = strtok((char *)NULL," ");
	while(tcmnick)
	  {
	    if(config_entries.debug)
	      {
		fprintf(outfile, "DEBUG: introducing [%s]\n", tcmnick);
	      }

	    if( already_have_tcm(tcmnick) )
	      {
		
		if(config_entries.debug)
		  {
		    fprintf(outfile, "DEBUG: already have [%s]\n",  tcmnick);
		  }
		sendtoalldcc(SEND_ALL_USERS,
   "!%s! Routing loop tcm [%s] linking in [%s] finding already present [%s]\n",
			   config_entries.dfltnick,param2,newtcm,tcmnick);

		(void)sprintf(dccbuff,":%s@%s -@%s .disconnect %s\n",
			    param2,
			    param2,
			    config_entries.dfltnick,
			    newtcm);

		sendto_all_linkedbots(dccbuff);
	      }
	    tcmnick = strtok((char *)NULL," ");
	  }
      }
      break;

    case K_ALLOW:
      if (connections[connnum].type & TYPE_REGISTERED)
	handle_allow(connections[connnum].socket,param2,who_did_command);
      else
	prnt(connections[connnum].socket,"You aren't registered\n");
      break;

      case K_UMODE:

	if (!(connections[connnum].type & TYPE_REGISTERED))
	  {
	    prnt(connections[connnum].socket, "You aren't registered\n");
	    return;
	  }

	if (param2_orig)
	  {
	    if(param3)
	      {
		if(! (connections[connnum].type & TYPE_ADMIN) )
		  {
		    prnt(connections[connnum].socket, "You aren't an admin\n");
		    return;
		  }

		if((*param3 == '+') || (*param3 == '-'))
		  {
		    set_umode(connnum,param3, param2_orig);
		  }
		else
		  {
		    prnt(connections[connnum].socket,
			 ".umode [user flags] | [user] | [flags]\n");
		  }
	      }
	    else
	      {
		if((*param2_orig == '+') || (*param2 == '-'))
		  {
		    set_umode(connnum, param2_orig, NULL);
		  }
		else
		  {
		    if(! (connections[connnum].type & TYPE_ADMIN) )
		      {
			prnt(connections[connnum].socket, 
			     "You aren't an admin\n");
			return;
		      }
		    show_user_umodes(connections[connnum].socket,param2_orig);
		  }
	      }
	  }
	else
	  {
	    prnt(connections[connnum].socket,
		 "Your current flags are: %s\n",
		 type_show(connections[connnum].type));
	  }
	break;

      case K_CONNECTIONS:
	list_connections(connections[connnum].socket);
	break;

      case K_DISCONNECT:
	if (connections[connnum].type & TYPE_REGISTERED)
	  handle_disconnect(connections[connnum].socket,param2,
			    who_did_command);
	else
	  prnt(connections[connnum].socket,"You aren't registered\n");
	  break;

      case K_HELP:
	print_help(connections[connnum].socket, param2);
	break;

      case K_MOTD:
	print_motd(connections[connnum].socket);
        break;

      case K_SAVE:
	if(connections[connnum].type & TYPE_ADMIN)
	  handle_save(connections[connnum].socket,connections[connnum].nick);

	else
	  {
	    prnt(connections[connnum].socket,
		 "You don't have admin priv. to save tcm.pref file\n");
	  }
        break;

      case K_LOAD:
	if(connections[connnum].type & TYPE_OPER)
	  {
	    prnt(connections[connnum].socket,
		 "Loading tcm.pref file\n");
	    sendtoalldcc(SEND_OPERS_ONLY, "%s is loading tcm.pref\n",
			 connections[connnum].nick);
	    load_prefs();
	  }
	else
	  {
	    prnt(connections[connnum].socket,
		 "You don't have oper priv. to load tcm.pref file\n");
	  }
        break;

      case K_CLOSE:
	prnt(connections[connnum].socket,"Closing connection\n");
	closeconn(connnum);
	break;

/* Added by ParaGod */

      case K_OP:
	{
	  if (connections[connnum].type & TYPE_REGISTERED)
	    {
	      if (!param2)
		prnt(connections[connnum].socket,"Usage: op [nick]\n");
	      else
		op(config_entries.defchannel,param2); 
	    }
	  else
	    prnt(connections[connnum].socket,"You aren't registered\n");
	}
      break;

    case K_CYCLE:
      {
	if (connections[connnum].type & TYPE_REGISTERED)
	  {
	    leave(config_entries.defchannel);
	    sendtoalldcc(SEND_OPERS_ONLY, "I'm cycling.  Be right back.\n");
	    sleep(1);

	    /* probably on a cycle, we'd want the tcm to set
	     * the key as well...
	     */

	    if(config_entries.defchannel_key[0])
	      join(config_entries.defchannel,config_entries.defchannel_key); 
	    else
	      join(config_entries.defchannel,(char *)NULL);
	  }
	else
	  prnt(connections[connnum].socket,"You aren't registered\n");
      }
    break;

    case K_DIE:
      {
	if(!(connections[connnum].type & TYPE_TCM))
	  {
	   if(connections[connnum].type & TYPE_OPER) 
	     {
	       sendtoalldcc(SEND_ALL_USERS, "I've been ordered to quit irc, goodbye.");
	       toserv("QUIT :Dead by request!\n");
	       exit(1);
	     }
	   else
	     {
	       not_authorized(connections[connnum].socket);
	     }
	  }
	else
	  prnt(connections[connnum].socket,
	       "Disabled for remote tcm's\n");
      }
    /* End of stuff added by ParaGod */
    break;

    case K_TCMIDENT:
      break;

    case K_INFO:
      prnt(connections[connnum].socket,
	   "real server name [%s]\n", config_entries.rserver_name );

      if(config_entries.hybrid)
	prnt(connections[connnum].socket,"Hybrid server version %d\n",
	     config_entries.hybrid_version );
      else
	prnt(connections[connnum].socket,"Not hybrid server\n" );

      break;

    case K_KFIND:
      if(!(connections[connnum].type & TYPE_OPER))
	{
	  not_authorized(connections[connnum].socket);
	}
      else
	{
	  if(param2_orig)
	    kfind(connections[connnum].socket,param2_orig);
	  else
	    prnt(connections[connnum].socket, "Usage: .kfind <hostmask>\n");
	}
      break;

    case K_VMULTI:
      if(!(connections[connnum].type & TYPE_OPER))
	{
	  not_authorized(connections[connnum].socket);
	}
      else
	{
	  if (param2_orig) report_vmulti(connections[connnum].socket, atoi(param2_orig));
	  else report_vmulti(connections[connnum].socket, 4);
	}
      break;

    case K_LOCOPS:
      if(!(connections[connnum].type & TYPE_OPER))
	{
	  not_authorized(connections[connnum].socket);
	}
      else
	{
	  if(param2_orig)
	    {
	      toserv("LOCOPS :(%s) %s %s\n",
		     connections[connnum].nick,
		     param2_orig,
		     param3?param3:"");
	    }
	  else
	    {
	      prnt(connections[connnum].socket,
		   "Really, it would help if you said something\n");
	    }
	}
      break;

    case K_UNKLINE:
      {
        char *pattern;  /* u@h or nick */

	if( connections[connnum].type & TYPE_REGISTERED )
	  {
	    if(!param2)
	      {
		prnt(connections[connnum].socket,
		     "missing user@host \".unkline [user@host]\"\n");
		return;
	      }
	    pattern = param2;
	    sendtoalldcc(SEND_OPERS_ONLY,
			 "UNKLINE %s attempted by oper %s",
			 pattern,who_did_command);
	    toserv("UNKLINE %s\n",pattern);
	  }
	else
	  prnt(connections[connnum].socket,"You aren't registered\n");
      }
    break;

#ifndef NO_D_LINE_SUPPORT
    case K_DLINE:
      {
	char *reason;
        char *pattern;  /* u@h or nick */
	
	if( connections[connnum].type & TYPE_REGISTERED )
	  {
	    if(param2)
	      {
		pattern = param2;
		reason = param3;

#ifdef RESTRICT_REMOTE_DLINE
		if(route_entry.to_nick[0] != '\0')
		  {
		    sendtoalldcc(SEND_OPERS_ONLY,
				 "remote dline restricted on %s",
				 config_entries.dfltnick);
		  }
#else
		if(not_legal_remote(connections[connnum].type))
		  {
		    prnt(connections[connnum].socket,"You have no remote .dline privs");
		    return;
		  }
#endif
		    
		if(pattern && reason)
		  {
		    log_kline("DLINE",
			      pattern,
			      0,
			      who_did_command,
			      reason);

		    sendtoalldcc(SEND_OPERS_ONLY,
				 "dline %s : by oper %s %s",
				 pattern,
				 who_did_command,
				 reason);

#ifdef HIDE_OPER_IN_KLINES
                    toserv("DLINE %s :%s \n",
                           pattern,
                           reason);
#else
                    toserv("DLINE %s :%s by %s \n",
			   pattern,
			   reason,
			   who_did_command);
#endif
                  }
                else
                  {
                    prnt(connections[connnum].socket,
			 "missing nick/user@host reason \".dline [nick]|[user@host] reason\"\n");
                  }
              }
          }
	else
	  prnt(connections[connnum].socket,"You aren't registered\n");
      }
    break;
#endif

    default:
      prnt(connections[connnum].socket,"Unknown command [%s]\n",param1);
      break;
    }
}

/*
 * setup_allow()
 *
 * input	- nick to allow
 * output	- NONE
 * side effects	- nick is added to botnick allow list
 */

static void setup_allow(char *nick)
{
  char botnick[MAX_NICK+4];	/* Allow room for '<' and '>' */
  int i=0;
  int remove_allow = NO;
  int first_free = -1;
  placed;

  while(*nick == ' ')
    nick++;

  if(*nick == '-')
    {
      remove_allow = YES;
      nick++;
    }

  botnick[i++] = '<';
  while(*nick)
    {
      if(*nick == ' ')
	break;
      if(i >= MAX_NICK+1)
	break;
      botnick[i++] = *nick++;
    }

  botnick[i++] = '>';
  botnick[i] = '\0';

  first_free = -1;

  for( i = 0; i < MAX_ALLOW_SIZE ; i++ )
    {
      if( allow_nick[i][0] == '\0' )
	allow_nick[i][0] = '-';

      if( (allow_nick[i][0] == '-') && (first_free < 0))
	{
	  first_free = i;
	}

      if( !(strcasecmp(allow_nick[i],botnick)) )
	{
	  if(remove_allow)	/* make it so it no longer matches */
	    allow_nick[i][0] = '-';
	  return;
	}
    }
  /* Not found insert if room */
  if(first_free >= 0)
    {
      strcpy(allow_nick[first_free],botnick);
    }
  /* whoops. if first_free < 0 then.. I'll just ignore with nothing said */
}

/*
 * send_to_nick
 *
 * inputs	- nick to send to
 *		  buffer to send to nick
 * output	- NONE
 * side effects	- NONE
 */

static void send_to_nick(char *to_nick,char *buffer)
{
  int i;
  char dccbuff[DCCBUFF_SIZE];
  placed;

  strncpy(dccbuff,buffer,DCCBUFF_SIZE-2);
  strcat(dccbuff,"\n");

  for( i = 1; i < maxconns; i++ )
    {
      if( !(strcasecmp(to_nick,connections[i].nick)) )
	{
	  send(connections[i].socket, dccbuff, strlen(dccbuff), 0);
	}
    }
}

/*
 * test_ignore()
 *
 * inputs	- input from link
 * output	- YES if not to ignore NO if to ignore
 * side effects	- NONE
 */

static int test_ignore(char *line)
{
  char botnick[MAX_NICK+4];	/* Allow room for '<' and '>' */
  int i;
  placed;

  if(line[0] != '<')
    return(NO);

  for(i=0;i<MAX_NICK+3;)
    {
      if(*line == '@')return(NO);	/* Not even just a botnick */
      botnick[i++] = *line++; 
      if(*line == '>')
	break;
    }
  botnick[i++] = '>';
  botnick[i] = '\0';


  for(i=0;i<MAX_ALLOW_SIZE;i++)
    {
      if( !(strcasecmp(allow_nick[i],botnick) ) )
	return(NO);
    }
  return(YES);
}

/*
 * init_allow_nick(void)
 *
 * inputs	- NONE
 * output	- NONE
 * side effects	- The allow nick table is cleared out.
 */

void init_allow_nick()
{
  int i;
  placed;
  for(i=0;i<MAX_ALLOW_SIZE;i++)
    {
      allow_nick[i][0] = '-';
      allow_nick[i][1] = '\0';
    }
}

/*
 * not_legal_remote()
 *
 * inputs	- type of connection making request
 * output	- YES if its not a legal remote command,
 *		  i.e. connection has no remote privs
 * side effects	- NONE
 */

static int not_legal_remote(int type)
{
  placed;
  if( !(route_entry.to_nick[0]) ) /* not routing,
				   * its a kill etc. on local server
				   */
    return (NO);
  if(type & TYPE_CAN_REMOTE)
    return (NO);
  return(YES);
}

/*
 * set_actions
 *
 * inputs	- key one of "clone_act" "flood_act" "link_act"
 *		  "bot_act" "wingate_act" "socks_act" "sclone_act"
 *		  or NULL
 * output	- NONE
 * side effects -
 */

static void set_actions(int socket, char *key, char *action, char *reason,
			char *message )
{
  if(!key)
    {
      prnt(socket, "Current actions:\n");

      if(config_entries.clone_act[0])
	prnt(socket,
	     "Current clone_act: \"%s\"\n", config_entries.clone_act);
      else
	prnt(socket,
	     "Current clone_act: \"warn\"\n");
      if(config_entries.clone_reason[0])
	prnt(socket,
	     "Current clone_reason: \"%s\"\n", config_entries.clone_reason);

      if(config_entries.channel_report & CHANNEL_REPORT_CLONES)
	prnt(socket," Reporting clones to channel\n");

#ifdef AUTO_DLINE
      if(config_entries.vclone_act[0])
	prnt(socket,
	     "Current vclone_act: \"%s\"\n", config_entries.vclone_act);
      else
	prnt(socket,
	     "Current vclone_act: \"warn\"\n");
      if(config_entries.vclone_reason[0])
	prnt(socket,
	     "Current vclone_reason: \"%s\"\n", config_entries.vclone_reason);

      if(config_entries.channel_report & CHANNEL_REPORT_VCLONES)
	prnt(socket," Reporting vclones to channel\n");
#endif

#ifdef SERVICES
      if(config_entries.sclone_act[0])
	prnt(socket,
	     "Current sclone_act: \"%s\"\n", config_entries.sclone_act);
      else
	prnt(socket,
	     "Current sclone_act: \"warn\"\n");
      if(config_entries.sclone_reason[0])
	prnt(socket,
	     "Current sclone_reason: \"%s\"\n", config_entries.sclone_reason);

      if(config_entries.channel_report & CHANNEL_REPORT_SCLONES)
	prnt(socket," Reporting services clones to channel\n");
#endif

      if(config_entries.flood_act[0])
	prnt(socket,
	     "Current flood_act: \"%s\"\n", config_entries.flood_act);
      else
	prnt(socket,
	     "Current flood_act: \"warn\"\n");
      if(config_entries.flood_reason[0])
	prnt(socket,
	     "Current flood_reason: \"%s\"\n", config_entries.flood_reason);
      if(config_entries.channel_report & CHANNEL_REPORT_FLOOD)
	prnt(socket," Reporting flooders to channel\n");

      if(config_entries.ctcp_act[0])
	prnt(socket,
	     "Current ctcp_act: \"%s\"\n", config_entries.ctcp_act);
      else
	prnt(socket,
	     "Current ctcp_act: \"warn\"\n");
      if(config_entries.ctcp_reason[0])
	prnt(socket,
	     "Current ctcp_reason: \"%s\"\n", config_entries.ctcp_reason);
      if(config_entries.channel_report & CHANNEL_REPORT_CTCP)
	prnt(socket," Reporting ctcp flooders to channel\n");

#ifdef DETECT_DNS_SPOOFERS
      if(config_entries.spoof_act[0])
	prnt(socket,
	     "Current spoof_act: \"%s\"\n", config_entries.spoof_act);
      else
	prnt(socket,
	     "Current spoof_act: \"warn\"\n");
      if(config_entries.spoof_reason[0])
	prnt(socket,
	     "Current spoof_reason: \"%s\"\n", config_entries.spoof_reason);
      if(config_entries.channel_report & CHANNEL_REPORT_SPOOF)
	prnt(socket," Reporting DNS spoofers to channel\n");
#endif

      if(config_entries.spambot_act[0])
	prnt(socket,
	     "Current spambot_act: \"%s\"\n", config_entries.spambot_act);
      else
	prnt(socket,
	     "Current spambot_act: \"warn\"\n");
      if(config_entries.spambot_reason[0])
	prnt(socket,
	     "Current spambot_reason: \"%s\"\n", config_entries.spambot_reason);
      if(config_entries.channel_report & CHANNEL_REPORT_SPAMBOT)
	prnt(socket," Reporting spambots to channel\n");

      if(config_entries.link_act[0])
	prnt(socket,
	     "Current link_act: \"%s\"\n", config_entries.link_act);
      else
	prnt(socket,
	     "Current link_act: \"warn\"\n");
      if(config_entries.link_reason[0])
	prnt(socket,
	     "Current link_reason: \"%s\"\n", config_entries.link_reason);
      if(config_entries.channel_report & CHANNEL_REPORT_LINK)
	prnt(socket," Reporting Link Lookers to channel\n");

      if(config_entries.bot_act[0])
	prnt(socket,
	     "Current bot_act: \"%s\"\n", config_entries.bot_act);
      else
	prnt(socket,
	     "Current bot_act: \"warn\"\n");
      if(config_entries.bot_reason[0])
	prnt(socket,
	     "Current bot_reason: \"%s\"\n", config_entries.bot_reason);
      if(config_entries.channel_report & CHANNEL_REPORT_BOT)
	prnt(socket," Reporting BOTS to channel\n");

#ifdef DETECT_WINGATE
      if(config_entries.wingate_act[0])
	prnt(socket,
	     "Current wingate_act: \"%s\"\n", config_entries.wingate_act);
      else
	prnt(socket,
	     "Current wingate_act: \"warn\"\n");
      if(config_entries.wingate_reason[0])
	prnt(socket,
	     "Current wingate_reason: \"%s\"\n", config_entries.wingate_reason);
      if(config_entries.channel_report & CHANNEL_REPORT_WINGATE)
	prnt(socket," Reporting open wingates to channel\n");
#endif

#ifdef DETECT_SOCKS
      if(config_entries.socks_act[0])
	prnt(socket,
	     "Current socks_act: \"%s\"\n", config_entries.socks_act);
      else
	prnt(socket,
	     "Current socks_act: \"warn\"\n");
      if(config_entries.socks_reason[0])
	prnt(socket,
	     "Current socks_reason: \"%s\"\n", config_entries.socks_reason);
      if(config_entries.channel_report & CHANNEL_REPORT_SOCKS)
	prnt(socket," Reporting open socks to channel\n");
#endif

#ifdef SERVICES_DRONES
      if(config_entries.drones_act[0])
	prnt(socket,
	     "Current drones_act: \"%s\"\n", config_entries.drones_act);
      else
	prnt(socket,
	     "Current drones_act: \"warn\"\n");
      if(config_entries.drones_reason[0])
	prnt(socket,
	     "Current drones_reason: \"%s\"\n", config_entries.drones_reason);
      if(config_entries.channel_report & CHANNEL_REPORT_DRONE)
	prnt(socket," Reporting drones to channel\n");
#endif

    }
  else
    {
      if(!strcasecmp(key,"clone_act"))
	{
	  if(!action)
	    {
	      prnt(socket,
		   "Set clone_act to \"warn\", was \"%s\"\n",
		   config_entries.clone_act);
	      config_entries.clone_act[0] = '\0';

	    }
	  else
	    {
	      prnt(socket,
		   "Set clone_act to \"%s\", was \"%s\"\n",
		   action, config_entries.clone_act);
	      strncpy(config_entries.clone_act, action, 
		       sizeof(config_entries.clone_act));

	      if(reason)
		{
		  prnt(socket,
		       "Set clone_reason to \"%s\", was \"%s\"\n",
		       reason, config_entries.clone_reason);
		  strncpy(config_entries.clone_reason, reason, 
			  sizeof(config_entries.clone_reason));
		}
	    }

	  if(message)
	    {
	      if(!strcasecmp(message,"yes"))
		{
		  config_entries.channel_report |= CHANNEL_REPORT_CLONES;
		}
	      else if(!strcasecmp(message,"no"))
		{
		  config_entries.channel_report &= ~CHANNEL_REPORT_CLONES;
		}
	    }
	}
#ifdef AUTO_DLINE
      else if(!strcasecmp(key,"vclone_act"))
	{
	  if(!action)
	    {
	      prnt(socket,
		   "Set vclone_act to \"warn\", was \"%s\"\n",
		   config_entries.vclone_act);
	      config_entries.vclone_act[0] = '\0';

	    }
	  else
	    {
	      prnt(socket,
		   "Set vclone_act to \"%s\", was \"%s\"\n",
		   action, config_entries.vclone_act);
	      strncpy(config_entries.vclone_act, action, 
		       sizeof(config_entries.vclone_act));

	      if(reason)
		{
		  prnt(socket,
		       "Set vclone_reason to \"%s\", was \"%s\"\n",
		       reason, config_entries.vclone_reason);
		  strncpy(config_entries.vclone_reason, reason, 
			  sizeof(config_entries.vclone_reason));
		}

	    }

	  if(message)
	    {
	      if(!strcasecmp(message,"yes"))
		{
		  config_entries.channel_report |= CHANNEL_REPORT_VCLONES;
		}
	      else if(!strcasecmp(message,"no"))
		{
		  config_entries.channel_report &= ~CHANNEL_REPORT_VCLONES;
		}
	    }
	}
#endif
#ifdef SERVICES
      else if(!strcasecmp(key,"sclone_act"))
	{
	  if(!action)
	    {
	      prnt(socket,
		   "Set sclone_act to \"warn\", was \"%s\"\n",
		   config_entries.sclone_act);
	      config_entries.sclone_act[0] = '\0';

	    }
	  else
	    {
	      prnt(socket,
		   "Set sclone_act to \"%s\", was \"%s\"\n",
		   action, config_entries.sclone_act);
	      strncpy(config_entries.sclone_act, action, 
		       sizeof(config_entries.sclone_act));

	      if(reason)
		{
		  prnt(socket,
		       "Set sclone_reason to \"%s\", was \"%s\"\n",
		       reason, config_entries.sclone_reason);
		  strncpy(config_entries.sclone_reason, reason, 
			  sizeof(config_entries.sclone_reason));
		}

	    }

	  if(message)
	    {
	      if(!strcasecmp(message,"yes"))
		{
		  config_entries.channel_report |= CHANNEL_REPORT_SCLONES;
		}
	      else if(!strcasecmp(message,"no"))
		{
		  config_entries.channel_report &= ~CHANNEL_REPORT_SCLONES;
		}
	    }
	}
#endif
      else if(!strcasecmp(key,"ctcp_act"))
	{
	  if(!action)
	    {
	      prnt(socket,
		   "Set ctcp_act to \"warn\", was \"%s\"\n",
		   config_entries.ctcp_act);
	      config_entries.ctcp_act[0] = '\0';
	    }
	  else
	    {
	      prnt(socket,
		   "Set ctcp_act to \"%s\", was \"%s\"\n",
		   action, config_entries.ctcp_act);
	      strncpy(config_entries.ctcp_act, action, 
		      sizeof(config_entries.ctcp_act));

	      if(reason)
		{
		  prnt(socket,
		       "Set ctcp_reason to \"%s\", was \"%s\"\n",
		       reason, config_entries.ctcp_reason);
		  strncpy(config_entries.ctcp_reason, reason, 
			  sizeof(config_entries.ctcp_reason));
		}
	    }

	  if(message)
	    {
	      if(!strcasecmp(message,"yes"))
		{
		  config_entries.channel_report |= CHANNEL_REPORT_CTCP;
		}
	      else if(!strcasecmp(message,"no"))
		{
		  config_entries.channel_report &= ~CHANNEL_REPORT_CTCP;
		}
	    }
	}
      else if(!strcasecmp(key,"flood_act"))
	{
	  if(!action)
	    {
	      prnt(socket,
		   "Set flood_act to \"warn\", was \"%s\"\n",
		   config_entries.flood_act);
	      config_entries.flood_act[0] = '\0';
	    }
	  else
	    {
	      prnt(socket,
		   "Set flood_act to \"%s\", was \"%s\"\n",
		   action, config_entries.flood_act);
	      strncpy(config_entries.flood_act, action, 
		      sizeof(config_entries.flood_act));

	      if(reason)
		{
		  prnt(socket,
		       "Set flood_reason to \"%s\", was \"%s\"\n",
		       reason, config_entries.flood_reason);
		  strncpy(config_entries.flood_reason, reason, 
			  sizeof(config_entries.flood_reason));
		}
	    }

	  if(message)
	    {
	      if(!strcasecmp(message,"yes"))
		{
		  config_entries.channel_report |= CHANNEL_REPORT_FLOOD;
		}
	      else if(!strcasecmp(message,"no"))
		{
		  config_entries.channel_report &= ~CHANNEL_REPORT_FLOOD;
		}
	    }
	}
      else if(!strcasecmp(key,"link_act"))
	{
	  if(!action)
	    {
	      prnt(socket,
		   "Set link_act to \"warn\", was \"%s\"\n",
		   config_entries.link_act);
	      config_entries.link_act[0] = '\0';
	    }
	  else
	    {
	      prnt(socket,
		   "Set link_act to \"%s\", was \"%s\"\n",
		   action, config_entries.link_act);
	      strncpy(config_entries.link_act, action, 
		      sizeof(config_entries.link_act));

	      if(reason)
		{
		  prnt(socket,
		       "Set link_reason to \"%s\", was \"%s\"\n",
		       reason, config_entries.link_reason);
		  strncpy(config_entries.link_reason, reason, 
			  sizeof(config_entries.link_reason));
		}
	    }

	  if(message)
	    {
	      if(!strcasecmp(message,"yes"))
		{
		  config_entries.channel_report |= CHANNEL_REPORT_LINK;
		}
	      else if(!strcasecmp(message,"no"))
		{
		  config_entries.channel_report &= ~CHANNEL_REPORT_LINK;
		}
	    }
	}
      else if(!strcasecmp(key,"bot_act"))
	{
	  if(!action)
	    {
	      prnt(socket,
		   "Set bot_act to \"warn\", was \"%s\"\n",
		     config_entries.bot_act);
	      config_entries.bot_act[0] = '\0';
	    }
	  else
	    {
	      prnt(socket,
		   "Set bot_act to \"%s\", was \"%s\"\n",
		     action, config_entries.bot_act);
	      strncpy(config_entries.bot_act,action,
		      sizeof(config_entries.bot_act));

	      if(reason)
		{
		  prnt(socket,
		       "Set bot_reason to \"%s\", was \"%s\"\n",
		       reason, config_entries.bot_reason);
		  strncpy(config_entries.bot_reason, reason, 
			  sizeof(config_entries.bot_reason));
		}
	    }

	  if(message)
	    {
	      if(!strcasecmp(message,"yes"))
		{
		  config_entries.channel_report |= CHANNEL_REPORT_BOT;
		}
	      else if(!strcasecmp(message,"no"))
		{
		  config_entries.channel_report &= ~CHANNEL_REPORT_BOT;
		}
	    }
	}
      else if(!strcasecmp(key,"spambot_act"))
	{
	  if(!action)
	    {
	      prnt(socket,
		   "Set spambot_act to \"warn\", was \"%s\"\n",
		     config_entries.spambot_act);
	      config_entries.spambot_act[0] = '\0';
	    }
	  else
	    {
	      prnt(socket,
		   "Set spambot_act to \"%s\", was \"%s\"\n",
		     action, config_entries.spambot_act);
	      strncpy(config_entries.spambot_act,action,
		      sizeof(config_entries.spambot_act));

	      if(reason)
		{
		  prnt(socket,
		       "Set spambot_reason to \"%s\", was \"%s\"\n",
		       reason, config_entries.spambot_reason);
		  strncpy(config_entries.spambot_reason, reason, 
			  sizeof(config_entries.spambot_reason));
		}
	    }

	  if(message)
	    {
	      if(!strcasecmp(message,"yes"))
		{
		  config_entries.channel_report |= CHANNEL_REPORT_SPAMBOT;
		}
	      else if(!strcasecmp(message,"no"))
		{
		  config_entries.channel_report &= ~CHANNEL_REPORT_SPAMBOT;
		}
	    }
	}
#ifdef DETECT_DNS_SPOOFERS
      else if(!strcasecmp(key,"spoof_act"))
	{
	  if(!action)
	    {
	      prnt(socket,
		   "Set spoof_act to \"warn\", was \"%s\"\n",
		     config_entries.spoof_act);
	      config_entries.spoof_act[0] = '\0';
	    }
	  else
	    {
	      prnt(socket,
		   "Set spoof_act to \"%s\", was \"%s\"\n",
		     action, config_entries.spoof_act);
	      strncpy(config_entries.spoof_act,action,
		      sizeof(config_entries.spoof_act));

	      if(reason)
		{
		  prnt(socket,
		       "Set spoof_reason to \"%s\", was \"%s\"\n",
		       reason, config_entries.spoof_reason);
		  strncpy(config_entries.bot_reason, reason, 
			  sizeof(config_entries.spoof_reason));
		}
	    }

	  if(message)
	    {
	      if(!strcasecmp(message,"yes"))
		{
		  config_entries.channel_report |= CHANNEL_REPORT_SPOOF;
		}
	      else if(!strcasecmp(message,"no"))
		{
		  config_entries.channel_report &= ~CHANNEL_REPORT_SPOOF;
		}
	    }
	}
#endif
#ifdef DETECT_WINGATE
      else if(!strcasecmp(key,"wingate_act"))
	{
	  if(!action)
	    {
	      prnt(socket,
		   "Set wingate_act to \"warn\", was \"%s\"\n",
		   config_entries.wingate_act);
	      config_entries.wingate_act[0] = '\0';
	    }
	  else
	    {
	      prnt(socket,
		   "Set wingate_act to \"%s\", was \"%s\"\n",
		   action, config_entries.wingate_act);
	      strncpy(config_entries.wingate_act, action, 
		      sizeof(config_entries.wingate_act));

	      if(reason)
		{
		  prnt(socket,
		       "Set wingate_reason to \"%s\", was \"%s\"\n",
		       reason, config_entries.wingate_reason);
		  strncpy(config_entries.wingate_reason, reason, 
			  sizeof(config_entries.wingate_reason));
		}
	    }

	  if(message)
	    {
	      if(!strcasecmp(message,"yes"))
		{
		  config_entries.channel_report |= CHANNEL_REPORT_WINGATE;
		}
	      else if(!strcasecmp(message,"no"))
		{
		  config_entries.channel_report &= ~CHANNEL_REPORT_WINGATE;
		}
	    }
	}
#endif
#ifdef DETECT_SOCKS
      else if(!strcasecmp(key,"socks_act"))
	{
	  if(!action)
	    {
	      prnt(socket,
		   "Set socks_act to \"warn\", was \"%s\"\n",
		   config_entries.socks_act);
	      config_entries.socks_act[0] = '\0';
	    }
	  else
	    {
	      prnt(socket,
		   "Set socks_act to \"%s\", was \"%s\"\n",
		   action, config_entries.socks_act);
	      strncpy(config_entries.socks_act, action,
		       sizeof(config_entries.socks_act));

	      if(reason)
		{
		  prnt(socket,
		       "Set socks_reason to \"%s\", was \"%s\"\n",
		       reason, config_entries.socks_reason);
		  strncpy(config_entries.socks_reason, reason, 
			  sizeof(config_entries.socks_reason));
		}
	    }

	  if(message)
	    {
	      if(!strcasecmp(message,"yes"))
		{
		  config_entries.channel_report |= CHANNEL_REPORT_SOCKS;
		}
	      else if(!strcasecmp(message,"no"))
		{
		  config_entries.channel_report &= ~CHANNEL_REPORT_SOCKS;
		}
	    }
	}
#endif
#ifdef SERVICES_DRONES
      else if(!strcasecmp(key,"drones_act"))
	{
	  if(!action)
	    {
	      prnt(socket,
		   "Set drones_act to \"warn\", was \"%s\"\n",
		   config_entries.drones_act);
	      config_entries.drones_act[0] = '\0';
	    }
	  else
	    {
	      prnt(socket,
		   "Set drones_act to \"%s\", was \"%s\"\n",
		   action, config_entries.drones_act);
	      strncpy(config_entries.drones_act, action, 
		      sizeof(config_entries.drones_act));

	      if(reason)
		{
		  prnt(socket,
		       "Set drones_reason to \"%s\", was \"%s\"\n",
		       reason, config_entries.drones_reason);
		  strncpy(config_entries.drones_reason, reason, 
			  sizeof(config_entries.drones_reason));
		}
	    }

	  if(message)
	    {
	      if(!strcasecmp(message,"yes"))
		{
		  config_entries.channel_report |= CHANNEL_REPORT_DRONE;
		}
	      else if(!strcasecmp(message,"no"))
		{
		  config_entries.channel_report &= ~CHANNEL_REPORT_DRONE;
		}
	    }
	}
#endif
      else
	{
	  prnt(socket,"Unknown action\n");
	}
    }
}

/*
 * is_kline_time()
 *
 * inputs          - pointer to ascii string in
 * output          - 0 if not an integer number, else the number
 * side effects    - none
 */

static int is_kline_time(char *p)
{
  int result = 0;
  placed;

  while(*p)
    {
      if(isdigit(*p))
        {
          result *= 10;
          result += ((*p) & 0xF);
          p++;
        }
      else
        return(0);
    }

  /* in the degenerate case where oper does a /quote kline 0 user@host :reason
   * i.e. they specifically use 0, I am going to return 1 instead
   * as a return value of non-zero is used to flag it as a temporary kline
   */

  if(!result)
    result = 1;
  return(result);
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

static void set_umode(int connnum, char *flags, char *registered_nick)
{
  int i;
  int reversing;
  int z;
  int found = NO;
  unsigned long type;
  unsigned long new_type;

  /* UMODE! -pro */
  
  if(!registered_nick)
    {
      for( i=0; flags[i]; i++ )
	{
	  switch(flags[i])
	    {
	    case 'e': type = TYPE_ECHO; break;
	    case 'i': type = TYPE_INVS; break;
	    case 'k': type = TYPE_KLINE; break;
	    case 'l': type = TYPE_LINK; break;
	    case 'm': type = TYPE_MOTD; break;
	    case 'o': type = TYPE_LOCOPS; break;
	    case 'p': type = TYPE_PARTYLINE; break;
	    case 's': type = TYPE_STAT; break;
	    case 'w': type = TYPE_WARN; break;

	    case 'I':
	      if (connections[connnum].type & TYPE_ADMIN)
		type = TYPE_INVM ;
	      else
		type = 0;
	      break;

	    case 'D':
	      if (connections[connnum].type & TYPE_ADMIN)
		type = TYPE_DLINE ;
	      else
		type = 0;
	      break;

	    case 'G':
	      if (connections[connnum].type & TYPE_ADMIN)
		type = TYPE_GLINE ;
	      else
		type = 0;
	      break;

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

      prnt(connections[connnum].socket,
	   "Your flags are now: +%s\n",
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

	  if (!strcasecmp(registered_nick, connections[z].registered_nick))
	    {
	      found = YES;

	      for(i=0; flags[i] ;i++)
		{
		  switch(flags[i])
		    {
		    case 'D': type = TYPE_DLINE; break;
		    case 'G': type = TYPE_GLINE; break;
		    case 'I': type = TYPE_INVM; break;
		    case 'K': type = TYPE_REGISTERED; break;
		    case 'O': type = TYPE_OPER; break;
		    case 'S': type = TYPE_SUSPENDED; break;
		    case 'e': type = TYPE_ECHO; break;
		    case 'i': type = TYPE_INVS; break;
		    case 'k': type = TYPE_KLINE; break;
		    case 'l': type = TYPE_LINK; break;
		    case 'm': type = TYPE_MOTD; break;
		    case 'o': type = TYPE_LOCOPS; break;
		    case 'p': type = TYPE_PARTYLINE; break;
		    case 's': type = TYPE_STAT; break;
		    case 'w': type = TYPE_WARN; break;
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

	      prnt(connections[connnum].socket,
		   "Flags for %s are now: +%s\n",
		   registered_nick, type_show(connections[z].type));

	      prnt(connections[z].socket,
		   "Flags for you changed by %s are now: +%s\n",
		   connections[connnum].nick,
		   type_show(connections[z].type));

	    }
	}

      if(!found)
	{
	  new_type=0;

	  for(z=0;userlist[z].user[0];z++)
	    {
	      if(userlist[z].type & TYPE_TCM)
		continue;

	      if(found)
		break;

	      if (!strcasecmp(registered_nick, userlist[z].usernick))
		{
		  found = YES;

		  new_type = userlist[z].type;

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
			case 'K': type = TYPE_REGISTERED; break;
			case 'G': type = TYPE_GLINE; break;
			case 'D': type = TYPE_DLINE; break;
			case 'O': type = TYPE_OPER; break;
			case 'S': type = TYPE_SUSPENDED; break;
			case 'k': type = TYPE_KLINE; break;
			case 'p': type = TYPE_PARTYLINE; break;
			case 's': type = TYPE_STAT; break;
			case 'w': type = TYPE_WARN; break;
			case 'e': type = TYPE_ECHO; break;
			case 'i': type = TYPE_INVS; break;
			case 'l': type = TYPE_LINK; break;
			case 'm': type = TYPE_MOTD; break;
			case 'o': type = TYPE_LOCOPS; break;
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

		  prnt(connections[connnum].socket,
		       "Startup flags for %s are now: +%s\n",
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

static void save_umodes(char *registered_nick, unsigned long type)
{
  FILE *fp;
  char user_pref[MAX_BUFF];

  (void)sprintf(user_pref,"%s.pref",registered_nick);

  if(!(fp = fopen(user_pref,"w")))
    {
      sendtoalldcc(SEND_ALL_USERS, "Couldn't open %s for write\n",
		   user_pref );
      return;
    }

  fprintf(fp,"%lu\n",
	  type & ~(TYPE_TCM|TYPE_ADMIN|TYPE_PENDING));
  (void)fclose(fp);
}

/*
 * load_umodes
 *
 * input	- connection id 
 * output	- none
 * side effect	- 
 */

static void load_umodes(int connect_id)
{
  FILE *fp;
  char user_pref[MAX_BUFF];
  char type_string[32];
  char *p;
  unsigned long type;

  (void)sprintf(user_pref,"%s.pref",connections[connect_id].registered_nick);

  if(!(fp = fopen(user_pref,"r")))
    {
      if(!(fp = fopen(user_pref,"w")))
	{
	  sendtoalldcc(SEND_ALL_USERS, "Couldn't open %s for write\n",
		       user_pref );
	  return;
	}
      type = connections[connect_id].type;
      fprintf(fp,"%lu\n",
	      type & ~(TYPE_TCM|TYPE_ADMIN|TYPE_PENDING));
      (void)fclose(fp);
      return;
    }

  fgets(type_string,30,fp);
  (void)fclose(fp);

  if( (p = strchr(type_string,'\n')) )
     *p = '\0';
  
  sscanf(type_string,"%lu",&type);
  type &= ~(TYPE_TCM|TYPE_ADMIN|TYPE_PENDING);

  connections[connect_id].type &= TYPE_ADMIN;
  connections[connect_id].type |= type;

  if( type & TYPE_SUSPENDED )
    {
      type = type & TYPE_SUSPENDED;
    }

  prnt(connections[connect_id].socket, "Set umodes from %s\n", user_pref );
  prnt(connections[connect_id].socket, "Your current flags are now: %s\n",
       type_show(connections[connect_id].type));
}

/*
 * find_user_umodes
 *
 * input	- registered nick
 * output	- none
 * side effect	- 
 */

static unsigned long find_user_umodes(char *registered_nick)
{
  FILE *fp;
  char user_pref[MAX_BUFF];
  char type_string[32];
  char *p;
  int  unsigned long type;

  (void)sprintf(user_pref,"%s.pref",registered_nick);

  if(!(fp = fopen(user_pref,"r")))
    {
      return 0L;
    }

  if( !(fgets(type_string,30,fp)) )
    {
      (void)fclose(fp);
      return 0L;
    }

  (void)fclose(fp);

  if( (p = strchr(type_string,'\n')) )
     *p = '\0';

  sscanf(type_string,"%lu",&type);

  type &= ~(TYPE_TCM|TYPE_ADMIN|TYPE_PENDING);

  return type;
}

/*
 * show_user_umodes
 *
 * input	- registered nick
 * output	- none
 * side effect	- 
 */

static void show_user_umodes(int socket, char *registered_nick)
{
  FILE *fp;
  char user_pref[MAX_BUFF];
  char type_string[32];
  int  i;
  unsigned long type;
  unsigned long pref_type;
  char *p;
  int  found = NO;

  for(i=0; userlist[i].user[0]; i++)
    {
      if(userlist[i].type & TYPE_TCM)
	continue;

      if (!strcasecmp(registered_nick, userlist[i].usernick))
	{
	  type = userlist[i].type;
	  found = YES;
	  break;
	}
    }

  if(!found)
    {
      prnt(socket,"Can't find user [%s]\n", registered_nick );
      return;
    }
     
  (void)sprintf(user_pref,"%s.pref",registered_nick);

  if(!(fp = fopen(user_pref,"r")))
    {
      prnt(socket,"%s user flags are %s\n", 
	   registered_nick,
	   type_show(type));
      return;
    }

  type &= TYPE_ADMIN ;

  fgets(type_string,30,fp);
  (void)fclose(fp);

  if( (p = strchr(type_string,'\n')) )
     *p = '\0';

  sscanf(type_string,"%lu",&pref_type);

  pref_type &= ~(TYPE_TCM|TYPE_ADMIN|TYPE_PENDING);

  prnt(socket,"%s user flags are %s\n", 
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

static void register_oper(int connnum, char *password, char *who_did_command)
{
  if(password)
    {
      if( islegal_pass(connnum, password) )
	{
	  load_umodes(connnum);
	  
	  if( connections[connnum].type & TYPE_SUSPENDED)
	    {
	      prnt(connections[connnum].socket,
		   "You are suspended\n");
	      sendtoalldcc(SEND_OPERS_ONLY,"%s is suspended\n",
			   who_did_command);
	      if (connections[connnum].type &
		  (TYPE_PENDING|~TYPE_TCM))
		connections[connnum].type &= ~TYPE_PENDING;
	    }
	  else
	    {
	      prnt(connections[connnum].socket,
		   "You are now registered\n");
	      sendtoalldcc(SEND_OPERS_ONLY,
			   "%s has registered\n",
			   who_did_command);
	      if (connections[connnum].type &
		  (TYPE_PENDING|~TYPE_TCM))
		connections[connnum].type &= ~TYPE_PENDING;
	    }
	}
      else
	{
	  prnt(connections[connnum].socket,"illegal password\n");
	  sendtoalldcc(SEND_OPERS_ONLY,
		       "illegal password from %s\n",
		       who_did_command);
	}
    }
  else
    {
      prnt(connections[connnum].socket,"missing password\n");
    }
}

/*
 * list_opers
 *
 * inputs	- socket
 * output	- NONE
 * side effects	- list current opers on socket
 */

static void list_opers(int socket)
{
  int i;
  
  for(i=0;i<MAXUSERS;i++)
    {
      if(!userlist[i].user[0])
	break;

      if(userlist[i].type & TYPE_TCM)
	{
	  prnt(socket,
	       "%s [%s@%s] %s\n",
	       userlist[i].user,
	       userlist[i].host,
	       userlist[i].usernick,
	       type_show(userlist[i].type));
	}
      else
	{
	  prnt(socket,
	       "(%s) %s@%s %s\n",
	       (userlist[i].usernick) ? userlist[i].usernick:"unknown",
	       userlist[i].user,
	       userlist[i].host,
	       type_show(userlist[i].type));
	}
    }
}

/*
 * list_tcmlist
 *
 * inputs	- socket
 * output	- NONE
 * side effects	- list tcm list on socket
 */

static void list_tcmlist(int socket)
{
  int i;
  
  for(i=0; i < MAXTCMS; i++)
    {
      if(!tcmlist[i].host[0])
	break;
      prnt(socket,"%s@%s\n", tcmlist[i].theirnick, tcmlist[i].host);
    }
}

/*
 * list_exemptions
 *
 * inputs	- socket
 * output	- NONE
 * side effects	- list current exemptions on socket
 */

static void list_exemptions(int socket)
{
  int i;

  for(i=0;i<MAXHOSTS;i++)
    {
      if(!hostlist[i].host[0])
	break;
      prnt(socket,"%s@%s\n", hostlist[i].user, hostlist[i].host);
    }
}

/*
 * handle_allow
 *
 * inputs	- socket
 *		- param 
 *		- who did the command
 * output	- NONE
 * side effects	- user is warned they aren't an oper
 */

static void handle_allow(int socket, char *param, char *who_did_command)
{
  int i;
  int found_one=NO;

  if(param)
    {
      if(*param == '-')
	sendtoalldcc(SEND_OPERS_ONLY,
		     "allow of %s turned off by %s\n",
		     param+1,
		     who_did_command);
      else
	sendtoalldcc(SEND_OPERS_ONLY,
		     "allow of %s turned on by %s\n",
		     param,
		     who_did_command);
		
      setup_allow(param);
    }
  else
    {
      for(i = 0; i < MAX_ALLOW_SIZE; i++ )
	{
	  if(allow_nick[i][0] != '-')
	    {
	      found_one = YES;
	      prnt(socket,"allowed: %s\n",allow_nick[i]);
	    }
	}
	      
      if(!found_one)
	{
	  prnt(socket,"There are no tcm allows in place\n");
	}
    }
}

/*
 * list_connections
 *
 * inputs	- socket
 * output	- NONE
 * side effects	- active connections are listed to socket
 */

static void list_connections(int socket)
{
  int i;

  for (i=1;i<maxconns;i++)
    {
      if (connections[i].socket != INVALID)
	{
	  if(connections[i].registered_nick[0])
	    {
	      prnt(socket,
		   "%s/%s %s (%s@%s) is connected\n",
		   connections[i].nick,
		   connections[i].registered_nick,
		   type_show(connections[i].type),
		   connections[i].user,
		   connections[i].host );
	    }
	  else
	    {
	      prnt(socket,
		   "%s %s (%s@%s) is connected\n",
		   connections[i].nick,
		   type_show(connections[i].type),
		   connections[i].user,
		   connections[i].host );
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

static void handle_disconnect(int socket,char *nickname,char *who_did_command)
{
  char *type;
  int  i;

  if (!nickname)
    prnt(socket,
	 "Usage: disconnect <nickname>\n");
  else
    {
      for (i=1;i<maxconns;++i)
	if (socket != INVALID &&
	    !strcasecmp(nickname,connections[i].nick))
	  {
	    type = "user";
	    if(connections[i].type & TYPE_OPER)
	      type = "oper";
	    if(connections[i].type & TYPE_TCM)
	      type = "tcm";

	    prnt(socket,
		 "Disconnecting %s %s\n",
		 type,
		 connections[i].nick);
	    prnt(socket,
		 "You have been disconnected by oper %s\n",
		 who_did_command);
	    closeconn(i);
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

static void handle_save(int socket,char *nick)
{
  prnt(socket, "Saving tcm.pref file\n");
  sendtoalldcc(SEND_OPERS_ONLY, "%s is saving tcm.pref\n", nick);
  save_prefs();
}


/*
 * handle_gline
 *
 * inputs	- socket
 *		- pattern to gline
 *		- reason to gline
 * output	- NONE
 * side effects	- 
 */

static void handle_gline(int socket,char *pattern,char *reason,
			 char *who_did_command)
{
  char dccbuff[MAX_BUFF];

  if(pattern)
    {
      if( reason )
	{
	  /* Removed *@ prefix from kline parameter -tlj */
	  sendtoalldcc(SEND_OPERS_ONLY,
		       "gline %s : %s added by oper %s",
		       pattern,reason,
		       who_did_command,
		       who_did_command);
			
	  log_kline("GLINE",
		    pattern,
		    0,
		    who_did_command,
		    reason);
			
	  toserv("KLINE %s :%s by %s\n",
		 pattern,
		 format_reason(reason),
		 who_did_command);

	  sprintf(dccbuff,".KLINE %s :%s by %s\n",
		  pattern,format_reason(reason),who_did_command);

	  sendto_all_linkedbots(dccbuff);
	}
      else
	{
	  prnt(socket,
	       "missing reason \"kline [nick]|[user@host] reason\"\n");
	}
    }
  else
    {
      prnt(socket,
	   "missing nick/user@host \".kline [nick]|[user@host] reason\"\n");
    }
}

/*
 * not_authorized
 *
 * inputs	- socket
 * output	- NONE
 * side effects	- user is warned they aren't an oper
 */

static void not_authorized(int socket)
{
  prnt(socket,"Only authorized opers may use this command\n");
}
