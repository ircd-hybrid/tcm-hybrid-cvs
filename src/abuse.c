#include "setup.h"

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <stdarg.h>

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
#include "token.h"
#include "bothunt.h"
#include "userlist.h"
#include "serverif.h"
#include "logging.h"
#include "abuse.h"

static char* suggest_host(char *);

static char *version="$Id: abuse.c,v 1.12 2001/07/03 03:47:01 wcampbel Exp $";

/*
 * do_a_kline()
 *
 * inputs	- command used i.e. ".kline", ".kclone" etc.
 *		- kline_time if non-zero its HYBRID and its a tkline
 *		- pattern (i.e. nick or user@host)
 *		- reason
 *		- who asked for this (oper)
 * output	- NONE
 * side effects	- someone gets k-lined
 *
 *
 */

void do_a_kline(char *command_name,int kline_time, char *pattern,
		char *reason,char *who_did_command)
{
#ifdef DEBUGMODE
  placed;
#endif

#ifdef RESTRICT_REMOTE_KLINE
  if( route_entry.to_nick[0] )
    sendtoalldcc(SEND_OPERS_ONLY, "remote kline restricted on %s\n",
		 config_entries.dfltnick);
#endif

  if(pattern == NULL)
    return;

  if(reason == NULL)
    return;

  /* Removed *@ prefix from kline parameter -tlj */

  if(config_entries.hybrid)
    {
      if(kline_time)
	sendtoalldcc(SEND_OPERS_ONLY,
		     "%s %d %s : %s added by oper %s\n",
		     command_name,
		     kline_time,
		     pattern,
		     format_reason(reason),
		     who_did_command);
      else
	sendtoalldcc(SEND_OPERS_ONLY,
		     "%s %s : %s added by oper %s\n",
		     command_name,
		     pattern,
		     format_reason(reason),
		     who_did_command);
    }
  else
    {
      sendtoalldcc(SEND_OPERS_ONLY,
		   "%s %s : %s added by oper %s\n",
		   command_name,
		   pattern,
		   format_reason(reason),
		   who_did_command);
    }

  /* If the kline doesn't come from the local tcm
   * and tcm has been compiled to restrict remote klines
   * then just ignore it
   */

  log_kline("KLINE",
	    pattern,
	    kline_time,
	    who_did_command,
	    reason);

  if(config_entries.hybrid)
    {
#ifdef HIDE_OPER_IN_KLINES
      if(kline_time)
	toserv("KLINE %d %s :%s\n",
	       kline_time,pattern,
	       reason);
      else
	toserv("KLINE %s :%s\n",
	       pattern,
	       reason);
#else
      if(kline_time)
	toserv("KLINE %d %s :%s by %s\n",
	       kline_time,pattern,reason,
	       who_did_command);
      else
	toserv("KLINE %s :%s by %s\n",
	       pattern,reason,
	       who_did_command);
#endif
    }
  else
    {
#ifdef HIDE_OPER_IN_KLINES
      toserv("KLINE %s :%s\n",
	     pattern,
	     format_reason(reason));
#else
      toserv("KLINE %s :%s by %s\n",
	     pattern,format_reason(reason),
	     who_did_command);
#endif
    }
}

/*
 * suggest_kill_kline
 *
 *  Suggest a kline or kill for an oper to use
 * inputs	- reason, integer corresponding to case which kline is needed
 *		- nick
 *	        - user name
 *	  	- host name
 *	  	- identd, its identd'ed or not
 * output	- none
 * side effects	- connected opers are dcc'ed a suggested kline or kill
 * 
 * I have to reassemble user and host back into a u@h, in order
 * to do matching of users not to KILL or KLINE. urgh. This seems
 * silly as I have had to split them elsewhere. 
 *
 *	- Dianora 
 *		Changes by pro, 6/2000.
 */

void suggest_kill_kline(int reason,
			char *nick,
			char *user,
			char *host,
			int different,
			int identd)
{
  char suggested_user[MAX_USER+1];
  char *suggested_host;

  /* Don't kill or kline exempted users */  
  if(okhost(user, host))
    return;

  if( (strchr(host,'*') == NULL) )
    {
      report(SEND_ALL_USERS,
	     CHANNEL_REPORT_SPOOF,
	     "Bogus dns spoofed host %s@%s\n",
	     user, host );
      return;
    }

  if( (strchr(host,'?') == NULL) )
    {
      report(SEND_ALL_USERS,
	     CHANNEL_REPORT_SPOOF,
	     "Bogus dns spoofed host %s@%s\n",
	     user, host );
      return;
    }

  if(identd)
    {
      strcpy(suggested_user,"*");
      strcat(suggested_user,user);
    }
  else
    {
      strcpy(suggested_user,"~*");
    }
  suggested_host=suggest_host(host);
/* 
 * Completely redone to conform to A: in config.
 * 	-pro 6/2000
 */
 switch (reason)
   {
   case R_CFLOOD:  /* connect flooding drones */
     if (config_entries.cflood_act[0] && config_entries.autopilot)
       {
	 if(strncasecmp(config_entries.cflood_act,"kline",5) == 0)
	   {
	     sendtoalldcc(SEND_OPERS_ONLY,
	       "Connect flooder detected %s@%s,auto-klining...\n",
               suggested_user, suggested_host);

             toserv("%s %s@%s :%s\n",
		    config_entries.cflood_act,
		    suggested_user, suggested_host,
		    config_entries.cflood_reason);
	   }
	 else if (strncasecmp(config_entries.cflood_act, "dline", 5) == 0)
	   {
	     sendtoalldcc(SEND_OPERS_ONLY,
		"Connect flooder detected %s@%s,auto-\002d\002lining...\n",
		suggested_user, host);
	     toserv("%s %s :%s\n",
		config_entries.cflood_act,
		host,
		config_entries.cflood_reason);
	   }
	 else if (strncasecmp(config_entries.cflood_act, "warn", 4) == 0)
	   {
	     sendtoalldcc(SEND_WARN_ONLY,
			  "*** Connect flooder detected from %s@%s.\n.kclone %s@%s\n",
			  suggested_user, suggested_host,
			  suggested_user, suggested_host);
	   }
       } 
     break;


   case R_SCLONES: /* services clones */
     if (config_entries.sclone_act[0] && config_entries.autopilot)
       {
	 if(strncasecmp(config_entries.sclone_act,"kline",5) == 0)
	   {
	     sendtoalldcc(SEND_OPERS_ONLY,
	       "Multi-server clones detected from %s@%s,auto-klining...\n",
               suggested_user, suggested_host);

             toserv("%s %s@%s :%s\n",
		    config_entries.sclone_act,
		    suggested_user, suggested_host,
		    config_entries.sclone_reason);
	   }
	 else if(strncasecmp(config_entries.sclone_act,"warn",4) == 0)
	   {
	     sendtoalldcc(SEND_WARN_ONLY,
			  "*** Multi-server clones detected from %s@%s.\n.kclone %s@%s\n",
			  suggested_user, suggested_host,
			  suggested_user, suggested_host);
	   }

       } 
     break;

#ifdef AUTO_DLINE
   case R_VCLONES:
     if (config_entries.vclone_act[0] && config_entries.autopilot)
       {
	 if(strncasecmp(config_entries.clone_act,"dline",5) == 0)
	   {
	     sendtoalldcc(SEND_OPERS_ONLY,
               "Virtual hosted clones detected from %s, auto-dlining...\n",
			  suggested_host);

	     toserv("%s %s :%s\n",
		    config_entries.vclone_act,
		    suggested_host,
		    config_entries.vclone_reason);
	   }
	 else if(strncasecmp(config_entries.clone_act,"kline",5) == 0)
	   {
	     sendtoalldcc(SEND_OPERS_ONLY,
               "Virtual hosted clones detected from %s, auto-klining...\n",
			  suggested_host);

	     toserv("%s *@%s :%s\n",
		    config_entries.vclone_act,
		    suggested_host,
		    config_entries.vclone_reason);
	   }
	 else if(strncasecmp(config_entries.clone_act,"warn",4) == 0)
	   {
	     sendtoalldcc(SEND_WARN_ONLY,
			  "*** Virtual hosted clones detected, coming from %s.\n.kdline %s\n",
			  suggested_host,
			  suggested_host);
	   }
       } 
     break;

#endif

   case R_CLONES:
     if (config_entries.clone_act[0] && config_entries.autopilot)
       {
	 if(strncasecmp(config_entries.clone_act,"kline",5) == 0)
	   {
	     if( (identd && !different) || (!identd) )
	       {
		 sendtoalldcc(SEND_OPERS_ONLY,
			      "Clones detected from %s@%s, Auto-klining\n",
			      suggested_user,
			      suggested_host);

		 toserv("%s %s@%s :%s\n",
			config_entries.clone_act,
			suggested_user, suggested_host,
			config_entries.clone_reason);
	       }
	   }
	 else if(strncasecmp(config_entries.clone_act,"warn",4) == 0)
	   {
	     sendtoalldcc(SEND_WARN_ONLY,
			  "*** Clones detected, coming from %s@%s.\n.kclone %s@%s\n",
			  suggested_user, suggested_host,
			  suggested_user, suggested_host);
	   }
       } 
     break;

   case R_FLOOD:
     if (config_entries.flood_act[0] && config_entries.autopilot)
       {
	 if(strncasecmp(config_entries.flood_act,"kline",5) == 0)
	   {
	     sendtoalldcc(SEND_OPERS_ONLY,
			  "Flooding detected from %s!%s@%s, auto-klining...\n",
			  nick,suggested_user, suggested_host);

	     toserv("%s %s@%s :%s\n",
		    config_entries.flood_act,
		    suggested_user, suggested_host,
		    config_entries.flood_reason);
	   }
	 else if(strncasecmp(config_entries.flood_act,"kill",4) == 0)
	   {
	     toserv("KILL %s :%s\n",
		    nick,config_entries.flood_reason);
	   }
	 else if(strncasecmp(config_entries.flood_act,"warn",4) == 0)
	   {
	     sendtoalldcc(SEND_WARN_ONLY,
			  "*** Flooding detected, coming from %s!%s@%s.\n.kflood %s@%s\n",
			  nick,
			  suggested_user, suggested_host,
			  suggested_user, suggested_host);
	   }
       }
     break;

   case R_CTCP:
     if (config_entries.ctcp_act[0] && config_entries.autopilot)
       {
	 if(strncasecmp(config_entries.ctcp_act,"kline",5) == 0)
	   {
	     sendtoalldcc(SEND_OPERS_ONLY,
			  "CTCP Flooding detected from %s!%s@%s, auto-klining...\n",
			  nick,
			  suggested_user, suggested_host);

	     toserv("%s %s@%s :%s\n",
		    config_entries.ctcp_act,
		    suggested_user,
		    suggested_host,
		    config_entries.ctcp_reason);
	   }
	 else if(strncasecmp(config_entries.ctcp_act,"kill",4) == 0)
	   {
	     toserv("KILL %s :%s\n",
		    nick,config_entries.ctcp_reason);
	   }
	 else if(strncasecmp(config_entries.ctcp_act,"warn",4) == 0)
	   {
	     sendtoalldcc(SEND_WARN_ONLY,
			  "*** CTCP Flooding detected, coming from %s@%s.\n.kflood %s@%s\n",
			  suggested_user, suggested_host,
			  suggested_user, suggested_host);
	   }
       }
     break;

   case R_SPOOF:
     if (config_entries.spoof_act[0] && config_entries.autopilot)
       {
	 if(strncasecmp(config_entries.spoof_act,"kill",4) == 0)
	   {
	     toserv("KILL %s :%s\n",
		  nick,config_entries.spoof_reason);
	   }
	 else if(strncasecmp(config_entries.spoof_act,"warn",4) == 0)
	   {
	     sendtoalldcc(SEND_WARN_ONLY,
			  "*** Spoofer detected %s\n", nick );
	   }
       }
     break;

   case R_SPAMBOT:
     if (config_entries.spambot_act[0] && config_entries.autopilot)
       {
	 if(strncasecmp(config_entries.spambot_act,"kline",5) == 0)
	   {
	     sendtoalldcc(SEND_OPERS_ONLY,
			  "Spambot detected from %s!%s@%s, auto-klining...\n",
			  nick, suggested_user, suggested_host);

	     toserv("%s %s@%s :%s\n",
		    config_entries.spambot_act,
		    suggested_user,
		    suggested_host,
		    config_entries.spambot_reason);
	   }
	 else if(strncasecmp(config_entries.spambot_act,"kill",4) == 0)
	   {
	     toserv("KILL %s :%s\n",
		    nick,config_entries.spambot_reason);
	   }
	 else if(strncasecmp(config_entries.spambot_act,"warn",4) == 0)
	   {
	     sendtoalldcc(SEND_WARN_ONLY,
			  "*** Spambot detected, coming from %s!%s@%s.\n.kspam %s@%s\n",
			  nick,
			  suggested_user, suggested_host,
			  suggested_user, suggested_host);
	   }
       }
     break;
 
 case R_LINK:
   if (config_entries.link_act[0] && config_entries.autopilot)
     {
       if(strncasecmp(config_entries.link_act,"kline",5) == 0)
	 {
	   sendtoalldcc(SEND_OPERS_ONLY,
			"Link Looker detected from %s!%s@%s, auto-klining...\n",
			nick,
			suggested_user, suggested_host);

	   toserv("%s %s@%s :%s\n",
		  config_entries.link_act,
		  suggested_user, suggested_host,
		  config_entries.link_reason );
	 }
       else if(strncasecmp(config_entries.link_act,"kill",4) == 0)
	 {
	   toserv("KILL %s :%s\n",
		  config_entries.link_reason );
	 }
       else if(strncasecmp(config_entries.link_act,"warn",4) == 0)       
	 {
	   sendtoalldcc(SEND_WARN_ONLY,
			"*** Link Looker detected, coming from %s!%s@%s.\n.klink %s@%s\n",
			nick,
			suggested_user, suggested_host,
			suggested_user, suggested_host);
	 }
     }
     break;

#ifdef DETECT_WINGATE
 case R_WINGATE:
   if (config_entries.wingate_act[0] && config_entries.autopilot)
     {
       if(strncasecmp(config_entries.wingate_act,"kline",5) == 0)
	 {
	   sendtoalldcc(SEND_OPERS_ONLY,
			"open wingate detected from %s!%s@%s, auto-klining...\n",
			nick,
			suggested_user, suggested_host);

	   toserv("%s %s@%s :%s\n",
		  config_entries.wingate_act,
		  suggested_user, suggested_host,
		  config_entries.wingate_reason);
	 }
       else if(strncasecmp(config_entries.wingate_act,"warn",4) == 0)
	 {
	   sendtoalldcc(SEND_WARN_ONLY,
			"*** Open socks detected detected from %s!%s@%s.\n.kline %s@%s\n",
			nick,
			suggested_user, suggested_host,
			suggested_user, suggested_host);
	 }
     }
     break;
#endif

#ifdef DETECT_SOCKS
 case R_SOCKS:
   if (config_entries.socks_act[0] && config_entries.autopilot)
     {
       if(strncasecmp(config_entries.socks_act,"kline",5) == 0)
	 {
	   sendtoalldcc(SEND_OPERS_ONLY,
			"open socks detected from %s!%s@%s, auto-klining...\n",
			nick,
			suggested_user, suggested_host);

	   toserv("%s %s@%s :%s\n",
		  config_entries.socks_act,
		  suggested_user, suggested_host,
		  config_entries.socks_reason);
	 }
       else if(strncasecmp(config_entries.socks_act,"warn",4) == 0)
	 {
	   sendtoalldcc(SEND_WARN_ONLY,
			"*** Open socks detected detected from %s!%s@%s.\n.kline %s@%s\n",
			nick,
			suggested_user, suggested_host,
			suggested_user, suggested_host);
	 }
     }
     break;
#endif

   case R_BOTS:
     if (config_entries.bot_act[0] && config_entries.autopilot)
       {
	 if(strncasecmp(config_entries.bot_act,"kline",5) == 0)
	   {
	     sendtoalldcc(SEND_OPERS_ONLY,
			  "Bot detected from %s!%s@%s, auto-klining...\n",
			  nick,
			  suggested_user, suggested_host);

	     toserv("%s %s@%s :%s\n",
		    config_entries.bot_act,
		    suggested_user, suggested_host,
		    config_entries.bot_reason);
	   }
	 else if(strncasecmp(config_entries.bot_act,"warn",4) == 0)
	   {
	     sendtoalldcc(SEND_WARN_ONLY,
			  "*** Bot detected, coming from %s!%s@%s.\n.kbot %s@%s\n",
			  nick,
			  suggested_user, suggested_host,
			  suggested_user, suggested_host);
	   }
       }
     break;

 default:
   break;
 }
}

/*
 * char *suggest_host(char *host)
 *
 * inputs	- raw hostname
 * output	- hostname stripped to klinable form
 * side effects - NONE
*/
static char *suggest_host(char *host)
{
  static char work_host[MAX_HOST];
  char *p = work_host;
  char *q = work_host;
  int dots = 0;
  int ip_number = YES;

  strncpy(work_host, host, MAX_HOST-1);

  while (*p)
    {
      if (*p == '.')
	++dots;
      else if (!isdigit(*p))
	ip_number = NO;
      ++p;
    }

  if (dots != 3)
    ip_number = NO;

  if (ip_number)
    {
      while (*p != '.')
	if ((--p) == q)			/* JUST in case */
	  break;

      *(p++) = '.';
      *(p++) = '*';
      *p = '\0';

      return q;
    }

  if (dots > 1)
    {
      while (*q != '.')
	if (*(++q) == '\0')			/* JUST in case */
	  break;
      
      p = q;
      while (*p) ++p;
      while (*p != '.') --p;
      p++;

/* I am now at the end of the hostname. the last little bit is the top
 * level domain. if its only two letters, then its a country domain, and I
 * have to rescan
 */
      if (strlen(p) != 3)
	{			/* sigh try again */
	  q = work_host;
	  if (dots > 2)
	    {
	      while (*q != '.')
		if (*(++q) == '\0')		/* JUST in case */
	          break;
	      *(--q) = '*';
	    }
	}
      else
	*(--q) = '*';
    }

  return q;
}

/*
 * format_reason()
 *
 * inputs	- reason
 * output	- pointer to static formatted string
 * side effects	- none
 */

char *format_reason(char *reason)
{
  static char reason_result[COMMENT_BUFF];

#ifdef CALVIN
  (void)sprintf(reason_result,"%s_%s",reason,date_stamp());
#else
  if(config_entries.hybrid)
    {
      (void)sprintf(reason_result,"%s",reason);
    }
  else
    {
      (void)sprintf(reason_result,"%s %s",reason,date_stamp());
    }
#endif

  return(reason_result);
}

