#include "setup.h"

#include <ctype.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "config.h"
#include "tcm.h"
#include "tcm_io.h"
#include "parse.h"
#include "logging.h"
#include "bothunt.h"
#include "userlist.h"
#include "actions.h"
#include "stdcmds.h"
#include "wild.h"
#include "hash.h"

/* actions.c
 *
 * $Id: actions.c,v 1.10 2002/05/30 02:21:54 db Exp $
 */

int act_sclone;
int act_drone;
int act_sdrone;
int act_cflood;
int act_vclone;
int act_flood;
int act_link;
int act_bot;
int act_spambot;
int act_clone;
int act_rclone;
struct a_entry actions[MAX_ACTIONS+1];

void
init_actions(void)
{
  act_cflood = add_action("cflood");
  set_action_strip(act_cflood, HS_CFLOOD);
  set_action_reason(act_cflood, REASON_CFLOOD);

  act_vclone = add_action("vclone");
  set_action_strip(act_vclone, HS_VCLONE);
  set_action_reason(act_vclone, REASON_VCLONE);

  act_flood = add_action("flood");
  set_action_strip(act_flood, HS_FLOOD);
  set_action_reason(act_flood, REASON_FLOOD);

  act_link = add_action("link");
  set_action_strip(act_link, HS_LINK);
  set_action_reason(act_link, REASON_LINK);

  act_bot = add_action("bot");
  set_action_strip(act_bot, HS_BOT);
  set_action_reason(act_bot, REASON_BOT);

  act_spambot = add_action("spam");
  set_action_strip(act_spambot, HS_SPAMBOT);
  set_action_reason(act_spambot, REASON_SPAMBOT);

  act_clone = add_action("clone");
  set_action_strip(act_clone, HS_CLONE);
  set_action_reason(act_clone, REASON_CLONE);

  act_rclone = add_action("rclone");
  set_action_strip(act_rclone, HS_RCLONE);
  set_action_reason(act_rclone, REASON_RCLONE);
}

/*
 * handle_action
 *
 * Replaces suggest_action. Uses configured actions and methods to
 * handle a reported event. 
 * 
 * This function does all reporting to DCC and channels, as configured
 * per action.
 * 
 * Note that if an ip is passed, it *must* be a valid ip, no checks for that
 */

void
handle_action(int actionid, int idented, char *nick, char *user,
	      char *host, char *ip, char * addcmt)
{
  char comment[MAX_BUFF];
  char *userhost;
  char *p;
  struct hashrec * userptr;

  if (!user && !host && nick)
    {
      if ((userptr = find_nick(nick)) != NULL)
	{
	  user = userptr->user;
	  host = userptr->host;
	  ip = userptr->ip_host;
	  if (!strcmp(ip, "255.255.255.255"))
	    ip = 0;
	}
    }

  /* Sane input? */
  if ((actionid < 0) || (actionid >= MAX_ACTIONS) ||
      !user || !host || !host[0] ||
      strchr(host, '*') || strchr(host, '?') ||
      strchr(user, '*') || strchr(user, '?')) 
    {
      if ((actionid < 0) || (actionid >= MAX_ACTIONS))
	tcm_log(L_WARN,
		"handle_action: action is %i\n", actionid);
      else if (!user)
	tcm_log(L_WARN,
		"handle_action(%s): user is NULL\n", actions[actionid].name);
      else if (!host)
	tcm_log(L_WARN,
		"handle_action(%s): host is NULL\n", actions[actionid].name);
      else if (host[0] != '\0')
	tcm_log(L_WARN,
		"handle_action(%s): host is empty\n", actions[actionid].name);
      else if (strchr(host, '*') || strchr(host, '?'))
	tcm_log(L_WARN, "handle_action(%s): host contains wildchars (%s)\n",
	    actions[actionid].name, host);
      else if (strchr(user, '*') || strchr(user, '?'))
	tcm_log(L_WARN, "handle_action(%s): user contains wildchars (%s)\n",
	    actions[actionid].name, user);
      return;
    }

  /* Valid action? */
  if (!actions[actionid].method)
    {
      tcm_log(L_WARN, 
	      "handle_action(%s): method field is 0\n",
	      actions[actionid].name);
      return;
    }

  userhost = get_method_userhost(actionid, nick, user, host);

  strcpy(comment, "No actions taken");

  if (!okhost(user[0] ? user : "*", host, actionid))
    {
      /* Now process the event, we got the needed data */
      if (actions[actionid].method & METHOD_TKLINE)
	{    
	  /* In case the actions temp k-line time isnt set, set a default */
	  if (actions[actionid].klinetime<=0) 
	    actions[actionid].klinetime = 60;
	  else if (actions[actionid].klinetime>14400) 
	    actions[actionid].klinetime = 14400;

	  print_to_server("KLINE %d %s :%s",
		 actions[actionid].klinetime, userhost,
		 actions[actionid].reason ?
		 actions[actionid].reason : "Automated temporary K-Line");

	  snprintf(comment, sizeof(comment),
		   "%d minutes temporary k-line of %s",
		   actions[actionid].klinetime, userhost);
	}
      else if (actions[actionid].method & METHOD_KLINE)
	{
	  print_to_server("KLINE %s :%s", userhost,
		 actions[actionid].reason ? 
		 actions[actionid].reason : "Automated K-Line");

	  snprintf(comment, sizeof(comment),
		   "Permanent k-line of %s", userhost);
	}
      else if (actions[actionid].method & METHOD_DLINE)
	{
	  if ((inet_addr(host) == INADDR_NONE) && (!ip))
	    {
	      /* We don't have any IP, so look it up from our tables */
	      userptr = find_host(host);
	      if (!userptr || !userptr->ip_host[0])
		{
		  /* We couldn't find one either, revert to a k-line */
		  tcm_log(L_WARN,
	  "handle_action(%s): Reverting to k-line, couldn't find IP for %s",
		      actions[actionid].name, host);

                  actions[actionid].method |= METHOD_KLINE;
		  handle_action(actionid, idented, nick, user, 
				host, 0, addcmt);
		  actions[actionid].method &= ~METHOD_KLINE;
		  return;
		}

	      handle_action(actionid, idented, nick, user,
			    host, userptr->ip_host, addcmt);
	      return;
	    }
	  if (inet_addr(host) == INADDR_NONE)
	    {
	      /* Oks, passed host isn't in IP form.
	       * Let's move the passed ip to newhost, then mask it if needed
	       */
	      strcpy(userhost, ip);

	      if ((actions[actionid].hoststrip & HOSTSTRIP_HOST)
		  == HOSTSTRIP_HOST_BLOCK)
	      {
		p = strrchr(userhost, '.');
		p++;
		strcpy(p, "*");
	      }
	    }

	  print_to_server("DLINE %s :%s", userhost,
		 actions[actionid].reason ?
		 actions[actionid].reason : "Automated D-Line");    

	  snprintf(comment, sizeof(comment), "D-line of %s", userhost);
	}
    }
  else
    {
      return;
    }

  /* kludge, ugh, but these have their own notices */
  if((strcasecmp(actions[actionid].name, "sclone") == 0) ||
     (strcasecmp(actions[actionid].name, "drone") == 0))
    return;

  if (actions[actionid].method & METHOD_DCC_WARN)
    {

      if (addcmt && addcmt[0])
	send_to_all(FLAGS_WARN,
		     "*** %s violation (%s) from %s (%s@%s): %s", 
		     actions[actionid].name, addcmt,
		     (nick && nick[0]) ? nick : "<unknown>", 
		     (user && user[0]) ? user : "<unknown>",
		     host, comment);
      else
	send_to_all(FLAGS_WARN,
		     "*** %s violation from %s (%s@%s): %s", 
		     actions[actionid].name, 
		     (nick && nick[0]) ? nick : "<unknown>", 
		     (user && user[0]) ? user : "<unknown>",
		     host, comment);

    }

  if (actions[actionid].method & METHOD_IRC_WARN)
    {
      if (addcmt && addcmt[0])
	privmsg(config_entries.defchannel,
		"*** %s violation (%s) from %s (%s@%s): %s",
		actions[actionid].name, addcmt,
		(nick && nick[0]) ? nick : "<unknown>", 
		(user && user[0]) ? user : "<unknown>",
		host, comment);
      else
	privmsg(config_entries.defchannel,
		"*** %s violation from %s (%s@%s): %s",
		actions[actionid].name, 
		(nick && nick[0]) ? nick : "<unknown>", 
		(user && user[0]) ? user : "<unknown>",
		host, comment);
    }
}

char *
get_method_userhost(int actionid, char *nick, char *m_user, char *m_host)
{
  struct hashrec *userptr;
  static char newuserhost[MAX_USER+MAX_HOST+2]; /* one for @, one for \0 */
  char *user;
  char *host;
  char *p;
  char *s;
  
  /* nick */
  if(nick != NULL)
  {
    /* non-existant nick */
    if((userptr = find_nick(nick)) == NULL)
      return NULL;

    user = userptr->user;
    host = userptr->host;
  }
  else
  {
    *p++ = '\0';
    user = m_user;
    host = m_host;
  }

  p = newuserhost;

  if(user[0] == '~')
  {
    switch(actions[actionid].hoststrip & HOSTSTRIP_NOIDENT)
    {
      case HOSTSTRIP_NOIDENT_PREFIXED:
        s = user;

	if(strlen(user) > MAX_USER-1)
          s++;

        snprintf(p, MAX_USER, "*%s", s);
	p += strlen(p);
	break;

      case HOSTSTRIP_NOIDENT_ALL:
      default:
	strcpy(p, "~*");
	p += 2;
	break;
    }
  }
  else
  {
    switch(actions[actionid].hoststrip & HOSTSTRIP_IDENT)
    {
      case HOSTSTRIP_IDENT_PREFIXED:
        s = user;

	if(strlen(user) > MAX_USER-1)
          s++;

	snprintf(p, MAX_USER+1, "*%s", s);
	p += strlen(p);
	break;

      case HOSTSTRIP_IDENT_ALL:
	*p++ = '*';
	break;

      case HOSTSTRIP_IDENT_AS_IS:
      default:
	strncpy(p, user, MAX_USER);
	p += strlen(p);
	break;
    }
  }

  *p++ = '@';

  switch(actions[actionid].hoststrip & HOSTSTRIP_HOST)
  {
    case HOSTSTRIP_HOST_BLOCK:
      /* its a host */
      if (inet_addr(host) == INADDR_NONE)
      {
        s = strchr(host, '.');

	/* XXX - host without dots, fixme for ipv6 */
	if(s == NULL)
          return NULL;

	snprintf(p, MAX_HOST+1, "*%s", s);
      }

      /* IP */
      else
      {
        s = strrchr(host, '.');

	if(s == NULL)
          return NULL;

	*s == '\0';
	snprintf(p, MAX_HOST+1, "%s.*", host);
      }
      break;

    case HOSTSTRIP_HOST_AS_IS:
    default:
      strncpy(p, host, MAX_HOST);
      break;
  }

  newuserhost[sizeof(newuserhost) - 1] = '\0';

  return newuserhost;
}


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

