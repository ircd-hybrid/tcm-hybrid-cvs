/* actions.c
 *
 * $Id: actions.c,v 1.19 2002/05/31 02:06:34 wcampbel Exp $
 */

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
#include "handler.h"
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
#include "modules.h"

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

static int add_action(char *name);
static void update_action(int connnum, int argc, char *argv[]);

static void m_action(int connnum, int argc, char *argv[]);
static void list_actions(int conn_num);
static void list_one_action(int conn_num, int action);

static void set_action_reason(int action, char *reason);
static void set_action_strip(int action, int hoststrip);

struct dcc_command actions_msgtab = {
  "actions", NULL, {m_action, m_action, m_action}
};
struct dcc_command action_msgtab = {
  "action", NULL, {m_unregistered, m_action, m_action}
};

void
m_action(int connnum, int argc, char *argv[])
{
  if(argc == 1)
    list_actions(connnum);
  else if(argc == 2)
    list_one_action(connnum, find_action(argv[1]));
  else
    update_action(connnum, argc, argv);
}

void
init_actions(void)
{
  add_dcc_handler(&actions_msgtab);
  add_dcc_handler(&action_msgtab);
  init_one_action(act_cflood, "cflood", HS_CFLOOD, REASON_CFLOOD);
  init_one_action(act_vclone, "vclone", HS_VCLONE, REASON_VCLONE);
  init_one_action(act_flood, "flood", HS_FLOOD, REASON_FLOOD);
  init_one_action(act_link, "link", HS_LINK, REASON_LINK);
  init_one_action(act_bot, "bot", HS_BOT, REASON_BOT);
  init_one_action(act_spambot, "spam", HS_SPAMBOT, REASON_SPAMBOT);
  init_one_action(act_clone, "clone", HS_CLONE, REASON_CLONE);
  init_one_action(act_rclone, "rclone", HS_RCLONE, REASON_RCLONE);
}

/* init_one_action()
 *
 * input	- action to set for
 * 		- name of action
 * 		- action strip type
 * 		- action reason
 * outputs	- 
 * side effects -
 */
void
init_one_action(int actionid, char *action, int hoststrip, char *reason)
{
  actionid = add_action(action);
  set_action_strip(actionid, hoststrip);
  set_action_reason(actionid, reason);
}

/* add_action()
 *
 * inputs	- action name
 * outputs	-
 * side effects - specified action is added to table
 */
int
add_action(char *name)
{
  int i;

  for(i = 0; i < MAX_ACTIONS; i++)
  {
    if(strcasecmp(actions[i].name, name) == 0)
      return i;

    if(actions[i].name[0] == '\0')
      break;
  }

  if(i == MAX_ACTIONS)
    return -1;

  strlcpy(actions[i].name, name, sizeof(actions[i].name));
  actions[i].method = METHOD_IRC_WARN | METHOD_DCC_WARN;
  actions[i].klinetime = 0;
  actions[i].hoststrip = HS_DEFAULT;

  return i;
}

/* set_action()
 *
 * inputs	- argc and argv
 * outputs	- 
 * side effects - sets action based on input
 */
void
set_action(int argc, char *argv[])
{
  char *p;
  char *q;
  int actionid;
  int method;

  if(argc < 3)
    return;

  if((actionid = find_action(argv[1])) < 0)
    return;

  actions[actionid].method = 0;
  actions[actionid].klinetime = 0;

  p = argv[2];

  while(p != NULL)
  {
    q = strchr(p, ' ');

    if(q)
      *q++ = '\0';

    if(actions[actionid].klinetime == 0 && atoi(p))
      actions[actionid].klinetime = atoi(p);
    else if((method = get_method_number(p)))
      actions[actionid].method |= method;

    p = q;
  }

  /* reason as well */
  if(argc >= 4)
    set_action_reason(actionid, argv[3]);
}

void
update_action(int conn_num, int argc, char *argv[])
{
  char reason[MAX_REASON];
  int actionid;
  int method;
  int i;

  if(argc < 3)
    return;

  if((actionid = find_action(argv[1])) < 0)
    return;

  actions[actionid].method = 0;
  actions[actionid].klinetime = 0;

  for(i = 2; i < argc; i++)
  {
    if(actions[actionid].klinetime == 0 && atoi(argv[i]))
      actions[actionid].klinetime = atoi(argv[i]);
    else if((method = get_method_number(argv[i])))
      actions[actionid].method |= method;

    /* hit the reason */
    else
    {
      expand_args(reason, MAX_REASON, argc-i, argv+i);
      set_action_reason(actionid, reason);
      break;
    }
  }

  if(actions[actionid].klinetime > 0)
    print_to_socket(connections[conn_num].socket,
		    "%s action now: %s %d, reason '%s'",
		    actions[actionid].name,
		    get_method_names(actions[actionid].method),
		    actions[actionid].klinetime, actions[actionid].reason);
  else
    print_to_socket(connections[conn_num].socket,
		    "%s action now: %s %d, reason '%s'",
		    actions[actionid].name,
		    get_method_names(actions[actionid].method),
		    actions[actionid].reason);
}

void
set_action_strip(int actionid, int hoststrip)
{
  if(actions[actionid].name[0] != '\0')
    actions[actionid].hoststrip = hoststrip;
}

void
set_action_reason(int actionid, char *reason)
{
  if(actions[actionid].name[0] != '\0' && reason[0] != '\0')
    strlcpy(actions[actionid].reason, reason,
            sizeof(actions[actionid].reason));
}

/* list_actions()
 *
 * inputs	- socket to list to
 * outputs	-
 * side effects - client is shown list of actions
 */
void
list_actions(int conn_num)
{
  int i;

  print_to_socket(connections[conn_num].socket,
		  "Listing actions..");

  for(i = 0; i < MAX_ACTIONS; i++)
  {
    if(actions[i].name[0])
      list_one_action(conn_num, i);
  }
}

/* list_one_action()
 *
 * inputs	- socket to list to
 * 		- actionid to list
 * outputs	-
 * side effects - specified action info is shown
 */
void
list_one_action(int conn_num, int actionid)
{
  if(actionid < 0)
  {
    print_to_socket(connections[conn_num].socket,
		    "No matching action found");
    return;
  }

  if(actions[actionid].name == '\0')
    return;

  if(actions[actionid].klinetime > 0)
    print_to_socket(connections[conn_num].socket,
		    "%s action: %s %d, reason '%s'",
		    actions[actionid].name, 
		    get_method_names(actions[actionid].method),
		    actions[actionid].klinetime,
		    actions[actionid].reason);
  else
    print_to_socket(connections[conn_num].socket,
		    "%s action: %s, reason '%s'",
		    actions[actionid].name,
		    get_method_names(actions[actionid].method),
		    actions[actionid].reason);
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
  struct user_entry *userptr;

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

  if (okhost(user[0] ? user : "*", host, actionid) == 0)
    {
      /* Now process the event, we got the needed data */
      if (actions[actionid].method & METHOD_TKLINE)
	{    
	  /* In case the actions temp k-line time isnt set, set a default */
	  if (actions[actionid].klinetime <= 0) 
	    actions[actionid].klinetime = 60;
	  else if (actions[actionid].klinetime > 14400) 
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

/* find_action()
 *
 * inputs	- name of action to search for
 * outputs	-
 * side effects - actionid is returned, -1 if not found
 */
int
find_action(char *name)
{
  int i;

  for(i = 0; i < MAX_ACTIONS; i++)
  {
    if(strcasecmp(name, actions[i].name) == 0)
      return i;
  }

  return -1;
}

/* get_method_userhost()
 *
 * inputs	- actionid
 * 		- optional nick to search for
 * 		- user to parse
 * 		- host to parse
 * outputs	-
 * side effects - the correct user@host for specified action is returned
 */
char *
get_method_userhost(int actionid, char *nick, char *m_user, char *m_host)
{
  struct user_entry *userptr;
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

	*s = '\0';
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
  if (method & METHOD_DLINE)
    strcat(namebuf, "dline ");
  if (method & METHOD_KLINE)
    strcat(namebuf, "kline ");
  if (method & METHOD_TKLINE)
    strcat(namebuf, "tkline ");
  if (namebuf[0])
    namebuf[strlen(namebuf)-1] = '\0';
  return namebuf;
}

