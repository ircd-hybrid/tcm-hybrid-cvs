/* actions.c
 *
 * $Id: actions.c,v 1.52 2003/06/01 01:19:05 bill Exp $
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
#include "skline.h"

#define valid_string(x) (((x) != NULL) && (*(x) != '\0'))

static int add_action(char *name);
static void update_action(struct connection *, int argc, char *argv[]);
static void m_action(struct connection *, int argc, char *argv[]);
static void list_actions(struct connection *);
static void list_one_action(struct connection *, int action);

static void set_action_reason(int action, char *reason);
static void set_action_strip(int action, int hoststrip);

struct dcc_command actions_msgtab = {
  "actions", NULL, {m_action, m_action, m_action}
};
struct dcc_command action_msgtab = {
  "action", NULL, {m_unregistered, m_action, m_action}
};

void
m_action(struct connection *connection_p, int argc, char *argv[])
{
  if(argc == 1)
    list_actions(connection_p);
  else if(argc == 2)
    list_one_action(connection_p, find_action(argv[1]));
  else
    update_action(connection_p, argc, argv);
}

void
init_actions(void)
{
  memset(&actions, 0, sizeof(actions));
  add_dcc_handler(&actions_msgtab);
  add_dcc_handler(&action_msgtab);
  init_one_action(&act_cflood, "cflood", HS_CFLOOD, REASON_CFLOOD);
  init_one_action(&act_vclone, "vclone", HS_VCLONE, REASON_VCLONE);
  init_one_action(&act_flood, "flood", HS_FLOOD, REASON_FLOOD);
  init_one_action(&act_link, "link", HS_LINK, REASON_LINK);
  init_one_action(&act_spam, "spam", HS_SPAM, REASON_SPAM);
  init_one_action(&act_clone, "clone", HS_CLONE, REASON_CLONE);
  init_one_action(&act_rclone, "rclone", HS_RCLONE, REASON_RCLONE);
  init_one_action(&act_nflood, "nflood", HS_NFLOOD, REASON_NFLOOD);
  init_one_action(&act_jupe, "jupe", HS_JUPE, REASON_JUPE);
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
init_one_action(int *actionid, char *action, int hoststrip, char *reason)
{
  *actionid = add_action(action);
  set_action_strip(*actionid, hoststrip);
  set_action_reason(*actionid, reason);
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

/* update_action()
 *
 * input	- pointer to connection struct changing
 * 		- argc and argv
 * output	-
 * side effects - action specified is changed to user params
 */
void
update_action(struct connection *connection_p, int argc, char *argv[])
{
  char reason[MAX_REASON];
  int actionid;
  int method;
  int i;

  if(argc < 3)
    return;

  if((actionid = find_action(argv[1])) < 0)
  {
    send_to_connection(connection_p, "No such action");
    return;
  }

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
    send_to_connection(connection_p, "%s action now: %s %d, reason '%s'",
		       actions[actionid].name,
		       get_method_names(actions[actionid].method),
		       actions[actionid].klinetime, actions[actionid].reason);
  else
    send_to_connection(connection_p,
		       "%s action now: %s, reason '%s'",
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
 * inputs	- pointer to struct connection to list to
 * outputs	- none
 * side effects - client is shown list of actions
 */
void
list_actions(struct connection *connection_p)
{
  int i;

  send_to_connection(connection_p, "Listing actions..");

  for(i = 0; i < MAX_ACTIONS; i++)
  {
    if(actions[i].name[0])
      list_one_action(connection_p, i);
  }
}

/* list_one_action()
 *
 * inputs	- pointer to struct connection to list to
 * 		- actionid to list
 * outputs	-
 * side effects - specified action info is shown
 */
void
list_one_action(struct connection *connection_p, int actionid)
{
  if(actionid < 0)
  {
    send_to_connection(connection_p, "No matching action found");
    return;
  }

  if(actions[actionid].name == '\0')
    return;

  if(actions[actionid].klinetime > 0)
    send_to_connection(connection_p,
		       "%s action: %s %d, reason '%s'",
		       actions[actionid].name, 
		       get_method_names(actions[actionid].method),
		       actions[actionid].klinetime,
		       actions[actionid].reason);
  else
    send_to_connection(connection_p,
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
handle_action(int actionid, char *g_nick, char *g_username,
	      char *g_host, char *g_ip, char * addcmt)
{
  char comment[MAX_BUFF];
  char l_nick[MAX_NICK], l_username[MAX_USER], l_host[MAX_HOST], l_ip[MAX_HOST];
  char *nick, *username, *host, *ip;
  char *userhost;
  char *p;
  struct user_entry *userptr;

  nick = username = host = ip = NULL;

  /*
   * it is nessecary to make copies of this data because of the parsing that follows.
   * sometimes, some of this data must be manipulated to form a ban mask, and if we
   * simply modified the original memory, it may cause problems removing the user
   * from the hash tables when the client disconnects.  -bill
   */
  if (g_nick != NULL)
  {
    strlcpy(l_nick, g_nick, sizeof(l_nick));
    nick = l_nick;
  }
  if (g_username != NULL)
  {
    strlcpy(l_username, g_username, sizeof(l_username));
    username = l_username;
  }
  if (g_host != NULL)
  {
    strlcpy(l_host, g_host, sizeof(l_host));
    host = l_host;
  }
  if (g_ip != NULL)
  {
    strlcpy(l_ip, g_ip, sizeof(l_ip));
    ip = l_ip;
  }

  if ((g_ip == NULL || g_host == NULL || g_username == NULL) && (g_nick != NULL))
  {
    if ((userptr = find_nick_or_host(nick, FIND_NICK)) != NULL)
    {
      username = l_username; host = l_host; ip = l_ip;
      strlcpy(username, userptr->username, MAX_USER);
      strlcpy(host, userptr->host, MAX_HOST);
      strlcpy(ip, userptr->ip_host, MAX_HOST);

      if (!strcmp(ip, "255.255.255.255"))
        ip = NULL;
    }
  }

  /* Sane input? */
  if ((actionid < 0) || (actionid >= MAX_ACTIONS) ||
      !username || !host || !host[0] ||
      strchr(host, '*') || strchr(host, '?') ||
      strchr(username, '*') || strchr(username, '?')) 
    {
      if ((actionid < 0) || (actionid >= MAX_ACTIONS))
	tcm_log(L_WARN, "handle_action: action is %i", actionid);
      else if (!username)
	tcm_log(L_WARN, "handle_action(%s): username is NULL",
                actions[actionid].name);
      else if (!host)
	tcm_log(L_WARN, "handle_action(%s): host is NULL", 
                actions[actionid].name);
      else if (host[0] != '\0')
	tcm_log(L_WARN, "handle_action(%s): host is empty", 
                actions[actionid].name);
      else if (strchr(host, '*') || strchr(host, '?'))
	tcm_log(L_WARN, "handle_action(%s): host contains wildchars (%s)",
	        actions[actionid].name, host);
      else if (strchr(username, '*') || strchr(username, '?'))
	tcm_log(L_WARN, "handle_action(%s): user contains wildchars (%s)",
	        actions[actionid].name, username);
      return;
    }

  /* Valid action? */
  if (!actions[actionid].method)
    {
      tcm_log(L_WARN, 
	      "handle_action(%s): method field is 0",
	      actions[actionid].name);
      return;
    }

  userhost = get_method_userhost(actionid, nick, username, host);
  strcpy(comment, "No actions taken");

  if (ok_host(valid_string(username) ? username : "*", host, actionid) == 0)
    {
      /* Now process the event, we got the needed data */
      if (actions[actionid].method & METHOD_KLINE)
	{
          if (actions[actionid].klinetime)
          {
            if (actions[actionid].klinetime < 0)
              actions[actionid].klinetime = 60;
            else if (actions[actionid].klinetime > 14400)
              actions[actionid].klinetime = 14400;

            send_to_server("KLINE %d %s :%s",
                           actions[actionid].klinetime, userhost,
                           actions[actionid].reason[0] ?
                           actions[actionid].reason : "Automated temporary K-Line");

            snprintf(comment, sizeof(comment),
                     "%d minutes temporary K-Line of %s",
                     actions[actionid].klinetime, userhost);
          }
          else
          {
	    send_to_server("KLINE %s :%s", userhost,
		           actions[actionid].reason[0] ? 
		           actions[actionid].reason : "Automated K-Line");

	    snprintf(comment, sizeof(comment),
		     "Permanent K-Line of %s", userhost);
          }
	}
      else if (actions[actionid].method & METHOD_SKLINE)
	{
          if (actions[actionid].klinetime < 0)
            actions[actionid].klinetime = 60;
          if (actions[actionid].klinetime > 14400)
            actions[actionid].klinetime = 14400;

          /* SKLINE CODE HERE */
          if (dynamic_empty() == YES)
          {
            tcm_log(L_WARN,
                    "handle_action(%s): Reverting to K-Line, dynamic hostmask list is empty",
                    actions[actionid].name);

            if (actions[actionid].klinetime)
            {
              send_to_server("KLINE %d %s :%s",
                             actions[actionid].klinetime, userhost,
                             actions[actionid].reason[0] ?
                             actions[actionid].reason : "Automated temporary K-Line");
              snprintf(comment, sizeof(comment),
                       "%d minutes temporary K-Line of %s",
                       actions[actionid].klinetime, userhost);
            }
            else
            {
              send_to_server("KLINE %s :%s",
                             userhost,
                             actions[actionid].reason[0] ?
                             actions[actionid].reason : "Automated K-Line");
              snprintf(comment, sizeof(comment),
                       "Permanent K-Line of %s", userhost);
            }
          }
          else
          {
            if (isdynamic(host))
            {
              send_to_server("KLINE %d %s :%s",
                             actions[actionid].klinetime, userhost,
                             actions[actionid].reason[0] ?
                             actions[actionid].reason : "Automated temporary K-Line");
              snprintf(comment, sizeof(comment),
                       "%d minutes temporary K-Line of %s",
                       actions[actionid].klinetime, userhost);
            }
            else
            {
              send_to_server("KLINE %s :%s",
                             userhost,
                             actions[actionid].reason[0] ?
                             actions[actionid].reason : "Automated K-Line");
              snprintf(comment, sizeof(comment),
                       "Permanent K-Line of %s", userhost);
            }
          }
	}
      else if (actions[actionid].method & METHOD_DLINE)
	{
          /* do we have a valid ip? if not, look it up. */
          if ((ip == NULL) || (inet_addr(ip) == INADDR_NONE))
	    {
	      /* We don't have any IP, so look it up from our tables */
	      userptr = find_nick_or_host(host, FIND_HOST);

	      if (userptr == NULL || !userptr->ip_host[0])
		{
		  /* We couldn't find one either, revert to a k-line */
		  tcm_log(L_WARN, 
                          "handle_action(%s): Reverting to k-line, could not find IP for %s",
		          actions[actionid].name, host);

		  send_to_server("KLINE *@%s :%s", host,
				 actions[actionid].reason ?
				 actions[actionid].reason : "Automated K-Line");
		  return;
		}
              strlcpy(l_ip, userptr->ip_host, sizeof(l_ip));
              ip = l_ip;
	    }

	  if ((actions[actionid].hoststrip & HOSTSTRIP_HOST)
	      == HOSTSTRIP_HOST_BLOCK)
	  {
	    p = strrchr(ip, '.');
	    p++;
	    strcpy(p, "*");
	  }

	  send_to_server("DLINE %s :%s", ip,
			 actions[actionid].reason ?
			 actions[actionid].reason : "Automated D-Line");    

	  snprintf(comment, sizeof(comment), "D-line of %s", ip);
	}
    }
  else
    return;

  /* kludge, ugh, but these have their own notices */
  if((strcasecmp(actions[actionid].name, "sclone") == 0) ||
     (strcasecmp(actions[actionid].name, "drone") == 0))
    return;

  if (actions[actionid].method & METHOD_DCC_WARN)
    {

      if (addcmt && addcmt[0])
	send_to_all(NULL, FLAGS_WARN,
		    "*** %s violation (%s) from %s (%s@%s): %s", 
		    actions[actionid].name, addcmt,
		    (nick && nick[0]) ? nick : "<unknown>", 
		    (username && username[0]) ? username : "<unknown>",
		     host, comment);
      else
	send_to_all(NULL, FLAGS_WARN,
		    "*** %s violation from %s (%s@%s): %s", 
		    actions[actionid].name, 
		    (nick && nick[0]) ? nick : "<unknown>", 
		    (username && username[0]) ? username : "<unknown>",
		    host, comment);

    }

  if (actions[actionid].method & METHOD_IRC_WARN &&
      (*config_entries.channel != '\0'))
    {
      if (addcmt && addcmt[0])
	privmsg(config_entries.channel,
		"*** %s violation (%s) from %s (%s@%s): %s",
		actions[actionid].name, addcmt,
		(nick && nick[0]) ? nick : "<unknown>", 
		(username && username[0]) ? username : "<unknown>",
		host, comment);
      else
	privmsg(config_entries.channel,
		"*** %s violation from %s (%s@%s): %s",
		actions[actionid].name, 
		(nick && nick[0]) ? nick : "<unknown>", 
		(username && username[0]) ? username : "<unknown>",
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
  static char newuserhost[MAX_USERHOST];
  char *user;
  char *host;
  char *p;
  char *s;
  int hoststrip;
  
  if(valid_string(m_user) && valid_string(m_host))
  {
    user = m_user;
    host = m_host;
  }
  else if(!valid_string(m_user) && valid_string(m_host))
  {
    /* for some actions, we have no username (like reconnecting clones) */
    user = "\0";
    host = m_host;
  }
  else if(valid_string(nick))
  {
    if((userptr = find_nick_or_host(nick, FIND_NICK)) == NULL)
      return NULL;

    user = userptr->username;
    host = userptr->host;
  }
  else
    return NULL;

  p = newuserhost;

  hoststrip = (actionid == -1) ? HS_DEFAULT : actions[actionid].hoststrip;
  if(user[0] == '~')
  {
    switch(hoststrip & HOSTSTRIP_NOIDENT)
    {
      case HOSTSTRIP_NOIDENT_PREFIXED:
        s = user;

	if(strlen(user) >= MAX_USER)
          s++;

        snprintf(p, MAX_USER, "*%s", s);
	p += strlen(p);
	break;

      case HOSTSTRIP_NOIDENT_ALL:
	*p++ = '*';
	break;

      case HOSTSTRIP_NOIDENT_ALL_NONE:
      default:
	strcpy(p, "~*");
	p += 2;
	break;
    }
  }
  else
  {
    switch(hoststrip & HOSTSTRIP_IDENT)
    {
      case HOSTSTRIP_IDENT_PREFIXED:
        s = user;

	if(strlen(user) >= MAX_USER-1)
          s++;

	snprintf(p, MAX_USER, "*%s", s);
	p += strlen(p);
	break;

      case HOSTSTRIP_IDENT_ALL:
	*p++ = '*';
	break;

      case HOSTSTRIP_IDENT_AS_IS:
      default:
	strlcpy(p, user, MAX_USER);
	p += strlen(p);
	break;
    }
  }

  *p++ = '@';

  switch(hoststrip & HOSTSTRIP_HOST)
  {
    case HOSTSTRIP_HOST_BLOCK:
	if (inet_addr(host) == INADDR_NONE && (s = strchr(host, '.')) != NULL) {
/* host */	snprintf(p, MAX_HOST, "*%s", s);
	} else if ((s = strrchr(host, '.')) != NULL) {
		*s = '\0';
/* ipv4 */	snprintf(p, MAX_HOST, "%s%s", host, ".*");
#if defined(IPV6) && defined (VIRTUAL_IPV6)
	} else if (strchr(host, ':') != NULL) {
		u_int16_t words[8];
		char buf6[MAX_IP];
/* ipv6 */
		strlcpy(buf6, host, MAX_IP);
		if (inet_pton6(buf6, (char *)&words)) {
			words[4] = words[5] = words[6] = words[7] = 0;
			inet_ntop6((char *)&words, buf6, MAX_IP);
			snprintf(p, MAX_HOST, "%s/64", buf6);
		}
#endif
	} else {
/* dunno */	return NULL;
	}
	break;

    case HOSTSTRIP_HOST_AS_IS:
    default:
      strlcpy(p, host, MAX_HOST);
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
  else if (!strcasecmp(methodname, "skline"))
    return METHOD_SKLINE;
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
  if (method & METHOD_SKLINE)
    strcat(namebuf, "skline ");
  if (namebuf[0])
    namebuf[strlen(namebuf)-1] = '\0';
  return namebuf;
}

