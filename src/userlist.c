/* tcm-hybrid/src/userlist.c
 *
 * contains functions for loading and updating the userlist and
 * config files.
 *
 * $Id: userlist.c,v 1.156 2004/06/03 02:51:37 bill Exp $
 */

#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <netinet/in.h>
#include "config.h"
#include "tcm.h"
#include "tcm_io.h"
#include "userlist.h"
#include "parse.h"
#include "logging.h"
#include "stdcmds.h"
#include "wild.h"
#include "match.h"
#include "bothunt.h"
#include "actions.h"
#include "handler.h"
#include "skline.h"

static void set_initial_umodes(struct oper_entry *);

static void m_umode(struct connection *, int, char *argv[]);
static void set_umode_connection(struct connection *, int, const char *);
static void set_umode_userlist(char *, const char *);

void save_umodes(const char *);

struct dcc_command umode_msgtab = {
  "umode", NULL, {m_unregistered, m_umode, m_umode}
};

struct umode_struct
{
  char umode;
  int type;
};

/* this table contains privleges that allow the user to do
 * certain things within tcm, such as kline.  only admins
 * may set these flags once tcm is running
 */
static struct umode_struct umode_privs[] =
{
  { 'M', FLAGS_ADMIN,		},
  { 'K', FLAGS_KLINE,		},
  { 'D', FLAGS_DLINE,		},
  { 'S', FLAGS_SUSPENDED, 	},
  { 'W', FLAGS_OPERWALL,	},
  { 'X', FLAGS_XLINE,		},
  { 'J', FLAGS_JUPE,		},
  { (char)0, 0,			}
};

/* this table contains the flags that a user can set themselves
 * so that they can see certain things within tcm.  these are
 * stored in <username>.prefs
 */
static struct umode_struct umode_flags[] =
{
  { 'k', FLAGS_VIEW_KLINES, 	},
  { 'w', FLAGS_WARN,		},
  { 'y', FLAGS_SPY,		},
  { 'i', FLAGS_INVS,		},
  { 'o', FLAGS_LOCOPS,		},
  { 'p', FLAGS_PARTYLINE,	},
  { 'x', FLAGS_SERVERS,		},
  { 'm', FLAGS_PRIVMSG,		},
  { 'n', FLAGS_NOTICE,		},
  { (char)0, 0,			}
};

void
init_userlist_handlers(void)
{
  add_dcc_handler(&umode_msgtab);
}

/* m_umode()
 *
 * input	- connection performing command
 * 		- argc
 * 		- argv
 * output	-
 * side effects - clients umode is listed or changed
 */
void
m_umode(struct connection *connection_p, int argc, char *argv[])
{
  struct oper_entry *user;
  struct connection *user_conn;

  if(argc < 2)
  {
    send_to_connection(connection_p,"Your current flags are: %s",
		       type_show(connection_p->type));
    return;
  }
  else if(argc == 2)
  {
    if((argv[1][0] == '+') || (argv[1][0] == '-'))
    {
      if(connection_p->type & FLAGS_ADMIN)
        set_umode_connection(connection_p, 1, argv[1]);
      else
        set_umode_connection(connection_p, 0, argv[1]);

      send_to_connection(connection_p, "Your flags are now: %s",
			 type_show(connection_p->type));
      return;
    }
    else
    {
      if((connection_p->type & FLAGS_ADMIN) == 0)
      {
        send_to_connection(connection_p,
			"You aren't an admin");
	return;
      }

      user = find_user_in_userlist(argv[1]);
      
      if(user != NULL)
      {
	send_to_connection(connection_p, "User flags for %s are: %s",
			argv[1], type_show(user->type));
      }
      else
        send_to_connection(connection_p, "Can't find user [%s]", argv[1]);
    }
  }
  else
  {
    if((connection_p->type & FLAGS_ADMIN) == 0)
    {
      send_to_connection(connection_p, "You aren't an admin");
      return;
    }

    user_conn = find_user_in_connections(argv[1]);

    if((argv[2][0] == '+') || (argv[2][0] == '-'))
    {
      /* user is currently connected.. */
      if(user_conn != NULL)
      {
        set_umode_connection(user_conn, 1, argv[2]);
        send_to_connection(user_conn,
	  "Your flags are now: %s (changed by %s)",
	  type_show(user_conn->type),
	  connection_p->registered_nick);
        send_to_connection(connection_p, "User flags for %s are now: %s",
                           argv[1], type_show(user_conn->type));
      }
      else 
      {
        set_umode_userlist(argv[1], argv[2]);
        send_to_connection(connection_p, "Added %s to user flags for %s",
                           argv[2], argv[1]);
      }

    }
    else
      send_to_connection(connection_p,
			 ".umode [user] [flags] | [user] | [flags]");
  }
}

/* set_umode_connection()
 *
 * input	- connection to change usermode for
 * 		- admin, whether we can set privs as well as flags
 * 		- the umode change
 * output	-
 * side effects - clients usermode is changed.
 */
void
set_umode_connection(struct connection *user_conn,
                     int admin, const char *umode)
{
  int plus = 1;
  int i;
  int j;

  for(i = 0; umode[i]; i++)
  {
    if(umode[i] == '+')
    {
      plus = 1;
      continue;
    }
    else if(umode[i] == '-')
    {
      plus = 0;
      continue;
    }

    for(j = 0; umode_flags[j].umode; j++)
    {
      if(umode_flags[j].umode == umode[i])
      {
	if(plus)
          user_conn->type |= umode_flags[j].type;
	else
          user_conn->type &= ~umode_flags[j].type;

	break;
      }
    }

    if(admin == 0)
      continue;

    /* allow admins to set privs as well as flags */
    for(j = 0; umode_privs[j].umode; j++)
    {
      if(umode_privs[j].umode == umode[i])
      {
        if(plus)
          user_conn->type |= umode_privs[j].type;
        else
          user_conn->type &= ~umode_privs[j].type;
      }
    }
  }

  set_umode_userlist(user_conn->registered_nick, umode);
}

/* set_umode_userlist()
 *
 * inputs       - user to update
 *              - umode to update with
 * outputs      -
 * side effects - users entry in the userlist is updated with flags
 */
void
set_umode_userlist(char *nick, const char *umode)
{
  dlink_node *ptr;
  struct oper_entry *user;
  int plus = 1;
  int i;
  int j;

  DLINK_FOREACH(ptr, user_list.head)
  {
    user = ptr->data;

    if(strcasecmp(nick, user->usernick))
      continue;

    /* dont set umodes for those from stats O */
    if(user->password[0] == '\0')
      continue;

    for(i = 0; umode[i]; i++)
    {
      if(umode[i] == '+')
      {
        plus = 1;
        continue;
      }
      else if(umode[i] == '-')
      {
        plus = 0;
        continue;
      }

      for(j = 0; umode_flags[j].umode; j++)
      {
        if(umode_flags[j].umode == umode[i])
        {
          if(plus)
            user->type |= umode_flags[j].type;
  	  else
            user->type &= ~umode_flags[j].type;

  	  break;
        }
      }

      for(j = 0; umode_flags[j].umode; j++)
      {
        if(umode_privs[j].umode == umode[j])
        {
          if(plus)
            user->type |= umode_privs[j].type;
          else
            user->type &= ~umode_privs[j].type;
        }
      }
    }
  }

  save_umodes(nick);
}

/* find_user_in_userlist()
 *
 * input	- username to search for
 * output	-
 * side effects - return user, or NULL if not found
 */
struct oper_entry *
find_user_in_userlist(const char *username)
{
  dlink_node *ptr;
  struct oper_entry *user;

  DLINK_FOREACH(ptr, user_list.head)
  {
    user = ptr->data;

    if(strcasecmp(user->usernick, username) == 0)
      return user;
  }

  return NULL;
}

/* set_initial_umodes()
 *
 * input	- user to set umodes for
 *              - initial umodes from confs
 * output	-
 * side effects - usermodes from conf and prefs are set
 */
void
set_initial_umodes(struct oper_entry *user)
{
  FILE *fp;
  char user_pref_filename[MAX_BUFF];
  char type_string[SMALL_BUFF];
  char *p;
  int type;

  snprintf(user_pref_filename, MAX_BUFF,
	   "etc/%s.pref", user->usernick);

  if ((fp = fopen(user_pref_filename, "r")) != NULL)
  {
    if ((fgets(type_string, SMALL_BUFF, fp)) == NULL)
      {
	(void)fclose(fp);
	return;
      }

    (void)fclose(fp);
    if((p = strchr(type_string, '\n')) != NULL)
      *p = '\0';

    type = atoi(type_string);

    /* if theres no FLAGS_VALID, its an old userfile */
    if((type & FLAGS_VALID) == 0)
    {
      send_to_all(NULL, FLAGS_ALL, "Preference file %s is invalid, removing",
                  user_pref_filename);
      unlink(user_pref_filename);
      return;
    }

    user->type |= type;
  }
}

/* save_umodes()
 *
 * input	- users nick
 * output	- usermodes are saved to prefs file
 * side effects -
 */
void
save_umodes(const char *nick)
{
  FILE *fp;
  struct oper_entry *user;
  char user_pref[MAX_BUFF];

  snprintf(user_pref, MAX_BUFF, "etc/%s.pref", nick);
  user = find_user_in_userlist(nick);
  
  if(user == NULL)
    return;

  if((fp = fopen(user_pref, "w")) != NULL)
  {
    fprintf(fp, "%d\n", (user->type|FLAGS_VALID));
    (void)fclose(fp);
  }
  else
  {
    send_to_all(NULL, FLAGS_ALL, "Couldn't open %s for writing", user_pref);
  }
}
    
/* on_stats_o()
 *
 * input	- server message body (argc/argv)
 * output	-
 * side effects - user listed in RPL_STATSOLINE is added to userlist
 */
void
on_stats_o(int argc, char *argv[])
{
  char *user_at_host;
  char *user;
  char *host;
  char *nick;
  char *p;

  user = user_at_host = argv[4];
  nick = argv[6];

  if ((p = strchr(user_at_host, '@')) != NULL)
    {
      *p++ = '\0';
      host = p;
    }
  else
    {
      user = "*";
      host = p;
    }

  add_oper(user, host, nick, "\0", 0);
  add_exempt(user, host, 0);
}

void
add_oper(char *username, char *host, char *usernick, 
         char *password, int flags)
{
  dlink_node *ptr;
  struct oper_entry *user;

  if(is_an_oper(username, host))
    return;

  ptr = dlink_create();
  user = (struct oper_entry *) xmalloc(sizeof(struct oper_entry));
  memset(user, 0, sizeof(struct oper_entry));

  strlcpy(user->username, username, sizeof(user->username));
  strlcpy(user->host, host, sizeof(user->host));
  strlcpy(user->usernick, usernick, sizeof(user->usernick));
  strlcpy(user->password, password, sizeof(user->password));

  user->type = flags;
  set_initial_umodes(user);

  dlink_add_tail(user, ptr, &user_list);
}

void
add_exempt(char *username, char *host, int type)
{
  dlink_node *ptr;
  struct exempt_entry *exempt;

  if (BadPtr(username) || BadPtr(host))
    return;

  ptr = dlink_create();
  exempt = (struct exempt_entry *) xmalloc(sizeof(struct exempt_entry));
  memset(exempt, 0, sizeof(struct exempt_entry));

  strlcpy(exempt->username, username, sizeof(exempt->username));
  strlcpy(exempt->host, host, sizeof(exempt->host));

  if(type)
    exempt->type = type;
  else
    exempt->type = 0xFFFFFFFF;

  dlink_add(exempt, ptr, &exempt_list);
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
  dlink_node *ptr;
  dlink_node *next_ptr;

  DLINK_FOREACH_SAFE(ptr, next_ptr, user_list.head)
  {
    xfree(ptr->data);
    xfree(ptr);
  }

  DLINK_FOREACH_SAFE(ptr, next_ptr, exempt_list.head)
  {
    xfree(ptr->data);
    xfree(ptr);
  }

  user_list.head = user_list.tail = NULL;
  exempt_list.head = exempt_list.tail = NULL;
}

/*
 * is_an_oper()
 *
 * inputs	- user name
 * 		- host name
 * output	- 1 if oper, 0 if not
 * side effects	- NONE
 */
int
is_an_oper(char *username, char *host)
{
  dlink_node *ptr;
  struct oper_entry *user;

  DLINK_FOREACH(ptr, user_list.head)
  {
    user = ptr->data;

    if((match(user->username, username) == 0) &&
       (wldcmp(user->host, host) == 0))
      return(YES);
  }

  return(NO);
}

/* Checks for ok hosts to block auto-kline - Phisher */
/*
 * ok_host()
 * 
 * inputs	- user, host, type
 * output	- if this user@host is in the exempt list or not
 * side effects	- none
 */
int
ok_host(char *username, char *host, int type)
{
  dlink_node *ptr;
  struct exempt_entry *exempt;
  int ok;

  DLINK_FOREACH(ptr, exempt_list.head)
  {
    exempt = ptr->data;
    ok = 0;
    
    if (strchr(username, '?') || strchr(username, '*'))
    {
      if(wldwld(exempt->username, username) == 0)
        ok++;
    }
    else
    {
      if(wldcmp(exempt->username, username) == 0)
        ok++;
    }

    if (strchr(host, '?') || strchr(host, '*'))
    {
      if(wldwld(exempt->host, host) == 0)
        ok++;
    }
    else
    {
      if(wldcmp(exempt->host, host) == 0)
        ok++;
    }

    if(ok == 2 && (exempt->type & (1 << type)))
      return(YES);
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
  int i;

  p = type_string;

  *p++ = 'O';

  for(i = 0; umode_privs[i].umode; i++)
  {
    if(type & umode_privs[i].type)
      *p++ = umode_privs[i].umode;
  }

  for(i = 0; umode_flags[i].umode; i++)
  {
    if(type & umode_flags[i].type)
      *p++ = umode_flags[i].umode;
  }
  
  *p = '\0';
  return(type_string);
}

/* reload_userlist()
 *
 * inputs	-
 * outputs	-
 * side effects - userlist and exempt list are reloaded.
 */
void
reload_userlist(void)
{
  clear_dynamic_info();
  load_dynamic_info(config_entries.dynamic_config);

  send_to_server("STATS Y");
  send_to_server("STATS O");

  if (config_entries.hybrid && (config_entries.hybrid_version >= 6))
    send_to_server("STATS I");

  logclear();
}

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
	fprintf(outfile, "virtual host [%s]\n",
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
    if ((local_host = gethostbyname (ourhostname)))
    {
      if(config_entries.debug && outfile)
      {
	fprintf(outfile, "found official name [%s]\n", local_host->h_name);
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
  return (0L);
}
