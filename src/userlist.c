/*
 *
 *  - added clear_userlist()
 *  - make it actually use MAXUSERS defined in config.h
 *  - added config file for bot nick, channel, server, port etc.
 *  - rudimentary remote tcm linking added
 *
 * $Id: userlist.c,v 1.131 2002/06/22 09:57:36 leeh Exp $
 *
 */

#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include "config.h"
#include "tcm.h"
#include "tcm_io.h"
#include "userlist.h"
#include "parse.h"
#include "logging.h"
#include "stdcmds.h"
#include "wild.h"
#include "modules.h"
#include "match.h"
#include "wingate.h"
#include "bothunt.h"
#include "actions.h"
#include "handler.h"

char wingate_class_list[MAXWINGATE][MAX_CLASS];

int	wingate_class_list_index;

static void load_a_user(char *);
static void load_e_line(char *);
static void add_oper(char *, char *, char *, char *, char *);

static void m_umode(int, int, char *argv[]);

struct dcc_command umode_msgtab = {
  "umode", NULL, {m_unregistered, m_umode, m_umode}
};

struct umode_struct
{
  char umode;
  int type;
};

/* this table contains privleges that allow the user to do
 * certain things within tcm, such as kline.  users are
 * not able to set any of these flags themselves and they
 * are permanent and read via the userlist.cf
 */
static struct umode_struct umode_privs[] =
{
  { 'M', FLAGS_ADMIN,		},
  { 'K', FLAGS_KLINE,		},
#ifndef NO_D_LINE_SUPPORT
  { 'D', FLAGS_DLINE,		},
#endif
  { 'S', FLAGS_SUSPENDED, 	},
#ifdef ENABLE_W_FLAG
  { 'W', FLAGS_WALLOPS,		},
#endif
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
 * input	- connection number of client doing .umode
 * 		- argc
 * 		- argv
 * output	-
 * side effects - clients umode is listed or changed
 */
void
m_umode(int connnum, int argc, char *argv[])
{
  struct oper_entry *user;
  slink_node *ptr;
  int new_type = 0;

  if(argc < 2)
  {
    user = find_user_in_userlist(connections[connnum].registered_nick);

    if(user == NULL)
      print_to_socket(connections[connnum].socket,
		      "Unable to find matching userlist entry!");
    else
      print_to_socket(connections[connnum].socket, 
  		      "Your current flags are: %s",
		      type_show(user->type));
    return;
  }
  else if(argc == 2)
  {
    if((argv[1][0] == '+') || (argv[1][0] == '-'))
    {
      /* update *all* the conf entries for this user, as there can
       * be multiple ones for different user@hosts
       */
      for(ptr = user_list; ptr; ptr = ptr->next)
      {
        user = ptr->data;

	if(strcasecmp(connections[connnum].registered_nick, user->usernick))
          continue;

	/* dont set usermodes for stuff from stats O */
        if(*user->password == '\0')
          continue;

        /* admins can set what they want.. */
        if(user->type & FLAGS_ADMIN)
          set_umode(user, 1, argv[1]);
        else
          set_umode(user, 0, argv[1]);

	new_type = user->type;
      }

      print_to_socket(connections[connnum].socket,
		      "Your flags are now: %s",
		      type_show(new_type));
      return;
    }
    else
    {
      if(has_umode(connnum, FLAGS_ADMIN) == 0)
      {
        print_to_socket(connections[connnum].socket,
			"You aren't an admin");
	return;
      }

      user = find_user_in_userlist(argv[1]);
      
      if(user != NULL)
      {
	print_to_socket(connections[connnum].socket,
			"User flags for %s are: %s",
			argv[1], type_show(user->type));
      }
      else
        print_to_socket(connections[connnum].socket,
			"Can't find user [%s]", argv[1]);
    }
  }
  else
  {
    int user_conn;

    if(has_umode(connnum, FLAGS_ADMIN) == 0)
    {
      print_to_socket(connections[connnum].socket,
		      "You aren't an admin");
      return;
    }

    user_conn = find_user_in_connections(argv[1]);

    if((argv[2][0] == '+') || (argv[2][0] == '-'))
    {
      /* update every relevant entry in userlist */
      for(ptr = user_list; ptr; ptr = ptr->next)
      {
        user = ptr->data;

        if(strcasecmp(argv[1], user->usernick))
          continue;

        if(*user->password == '\0')
          continue;

        set_umode(user, 1, argv[2]);
	new_type = user->type;
      }

      if(new_type)
      {
        print_to_socket(connections[connnum].socket,
  	                "User flags for %s are now: %s",
	 	        argv[1], type_show(new_type));

        if(user_conn >= 0)
          print_to_socket(connections[user_conn].socket,
			  "Your flags are now: %s (changed by %s)",
			  type_show(user->type),
			  connections[connnum].registered_nick);
      }
      else
      {
        print_to_socket(connections[connnum].socket, 
			"Can't find user [%s]", argv[1]);
      }
    }
    else
      print_to_socket(connections[connnum].socket,
		      ".umode [user] [flags] | [user] | [flags]");
  }
}

/* set_umode()
 *
 * input	- user in userlist to change umode for
 * 		- admin, whether we can set privs as well as flags
 * 		- the umode change
 * output	-
 * side effects - clients usermode is changed.
 */
void
set_umode(struct oper_entry *user, int admin, const char *umode)
{
  /* default to 1 so we can call this from load_a_user */
  int plus = 1;
  int i;
  int j;

  /* mark the file for saving */
  user->type |= FLAGS_CHANGED;

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

    /* this allows us to set privs as well as flags */
    if(admin)
    {
      for(j = 0; umode_privs[j].umode; j++)
      {
        if(umode_privs[j].umode == umode[i])
	{
          if(plus)
            user->type |= umode_privs[j].type;
	  else
            user->type &= ~umode_privs[j].type;
	}
      }
    }
  }
}

/* has_umode()
 *
 * input	- connection number of client to test
 * 		- umode to test for
 * output	-
 * side effects - returns 1 if client has umode, else 0
 */
int
has_umode(int conn_num, int type)
{
  struct oper_entry *user;

  user = find_user_in_userlist(connections[conn_num].registered_nick);

  if(user != NULL && user->type & type)
    return type;

  return 0;
}

/* get_umode()
 *
 * input	- connection number of client to get umode for
 * output	-
 * side effects - returns umode or 0 if not found
 */
int
get_umode(int conn_num)
{
  struct oper_entry *user;

  user = find_user_in_userlist(connections[conn_num].registered_nick);

  if(user != NULL)
    return(user->type|FLAGS_ALL);
  else
    return(FLAGS_ALL);
}

/* find_user_in_userlist()
 *
 * input	- username to search for
 * output	-
 * side effects - return place in userlist, or -1 if not found
 */
struct oper_entry *
find_user_in_userlist(const char *username)
{
  slink_node *ptr;
  struct oper_entry *user;

  for(ptr = user_list; ptr; ptr = ptr->next)
  {
    user = ptr->data;

    if(strcasecmp(user->usernick, username) == 0)
      return user;
  }

  return NULL;
}

/* get_umodes_from_prefs()
 *
 * input	- user to get prefs for
 * output	-
 * side effects - usermodes from preferences are returned
 */
void
get_umodes_from_prefs(struct oper_entry *user)
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
      send_to_all(FLAGS_ALL, "Preference file %s is invalid, removing",
                  user_pref_filename);
      unlink(user_pref_filename);
      return;
    }

    user->type |= type;
  }
}

/* save_umodes()
 *
 * input	-
 * output	- usermodes are saved to prefs file
 * side effects -
 */
void
save_umodes(void *unused)
{
  FILE *fp;
  slink_node *ptr;
  struct oper_entry *user;
  char user_pref[MAX_BUFF];

  for(ptr = user_list; ptr; ptr = ptr->next)
  {
    user = ptr->data;
    
    if((user->type & FLAGS_CHANGED) == 0)
      continue;

    snprintf(user_pref, MAX_BUFF, "etc/%s.pref", user->usernick);

    if((fp = fopen(user_pref, "w")) != NULL)
    {
      fprintf(fp, "%d\n", (user->type|FLAGS_VALID));
      (void)fclose(fp);
    }
    else
      send_to_all(FLAGS_ALL, "Couldn't open %s for writing", user_pref);

    user->type &= ~FLAGS_CHANGED;
  }
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
  config_entries.channel[0] = '\0';
  config_entries.dfltnick[0] = '\0';
  config_entries.email_config[0] = '\0';

  strlcpy(config_entries.userlist_config, USERLIST_FILE, MAX_CONFIG);

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
      set_action(argc, argv);
      break;

    case 'e':case 'E':
      strlcpy(config_entries.email_config, argv[1], MAX_CONFIG);
      break;

    case 'f':case 'F':
      if (config_entries.debug && outfile)
	(void)fprintf(outfile, "tcm.pid file name = [%s]\n", argv[1]);
      strlcpy(config_entries.tcm_pid_file, argv[1], MAX_CONFIG);
      break;

    case 'l':case 'L':
      strlcpy(config_entries.userlist_config, argv[1], MAX_CONFIG);
      break;

    case 'm':case 'M':
      strlcpy(config_entries.statspmsg, argv[1], sizeof(config_entries.statspmsg));
      for ( a = 2 ; a < argc ; ++a )
      {
	strcat(config_entries.statspmsg, ":");
	strcat(config_entries.statspmsg, argv[a]);
      }
      if (config_entries.statspmsg[strlen(config_entries.statspmsg)-1] == ':')
	config_entries.statspmsg[strlen(config_entries.statspmsg)-1] = '\0';
      break;

    case 'o':case 'O':
      strlcpy(config_entries.oper_nick_config, argv[1], MAX_NICK);
      strlcpy(config_entries.oper_pass_config, argv[2], MAX_CONFIG);
      break;

    case 'u':case 'U':
      if (config_entries.debug && outfile)
	fprintf(outfile, "user name = [%s]\n", argv[1]);

      strlcpy(config_entries.username_config, argv[1], MAX_CONFIG);
      break;

    case 'v':case 'V':
      if (config_entries.debug && outfile)
	fprintf(outfile, "virtual host name = [%s]\n", argv[1]);

      strlcpy(config_entries.virtual_host_config, argv[1], MAX_CONFIG);
      break;

    case 's':case 'S':
      if (config_entries.debug && outfile)
	fprintf(outfile, "server = [%s]\n", argv[1]);
      strlcpy(config_entries.server_name,argv[1],MAX_CONFIG);
      strlcpy(tcm_status.my_server, argv[1], MAX_HOST);

      if (argc > 2)
	strlcpy(config_entries.server_port, argv[2], MAX_CONFIG);

      if (argc > 3)
	strlcpy(config_entries.server_pass, argv[3], MAX_CONFIG);
      break;

    case 'n':case 'N':
      if (config_entries.debug && outfile)
	fprintf(outfile, "nick for tcm = [%s]\n", argv[1]);
      strlcpy(config_entries.dfltnick, argv[1], MAX_NICK);
      break;

    case 'i':case 'I':
      if (config_entries.debug && outfile)
	fprintf(outfile, "IRCNAME = [%s]\n", argv[1]);
      strlcpy(config_entries.ircname_config, argv[1], MAX_CONFIG);
      break;

    case 'c':case 'C':
      if (config_entries.debug && outfile)
	fprintf(outfile, "Channel = [%s]\n", argv[1]);

      if (argc > 2)
	strlcpy(config_entries.channel_key, argv[2], MAX_CONFIG);
      else
	config_entries.channel_key[0] = '\0';

      strlcpy(config_entries.channel, argv[1], MAX_CHANNEL);
      break;

    case 'w': case 'W':
      strlcpy(wingate_class_list[wingate_class_list_index], argv[1],
	      MAX_CLASS);
      wingate_class_list_index++;
      break;

    default:
      break;
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
      send_to_all(FLAGS_ALL, "Couldn't open %s: %s",
		  CONFIG_FILE, strerror(errno));
      return;
    }

  snprintf(filename, sizeof(filename), "%s.%d", CONFIG_FILE, getpid());

  if ((fp_out = fopen(filename, "w")) == NULL)
    {
      send_to_all(FLAGS_ALL, "Couldn't open %s: %s", filename, strerror(errno));
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
	    }
          break;
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
    send_to_all(FLAGS_ALL,
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
    fprintf(outfile, "load_a_user() line =[%s]\n",line);

  if ((userathost = strtok(line,":")) == NULL)
    return;

  if((usernick = strtok(NULL, ":")) == NULL)
    return;

  if((password = strtok(NULL, ":")) == NULL)
    return;

  if((type = strtok(NULL, ":")) == NULL)
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

  add_oper(user, host, usernick, password, type);
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

  add_oper(user, host, nick, "\0", "\0");
  add_exempt(user, host, 0);
}

void
add_oper(char *username, char *host, char *usernick, 
         char *password, char *type)
{
  slink_node *ptr;
  struct oper_entry *user;

  if(strcmp(host, "*") == 0)
    return;

  if(is_an_oper(username, host))
    return;

  ptr = slink_create();
  user = (struct oper_entry *) xmalloc(sizeof(struct oper_entry));
  memset(user, 0, sizeof(struct oper_entry));

  strlcpy(user->username, username, sizeof(user->username));
  strlcpy(user->host, host, sizeof(user->host));
  strlcpy(user->usernick, usernick, sizeof(user->usernick));
  strlcpy(user->password, password, sizeof(user->password));

  /* its from the conf.. load their umodes. */
  if(*type != '\0')
  {
    set_umode(user, 1, type); 
    get_umodes_from_prefs(user);
  }

  slink_add_tail(user, ptr, &user_list);
}

void
add_exempt(char *username, char *host, int type)
{
  slink_node *ptr;
  struct exempt_entry *exempt;

  if(strcmp(host, "*") == 0)
    return;

  ptr = slink_create();
  exempt = (struct exempt_entry *) xmalloc(sizeof(struct exempt_entry));
  memset(exempt, 0, sizeof(struct exempt_entry));

  strlcpy(exempt->username, username, sizeof(exempt->username));
  strlcpy(exempt->host, host, sizeof(exempt->host));

  if(type)
    exempt->type = type;
  else
    exempt->type = 0xFFFFFFFF;

  slink_add(exempt, ptr, &exempt_list);
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
    *p++ = '\0';
    add_exempt(uhost, p, type);
  }
  else
  {
    add_exempt("*", uhost, type);
  }
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
  slink_node *ptr;
  slink_node *next_ptr;

  wingate_class_list_index = 0;
  memset((void *)wingate_class_list, 0, sizeof(wingate_class_list));

  for(ptr = user_list; ptr; ptr = next_ptr)
  {
    next_ptr = ptr->next;
    xfree(ptr->data);
    xfree(ptr);
  }

  for(ptr = exempt_list; ptr; ptr = next_ptr)
  {
    next_ptr = ptr->next;
    xfree(ptr->data);
    xfree(ptr);
  }

  user_list = NULL;
  exempt_list = NULL;
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
  slink_node *ptr;
  struct oper_entry *user;

  for(ptr = user_list; ptr; ptr = ptr->next)
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
  slink_node *ptr;
  struct exempt_entry *exempt;
  int ok;

  for(ptr = exempt_list; ptr; ptr = ptr->next)
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
#if defined(DETECT_WINGATE) || defined(DETECT_SOCKS) || defined(DETECT_SQUID)
  _reload_wingate(0, 0, NULL);
#endif

  clear_userlist();
  load_userlist();

  print_to_server("STATS Y");
  print_to_server("STATS O");

  if (config_entries.hybrid && (config_entries.hybrid_version >= 6))
    print_to_server("STATS I");

  logclear();
}

#ifdef DEBUGMODE
/*
 * exempt_summary()
 *
 * inputs - none
 * outputs - none
 * side effects - prints out summary of exempts, indexed by action names
 */

void
exempt_summary()
{
  slink_node *ptr;
  struct exempt_entry *exempt;
  int i;

  for (i = 0; i < MAX_ACTIONS; i++)
  {
    if (actions[i].name[0] == '\0')
     break;

    printf("%s:", actions[i].name);

    for(ptr = exempt_list; ptr; ptr = ptr->next)
    {
      exempt = ptr->data;

      if(exempt->type & i)
        printf(" %s@%s", exempt->username, exempt->host);
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
  return (0L);
}

/*
 * wingate_class
 *
 * inputs       - class
 * output       - if this class is a wingate class to check
 * side effects - none
 */

int
wingate_class(char *class)
{
  int i;

  for(i=0; wingate_class_list[i] != '\0' ;i++)
    {
      if(strcasecmp(wingate_class_list[i], class) == 0)
        {
          return(YES);
        }
    }
  return(NO);
}
