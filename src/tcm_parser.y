/*
 *  tcm-hybrid: an advanced irc connection monitor
 *  tcm_parser.y: parses configuration file
 *
 *  Copyright (C) 2004 by William Bierman and the Hybrid Development Team
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307
 *  USA
 *
 *    $Id: tcm_parser.y,v 1.6 2004/06/15 22:36:47 bill Exp $
 */

%{
#define WE_ARE_MEMORY_C

#define YY_NO_UNPUT

#include <stdio.h>
#include <string.h>

#include "setup.h"

#include "tcm.h"
#include "userlist.h"
#include "actions.h"
#include "conf.h"
#include "bothunt.h"
#ifndef NO_LIBOPM
#include "libopm/src/opm.h"
#include "proxy.h"
#endif

int current_action, flags;

char oper_nick[MAX_NICK];
char oper_pass[MAX_CONFIG];
char oper_user[MAX_USER];
char oper_host[MAX_HOST];
char *user, *host;

dlink_node *ptr;
struct scanner_conf *sc;
struct protocol_conf *pc;

%}

%union {
  int number;
  char *string;
}

%token	ADMIN
%token	ACTION
%token	ACTIONS
%token	CFLOOD
%token	CHANNEL
%token	CLONE
%token	DCCWARN
%token	DLINE
%token	DRONE
%token	DURATION
%token	EXEMPT
%token	FDS
%token	FLAGS
%token	FLOOD
%token	GECOS
%token	GENERAL
%token	IRCWARN
%token	JUPE
%token	KEY
%token	KLINE
%token	LINK
%token	METHOD
%token	NAME
%token	NFLOOD
%token	NICK
%token	NUMBER
%token	OPER_NAME
%token	OPER_PASS
%token	OPERATOR
%token	OPERWALL
%token	PASSWORD
%token	PORT
%token	PROTOCOL
%token	PROTOCOLTYPE
%token	PROXY
%token	QSTRING
%token	RCLONE
%token	REASON
%token	SCLONE
%token	SERVER
%token	SKLINE
%token	_SKLINE_FILE
%token	SPAM
%token	SSL_KEYFILE
%token	SSL_KEYPHRASE
%token	STATS_P_MESSAGE
%token	TARGET_IP
%token	TARGET_PORT
%token	TARGET_STRING
%token	TIMEOUT
%token	TYPE
%token	USER
%token	USERNAME
%token	VCLONE
%token	VHOST
%token	XLINE

%token	SECONDS MINUTES HOURS DAYS WEEKS

%type <string> QSTRING
%type <number> NUMBER
%type <number> timespec
%type <number> timespec_
%type <number> PROTOCOLTYPE

%%

conf:
	| conf conf_item
	;

conf_item:	  actions_entry
	        | general_entry
		| operator_entry
		| exempt_entry
		| proxy_entry
		| error ';'
		| error '}'
	;

timespec_: { $$ = 0; } | timespec;
timespec:	NUMBER timespec_
		{
			$$ = $1 + $2;
		}
		| NUMBER SECONDS timespec_
		{
			$$ = $1 + $3;
		}
		| NUMBER MINUTES timespec_
		{
			$$ = $1 * 60 + $3;
		}
		| NUMBER HOURS timespec_
		{
			$$ = $1 * 60 * 60 + $3;
		}
		| NUMBER DAYS timespec_
		{
			$$ = $1 * 60 * 60 * 24 + $3;
		}
		| NUMBER WEEKS timespec_
		{
			$$ = $1 * 60 * 60 * 24 * 7 + $3;
		}
		;

/* section actions */
actions_entry:	ACTIONS '{' actions_items '}' ';';

actions_items:	actions_items actions_item | actions_item;
actions_item:	actions_action | actions_duration |
		actions_name | actions_reason | error;

actions_action:	ACTION '=' CFLOOD ';'
{
  current_action = act_cflood;
} | ACTION '=' CLONE ';'
{
  current_action = act_clone;
} | ACTION '=' DRONE ';'
{
  current_action = act_drone;
} | ACTION '=' FLOOD ';'
{
  current_action = act_flood;
} | ACTION '=' JUPE ';'
{
  current_action = act_jupe;
} | ACTION '=' LINK ';'
{
  current_action = act_link;
} | ACTION '=' NFLOOD ';'
{
  current_action = act_nflood;
} | ACTION '=' PROXY ';'
{
#ifndef NO_LIBOPM
  current_action = act_proxy;
#endif
} | ACTION '=' RCLONE ';'
{
  current_action = act_rclone;
} | ACTION '=' SCLONE ';'
{
  current_action = act_sclone;
} | ACTION '=' SPAM ';'
{
  current_action = act_spam;
} | ACTION '=' VCLONE ';'
{
  current_action = act_vclone;
};

actions_duration: DURATION '=' timespec ';'
{
  if (current_action == -1)
    break;

  actions[current_action].klinetime = $3 / 60;
};

actions_name: METHOD
{
  if (current_action == -1)
    break;

  actions[current_action].method = 0;
} '=' action_types ';';

action_types: action_types ',' action_type_item | action_type_item;
action_type_item: DLINE
{
  actions[current_action].method |= METHOD_DLINE;
} | DCCWARN
{
  actions[current_action].method |= METHOD_DCC_WARN;
} | IRCWARN
{
  actions[current_action].method |= METHOD_IRC_WARN;
} | KLINE
{
  actions[current_action].method |= METHOD_KLINE;
  actions[current_action].method &= ~METHOD_SKLINE;
} | SKLINE
{
  actions[current_action].method |= METHOD_SKLINE;
  actions[current_action].method &= ~METHOD_KLINE;
};

actions_reason: REASON '=' QSTRING ';'
{
  if (current_action == -1)
    break;

  strlcpy(actions[current_action].reason, yylval.string, sizeof(actions[current_action].reason));
};


general_entry: GENERAL
  '{' general_items '}' ';';

general_items: general_items general_item | general_item;
general_item:  general_channel     | general_gecos         | general_key           | general_nick            |
               general_oper_name   | general_oper_pass     | general_port          | general_server          |
               general_skline_file | general_ssl_keyfile   | general_ssl_keyphrase | general_stats_p_message |
               general_username    | general_vhost         | error;

general_channel: CHANNEL '=' QSTRING ';'
{
  strlcpy(config_entries.channel, yylval.string, sizeof(config_entries.channel));
};

general_gecos: GECOS '=' QSTRING ';'
{
  strlcpy(config_entries.ircname_config, yylval.string, sizeof(config_entries.ircname_config));
};

general_key: KEY '=' QSTRING ';'
{
  strlcpy(config_entries.channel_key, yylval.string, sizeof(config_entries.channel_key));
};

general_nick: NICK '=' QSTRING ';'
{
  strlcpy(config_entries.dfltnick, yylval.string, sizeof(config_entries.dfltnick));
};

general_oper_name: OPER_NAME '=' QSTRING ';'
{
  strlcpy(config_entries.oper_nick_config, yylval.string, sizeof(config_entries.oper_nick_config));
};

general_oper_pass: OPER_PASS '=' QSTRING ';'
{
  strlcpy(config_entries.oper_pass_config, yylval.string, sizeof(config_entries.oper_pass_config));
};

general_port: PORT '=' NUMBER ';'
{
  config_entries.server_port = $3;
};

general_server: SERVER '=' QSTRING ';'
{
  strlcpy(config_entries.server_name, yylval.string, sizeof(config_entries.server_name));
};

general_skline_file: _SKLINE_FILE '=' QSTRING ';'
{
  strlcpy(config_entries.dynamic_config, yylval.string, sizeof(config_entries.dynamic_config));
};

general_ssl_keyfile: SSL_KEYFILE '=' QSTRING ';'
{
  strlcpy(config_entries.oper_keyfile, yylval.string, sizeof(config_entries.oper_keyfile));
};

general_ssl_keyphrase: SSL_KEYPHRASE '=' QSTRING ';'
{
  strlcpy(config_entries.oper_keyphrase, yylval.string, sizeof(config_entries.oper_keyphrase));
};

general_stats_p_message: STATS_P_MESSAGE '=' QSTRING ';'
{
  strlcpy(config_entries.statspmsg, yylval.string, sizeof(config_entries.statspmsg));
};

general_username: USERNAME '=' QSTRING ';'
{
  strlcpy(config_entries.username_config, yylval.string, sizeof(config_entries.username_config));
};

general_vhost: VHOST '=' QSTRING ';'
{
  strlcpy(config_entries.virtual_host_config, yylval.string, sizeof(config_entries.virtual_host_config));
};

operator_entry: OPERATOR
{
  oper_nick[0] = oper_pass[0] = flags = 0;
} '{' operator_items '}' ';'
{
  if (oper_nick[0] == '\0')
    break;

  add_oper(oper_user, oper_host, oper_nick, oper_pass, flags);
  oper_user[0] = oper_host[0] = oper_nick[0] = oper_pass[0] = flags = 0;
};

operator_items: operator_items operator_item | operator_item;
operator_item:  operator_name | operator_user | operator_flags | operator_password | error;

operator_name: NAME '=' QSTRING ';'
{
  if (oper_nick[0] != '\0')
  {
    add_oper(oper_user, oper_host, oper_nick, oper_pass, flags);
    oper_user[0] = oper_host[0] = oper_nick[0] = oper_pass[0] = flags = 0;
  }

  strlcpy(oper_nick, yylval.string, sizeof(oper_nick));
};

operator_user: USER '=' QSTRING ';'
{
  if (oper_nick[0] == '\0')
    break;

  get_user_host(&user, &host, yylval.string);

  if (BadPtr(user) || BadPtr(host))
    break;

  strlcpy(oper_user, user, sizeof(oper_user));
  strlcpy(oper_host, host, sizeof(oper_host));
};

operator_flags: FLAGS
{
  if (oper_nick[0] == '\0')
    break;

  flags = 0;
} '=' operator_flags_types ';';

operator_flags_types: operator_flags_types ',' operator_flags_type_item | operator_flags_type_item;
operator_flags_type_item: ADMIN
{
  flags |= FLAGS_ADMIN;
} | KLINE
{
  flags |= FLAGS_KLINE;
} | DLINE
{
  flags |= FLAGS_DLINE;
} | XLINE
{
  flags |= FLAGS_XLINE;
} | JUPE
{
  flags |= FLAGS_JUPE;
} | OPERWALL
{
  flags |= FLAGS_OPERWALL;
};

operator_password: PASSWORD '=' QSTRING ';'
{
  if (oper_nick[0] == '\0')
    break;

  strlcpy(oper_pass, yylval.string, sizeof(oper_pass));
};

exempt_entry: EXEMPT
{
  flags = 0;
} '{' exempt_items '}' ';'
{
  add_exempt(oper_user, oper_host, flags);
  oper_user[0] = oper_host[0] = flags = '\0'; 
};

exempt_items: exempt_items exempt_item | exempt_item;
exempt_item: exempt_user | exempt_type | error;

exempt_user: USER '=' QSTRING ';'
{
  if (flags != 0)
  {
    add_exempt(user, host, flags);
    flags = 0;
  }

  get_user_host(&user, &host, yylval.string);

  if (BadPtr(user) || BadPtr(host))
    break;

  strlcpy(oper_user, user, sizeof(oper_user));
  strlcpy(oper_host, host, sizeof(oper_host));
};

exempt_type: TYPE
{
  flags = 0;
} '=' exempt_type_types ';'
{
  if (flags == 0)
    break;

  add_exempt(oper_user, oper_host, flags);
  oper_user[0] = oper_host[0] = flags = '\0';
};

exempt_type_types: exempt_type_types ',' exempt_type_item | exempt_type_item;
exempt_type_item: CFLOOD
{
  flags += (1 << act_cflood);
} | CLONE
{
  flags += (1 << act_clone);
} | DRONE
{
  flags += (1 << act_drone);
} | FLOOD
{
  flags += (1 << act_flood);
} | JUPE
{
  flags += (1 << act_jupe);
} | LINK
{
  flags += (1 << act_link);
} | NFLOOD
{
  flags += (1 << act_nflood);
} | RCLONE
{
  flags += (1 << act_rclone);
} | SCLONE
{
  flags += (1 << act_sclone);
} | SPAM
{
  flags += (1 << act_spam);
} | VCLONE
{
  flags += (1 << act_vclone);
};

proxy_entry: PROXY
{
#ifndef NO_LIBOPM
  proxy_fds = DEFAULT_FDS;
  strlcpy(proxy_vhost, "0.0.0.0", sizeof(proxy_vhost));
#endif
} '{' proxy_items '}' ';'
{
#ifndef NO_LIBOPM
  if (sc != NULL)
    add_scanner(sc);
#endif
};

proxy_items: proxy_items proxy_item | proxy_item;
proxy_item: proxy_fds  | proxy_name  | proxy_protocol | proxy_target_ip | proxy_target_port |
            proxy_target_string      | proxy_timeout  | proxy_user      | proxy_vhost | error;

proxy_fds: FDS '=' NUMBER ';'
{
#ifndef NO_LIBOPM
  proxy_fds = $3;
#endif
};

proxy_name: NAME '=' QSTRING ';'
{
#ifndef NO_LIBOPM
  if (sc != NULL)
    add_scanner(sc);

  sc = scanner_create();
  strlcpy(sc->name, yylval.string, sizeof(sc->name));
#endif
};

proxy_protocol: PROTOCOL '=' PROTOCOLTYPE ':' NUMBER ';'
{
#ifndef NO_LIBOPM
  if (sc == NULL)
  {
    sc = scanner_create();
    strlcpy(sc->name, "default", sizeof(sc->name));
    add_scanner(sc);
  }

  pc = protocol_create();
  pc->type = $3;
  pc->port = $5;

  add_protocol_to_scanner(pc, sc);
#endif
};

proxy_target_ip: TARGET_IP '=' QSTRING ';'
{
#ifndef NO_LIBOPM
  if (sc == NULL)
    break;

  strlcpy(sc->target_ip, yylval.string, sizeof(sc->target_ip));
#endif
};

proxy_target_port: TARGET_PORT '=' NUMBER ';'
{
#ifndef NO_LIBOPM
  if (sc == NULL)
    break;

  sc->target_port = $3;
#endif
};

proxy_target_string: TARGET_STRING '=' QSTRING ';'
{
#ifndef NO_LIBOPM
  if (sc == NULL)
    break;

  strlcpy(sc->target_string, yylval.string, sizeof(sc->target_string));
#endif
};

proxy_timeout: TIMEOUT '=' timespec ';'
{
#ifndef NO_LIBOPM
  proxy_timeout = $3;
#endif
};

proxy_user: USER '=' QSTRING ';'
{
#ifndef NO_LIBOPM
  char *userhost;

  if (sc == NULL)
  {
    sc = scanner_create();
    strlcpy(sc->name, "default", sizeof(sc->name));
    add_scanner(sc);
  }

  ptr = dlink_create();
  ptr->data = userhost = (char *)malloc(strlen(yylval.string) + 1);
  dlink_add(userhost, ptr, &sc->targets);
#endif
};

proxy_vhost: VHOST '=' QSTRING ';'
{
#ifndef NO_LIBOPM
  strlcpy(proxy_vhost, yylval.string, sizeof(proxy_vhost));
#endif
};

