/*
 *  tcm-hybrid: an advanced irc connection monitor
 *  tcm_lexer.l: lex file for tcm's configuration file
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
 *    $Id: tcm_lexer.l,v 1.5 2004/06/15 22:36:47 bill Exp $
 */

%option case-insensitive
%option noyywrap
%option nounput

%{
#define WE_ARE_MEMORY_C

#define MAX_INCLUDE_DEPTH		10

#include <string.h>

#include "setup.h"

#ifndef NO_LIBOPM
#include "libopm/src/opm_types.h"
#endif

#include "tcm.h"
#include "tcm_io.h"
#include "logging.h"
#include "conf.h"

#include "y.tab.h"

#undef YY_INPUT

#define YY_FATAL_ERROR(msg)		conf_fatal_error(msg)
#define YY_INPUT(buf, result, max_size)	if (!(result = conf_fgets(buf, max_size, conf_file_in))) \
					  YY_FATAL_ERROR("input in flex scanner failed");

int lineno = 1;
int include_stack_ptr = 0;
int lineno_stack[MAX_INCLUDE_DEPTH];
int ieof(void);

char linebuf[BUFFERSIZE];
char conffilebuf[BUFFERSIZE];
char conffile_stack[MAX_INCLUDE_DEPTH][BUFFERSIZE];

YY_BUFFER_STATE include_stack[MAX_INCLUDE_DEPTH];

FILE *inc_file_in[MAX_INCLUDE_DEPTH];

void ccomment(void);
void hashcomment(void);
void cinclude(void);

%}

ws	[ \t]*
digit	[0-9]
comment	#.*
qstring	\"[^\"\n]*[\"\n]
include	\.include{ws}(\<.*\>|\".*\")

%%

{include}	{ cinclude(); }
"/*"		{ ccomment(); }

\n.*		{ strcpy(linebuf, yytext+1); lineno++; yyless(1); }

{ws}		;
{comment}	{ hashcomment(); }

{digit}+	{ yylval.number = atoi(yytext); return NUMBER; }

{qstring}	{ if(yytext[yyleng-2] == '\\')
		  {
		    yyless(yyleng-1); /* return last quote */
		    yymore();         /* append next string */
		  }
		  else
		  {
		    yylval.string = yytext+1;
		    if(yylval.string[yyleng-2] != '"')
		      tcm_log(L_ERR, "Unterminated character string");
		    else
		    {
		      int i,j;

	 	      yylval.string[yyleng-2] = '\0'; /* remove close quote */
       
		      for (j=i=0 ;yylval.string[i] != '\0'; i++,j++)
		      {
		        if (yylval.string[i] != '\\')
		          yylval.string[j] = yylval.string[i];
		        else
		        {
		          i++;
		          if (yylval.string[i] == '\0') /* XXX - should not happen */
		          {
		            tcm_log(L_ERR, "Unterminated character string");
		            break;
		          }
		
		          yylval.string[j] = yylval.string[i];
		        }
		      }
		
		      yylval.string[j] = '\0';
		
		      return QSTRING;
		    }
		  }
		}

action		{ return ACTION;		}
actions		{ return ACTIONS;		}
admin		{ return ADMIN;			}
cflood		{ return CFLOOD;		}
channel		{ return CHANNEL;		}
clone		{ return CLONE;			}
dccwarn		{ return DCCWARN;		}
dline		{ return DLINE;			}
drone		{ return DRONE;			}
duration	{ return DURATION;		}
exempt		{ return EXEMPT;		}
fds		{ return FDS;			}
flags		{ return FLAGS;			}
flood		{ return FLOOD;			}
gecos		{ return GECOS;			}
general		{ return GENERAL;		}
ircwarn		{ return IRCWARN;		}
jupe		{ return JUPE;			}
key		{ return KEY;			}
kline		{ return KLINE;			}
link		{ return LINK;			}
method		{ return METHOD;		}
name		{ return NAME;			}
nflood		{ return NFLOOD;		}
nick		{ return NICK;			}
oper_name	{ return OPER_NAME;		}
oper_pass	{ return OPER_PASS;		}
operator	{ return OPERATOR;		}
operwall	{ return OPERWALL;		}
password	{ return PASSWORD;		}
port		{ return PORT;			}
protocol	{ return PROTOCOL;		}
proxy		{ return PROXY;			}
rclone		{ return RCLONE;		}
reason		{ return REASON;		}
sclone		{ return SCLONE;		}
server		{ return SERVER;		}
skline		{ return SKLINE;		}
skline_file	{ return _SKLINE_FILE;		}
spam		{ return SPAM;			}
ssl_keyfile	{ return SSL_KEYFILE;		}
ssl_keyphrase	{ return SSL_KEYPHRASE;		}
stats_p_message	{ return STATS_P_MESSAGE;	}
target_ip	{ return TARGET_IP;		}
target_port	{ return TARGET_PORT;		}
target_string	{ return TARGET_STRING;		}
timeout		{ return TIMEOUT;		}
type		{ return TYPE;			}
user		{ return USER;			}
username	{ return USERNAME;		}
vclone		{ return VCLONE;		}
vhost		{ return VHOST;			}
xline		{ return XLINE;			}

weeks		{ return WEEKS;		}
week		{ return WEEKS;		}
days		{ return DAYS;		}
day		{ return DAYS;		}
hours		{ return HOURS;		}
hour		{ return HOURS;		}
minutes		{ return MINUTES;	}
minute		{ return MINUTES;	}
seconds		{ return SECONDS;	}
second		{ return SECONDS;	}

HTTP		{
#ifndef NO_LIBOPM
		  yylval.number = OPM_TYPE_HTTP;
		  return PROTOCOLTYPE;
#endif
		}

HTTPPOST	{
#ifndef NO_LIBOPM
		  yylval.number = OPM_TYPE_HTTPPOST;
		  return PROTOCOLTYPE;
#endif
		}

SOCKS4		{
#ifndef NO_LIBOPM
		  yylval.number = OPM_TYPE_SOCKS4;
		  return PROTOCOLTYPE;
#endif
		}

SOCKS5		{
#ifndef NO_LIBOPM
		  yylval.number = OPM_TYPE_SOCKS5;
		  return PROTOCOLTYPE;
#endif
		}

WINGATE		{
#ifndef NO_LIBOPM
		  yylval.number = OPM_TYPE_WINGATE;
		  return PROTOCOLTYPE;
#endif
		}

ROUTER		{
#ifndef NO_LIBOPM
		  yylval.number = OPM_TYPE_ROUTER;
		  return PROTOCOLTYPE;
#endif
		}

.		{ return yytext[0];		}
<<EOF>>		{ if (ieof()) yyterminate();	}

%%

/* C-comment ignorning routine -kre */
void
ccomment(void)
{
  int c;

  while (1)
  {
    while ((c = input()) != '*' && c != EOF)
      if (c == '\n') ++lineno;

    if (c == '*')
    {
      while ((c = input()) == '*');
      if (c == '/')
        break;
    }

    if (c == EOF)
    {
      YY_FATAL_ERROR("EOF in comment");

      /* XXX - hack to fix gcc compile warning */
      if (0)
        yy_fatal_error("EOF in comment");

      break;
    }
  }
}

#define INCLUDE "#include"

void
hashcomment(void)
{
  if (strlen(yytext) < strlen(INCLUDE))
    return;

  if (!strncasecmp(yytext, INCLUDE, strlen(INCLUDE)))
    yyerror("You probably meant '.include', skipping");
}

/* C-style includes. -kre */
void
cinclude(void)
{
  char *c;

  if ((c = strchr(yytext, '<')) == NULL)
    *strchr(c = strchr(yytext, '"') + 1, '"') = 0;
  else
    *strchr(++c, '>') = 0;

  if (include_stack_ptr >= MAX_INCLUDE_DEPTH)
    tcm_log(L_ERR, "Includes nested too deep in %s", c);
  else
  {
    FILE *tmp_file_in;
    char filenamebuf[BUFFERSIZE];

    snprintf(filenamebuf, sizeof(filenamebuf), "etc/%s", c);
    tmp_file_in = fopen(filenamebuf, "r");

    if (tmp_file_in == NULL)
    {
      tcm_log(L_ERR, "Cannot include %s", filenamebuf);
      return;
    }

    lineno_stack[include_stack_ptr] = lineno;
    lineno = 1;
    inc_file_in[include_stack_ptr] = conf_file_in;
    strlcpy(conffile_stack[include_stack_ptr], conffilebuf, BUFFERSIZE);
    include_stack[include_stack_ptr++] = YY_CURRENT_BUFFER;
    conf_file_in = tmp_file_in;
    snprintf(conffilebuf, sizeof(conffilebuf), "%s", c);
    yy_switch_to_buffer(yy_create_buffer(yyin, YY_BUF_SIZE));
  }
}

int
ieof(void)
{
  if (include_stack_ptr)
    fclose(conf_file_in);

  if (--include_stack_ptr < 0)
  {
    include_stack_ptr = 0;
    lineno = 1;
    return 1;
  }

  yy_delete_buffer(YY_CURRENT_BUFFER);
  lineno = lineno_stack[include_stack_ptr];
  conf_file_in = inc_file_in[include_stack_ptr];
  strlcpy(conffilebuf, conffile_stack[include_stack_ptr], BUFFERSIZE);
  yy_switch_to_buffer(include_stack[include_stack_ptr]);

  return 0;
}
