/*
 * tcm lexer file
 *
 * $Id: tcm_lexer.l,v 1.3 2004/06/09 21:23:00 bill Exp $
 */

%option case-insensitive
%option noyywrap
%option nounput

%{
#define WE_ARE_MEMORY_C

#define MAX_INCLUDE_DEPTH		10

#include <string.h>

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
rclone		{ return RCLONE;		}
reason		{ return REASON;		}
sclone		{ return SCLONE;		}
server		{ return SERVER;		}
skline		{ return SKLINE;		}
skline_file	{ return SKLINE_FILE;		}
spam		{ return SPAM;			}
ssl_keyfile	{ return SSL_KEYFILE;		}
ssl_keyphrase	{ return SSL_KEYPHRASE;		}
stats_p_message	{ return STATS_P_MESSAGE;	}
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
