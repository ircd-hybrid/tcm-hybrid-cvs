/* 
 * token.c
 *
 * command table tokenizer for tcm
 *
 * - Dianora db@db.net
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "config.h"
#include "tcm.h"
#include "token.h"
//#include "bothunt.h"

#ifdef DMALLOC
#include "dmalloc.h"
#endif

static char *version="$Id: token.c,v 1.11 2001/10/11 20:45:22 bill Exp $";

static int hash_cmd(char *);

#define MAX_COMMAND_HASH  511

struct command_token {
  char *token_string;
  int  keyword_value;
};

struct command_hash {
  char *token_string;
  int token;
  struct command_hash *next;
};

/* bug spotted by torak crobbins@dingoblue.net.au */

struct command_hash  *command_hash_table[MAX_COMMAND_HASH+1];

struct command_token command_table[] =
{
  {"clones",       K_CLONES},
  {"nflood",       K_NFLOOD},
  {"rehash",       K_REHASH},
  {"trace",        K_TRACE},
  {"failures",     K_FAILURES},
  {"domains",      K_DOMAINS},
  {"multi",        K_BOTS},
  {"bots",         K_BOTS},
  {"nfind",        K_NFIND},
  {"list",         K_LIST},
  {"killlist",     K_KILLLIST},
  {"kl",           K_KILLLIST},
  {"kline",        K_KLINE},
  {"kclone",       K_KCLONE},
  {"kflood",       K_KFLOOD},
  {"kperm",        K_KPERM},
  {"klink",        K_KLINK},
  {"kbot",         K_KBOT},
  {"kspam",	   K_SPAM},
  {"kdrone",	   K_KDRONE},
  {"kill",         K_KILL},
  {"register",     K_REGISTER},
  {"identify",     K_REGISTER},
  {"opers",        K_OPERS},
  {"tcmlist",      K_TCMLIST},
  {"exemptions",   K_EXEMPTIONS},
  {"tcmconn",      K_TCMCONN},
  {"umode",	   K_UMODE},
  {"connections",  K_CONNECTIONS},
  {"who",	   K_CONNECTIONS},
  {"whom",	   K_CONNECTIONS},
  {"disconnect",   K_DISCONNECT},
  {"kick",         K_DISCONNECT},
  {"help",         K_HELP},
  {"close",        K_CLOSE},
  {"quit",         K_CLOSE},
  {"op",           K_OP},
  {"cycle",        K_CYCLE},
  {"die",          K_DIE},
  {"tcmintro",     K_TCMINTRO},
  {"set",          K_SET},
  {"unkline",      K_UNKLINE},
  {"dkline",       K_DLINE},
  {"dline",        K_DLINE},
  {"class",	   K_CLASS},
  {"classt",	   K_CLASST},
  {"chat",	   K_CHAT},
  {"ban",	   K_BAN},
  {"vbots",	   K_VBOTS},
  {"vlist",	   K_VLIST},
  {"hmulti",	   K_HMULTI},
  {"umulti",	   K_UMULTI},
  {"mem", 	   K_MEM},
  {"action",	   K_ACTION},
  {"actions",	   K_ACTION},
  {"motd",	   K_MOTD},
  {"save",	   K_SAVE},
  {"load",	   K_LOAD},
  {"locops",	   K_LOCOPS},
  {"info",	   K_INFO},
  {"vmulti",	   K_VMULTI},
  {"uptime",	   K_UPTIME},
  {"autopilot",	   K_AUTOPILOT},
#ifdef ENABLE_QUOTE
  {"quote",        K_QUOTE},
  {"raw",          K_QUOTE},
#endif
  {NULL,	   0}
};

/*
 * init_tokenizer()
 *
 * inputs	- NONE
 * output	- NONE
 * side effects	- initalize the token hash table
 */

void init_tokenizer()
{
  int i;
  int hash;
  struct command_hash *hash_ptr;
  struct command_hash *new_command;

  for(i=0; i < MAX_COMMAND_HASH; i++)
    command_hash_table[i] = ((struct command_hash *)NULL);

  for(i = 0; command_table[i].token_string; i++ )
    {
      new_command = (struct command_hash *)malloc(sizeof(struct command_hash));
      if(new_command == (struct command_hash *)NULL)
	{
	  fprintf(stderr,"Out of memory in token.c\n");
	  exit(0);
	}

      new_command->token_string = strdup(command_table[i].token_string);
      new_command->token = command_table[i].keyword_value;

      hash = hash_cmd(command_table[i].token_string);
      hash_ptr = command_hash_table[hash];

      if(hash_ptr)
	{
	  new_command->next = hash_ptr;
	}
      else
	{
	  new_command->next = (struct command_hash *)NULL;
	}
      command_hash_table[hash] = new_command;
    }
}

/*
 * get_token()
 * 
 * input	- token string in
 * output	- token number out
 * side effects	- return a token number from given input string
 */

int get_token(char *token_in)
{
  struct command_hash *hash_ptr;

  for( hash_ptr = command_hash_table[hash_cmd(token_in)];
       hash_ptr; hash_ptr = hash_ptr->next )
    {
      if(!strcasecmp(hash_ptr->token_string,token_in))
	return(hash_ptr->token);
    }

  return 0;	/* Not found */
}

/*
 * hash_cmd()
 *
 * input	- pointer to string
 * output	- hash value 
 * side effects	- NONE
 */

static int hash_cmd(char *string)
{
  int hash = 0;

  while(*string)
    {
      hash += (*string) & 0x5F;	/* ignore the upper/lower case bit */
      string++;
    }

  return( hash & MAX_COMMAND_HASH);
}

char* splitc ( char *rest, char divider)
{
  char *p;

  if(!(p = strchr(rest, divider)))
    {
      return((char *)NULL);
    }

  *p = 0;
  p++;
  return p;
}

char* split (char *rest)
{
  return ( splitc(rest, ' ') );
}

int occurance(char *string, char find)
{
  int a=0, found=0;
#ifdef DEBUGMODE
  placed;
#endif

  if (!string) return 0;
  for (a=0;a<strlen(string);++a)
    if (string[a] == find) ++found;
  return found;
}










