/* 
 * token.c
 *
 * command table tokenizer for tcm
 *
 * - Dianora db@db.net
 *
 * $Id: token.c,v 1.23 2002/04/04 23:19:24 bill Exp $
 *
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

#ifdef DMALLOC
#include "dmalloc.h"
#endif

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
  {"chat",	   K_CHAT},
  {NULL,	   0}
};

/*
 * init_tokenizer()
 *
 * inputs	- NONE
 * output	- NONE
 * side effects	- initalize the token hash table
 */

void 
init_tokenizer()
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

int 
get_token(char *token_in)
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

static int 
hash_cmd(char *string)
{
  int hash = 0;

  while(*string)
    {
      hash += (*string) & 0x5F;	/* ignore the upper/lower case bit */
      string++;
    }

  return( hash & MAX_COMMAND_HASH);
}

char* 
splitc ( char *rest, char divider)
{
  char *p;

  if(!(p = strchr(rest, divider)))
    {
      return((char *)NULL);
    }

  *p = '\0';
  p++;
  return p;
}

/* XXX - unused
char* 
split (char *rest)
{
  return ( splitc(rest, ' ') );
}
*/

int 
occurance(char *string, char find)
{
  int a=0, found=0;

  if (!string) return 0;
  for (a=0;a<strlen(string);++a)
    if (string[a] == find) ++found;
  return found;
}

