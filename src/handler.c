/* handler.c
 *
 * contains the code for the dcc and server command handlers
 * $Id: handler.c,v 1.5 2002/06/04 21:21:44 leeh Exp $
 */

#include <assert.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <dirent.h>
#include <unistd.h>
#include "config.h"
#include "tcm.h"
#include "tcm_io.h"
#include "bothunt.h"
#include "modules.h"
#include "stdcmds.h"
#include "wild.h"
#include "parse.h"
#include "handler.h"

struct serv_numeric *serv_numeric_table;

static int hash_command(const char *);

/* init_handlers()
 *
 * input        -
 * output       -
 * side effects - initialises the dcc/server handler stuff
 */
void
init_handlers(void)
{
  memset(dcc_command_table, 0, sizeof(struct dcc_command) * MAX_HASH);
  memset(serv_command_table, 0, sizeof(struct serv_command) * MAX_HASH);
  serv_numeric_table = NULL;
}

/* add_dcc_handler()
 *
 * input        - dcc command struct
 * output       -
 * side effects - command is added to dcc hash table
 */
void
add_dcc_handler(struct dcc_command *ptr)
{
  int hashval;

  hashval = hash_command(ptr->cmd);

  ptr->next = dcc_command_table[hashval];
  dcc_command_table[hashval] = ptr;
}

/* del_dcc_handler()
 *
 * input        - dcc command
 * output       -
 * side effects - command (if found) is removed from dcc hashtable
 */
void
del_dcc_handler(struct dcc_command *ptr)
{
  struct dcc_command *temp_ptr;
  struct dcc_command *last_ptr = NULL;
  int hashval;

  hashval = hash_command(ptr->cmd);

  /* search the hash table for the command, we dont use
   * find_dcc_handler because we need last_ptr
   */
  for(temp_ptr = dcc_command_table[hashval]; temp_ptr;
      temp_ptr = temp_ptr->next)
  {
    if(temp_ptr == ptr)
      break;

    last_ptr = temp_ptr;
  }

  /* command was found.. */
  if(temp_ptr != NULL)
  {
    /* something points to this command */
    if(last_ptr != NULL)
      last_ptr->next = ptr->next;

    /* this command is first in the hashtable */
    else
      dcc_command_table[hashval] = ptr->next;
  }
}

/* find_dcc_handler()
 *
 * input        - command
 * output       -
 * side effects - dcc handler is returned if found, else NULL
 */
struct dcc_command *
find_dcc_handler(char *cmd)
{
  struct dcc_command *ptr;
  int hashval;

  hashval = hash_command(cmd);

  for(ptr = dcc_command_table[hashval]; ptr; ptr = ptr->next)
  {
    if(strcasecmp(cmd, ptr->cmd) == 0)
      return ptr;
  }

  return NULL;
}

/* add_serv_handler()
 *
 * input        - serv command struct
 * output       -
 * side effects - command is added to serv hash table
 */
void
add_serv_handler(struct serv_command *ptr)
{
  int hashval;

  hashval = hash_command(ptr->cmd);

  ptr->next = serv_command_table[hashval];
  serv_command_table[hashval] = ptr;
}

/* del_serv_handler()
 *
 * input        - server command
 * output       -
 * side effects - command (if found) is removed from server hashtable
 */
void
del_serv_handler(struct serv_command *ptr)
{
  struct serv_command *temp_ptr;
  struct serv_command *last_ptr = NULL;
  int hashval;

  hashval = hash_command(ptr->cmd);

  for(temp_ptr = serv_command_table[hashval]; temp_ptr;
      temp_ptr = temp_ptr->next)
  {
    if(temp_ptr == ptr)
      break;

    last_ptr = temp_ptr;
  }

  /* command was found */
  if(temp_ptr != NULL)
  {
    if(last_ptr != NULL)
      last_ptr->next = ptr->next;
    else
      serv_command_table[hashval] = ptr->next;
  }
}

/* find_serv_handler()
 *
 * input        - command
 * output       -
 * side effects - handler of command is returned
 */
struct serv_command *
find_serv_handler(char *cmd)
{
  struct serv_command *ptr;
  int hashval;

  hashval = hash_command(cmd);

  for(ptr = serv_command_table[hashval]; ptr; ptr = ptr->next)
  {
    if(strcasecmp(cmd, ptr->cmd) == 0)
      return ptr;
  }

  return NULL;
}

/* add_numeric_handler()
 *
 * input        - numeric handler
 * output       -
 * side effects - handler is added to numeric handler list
 */
void
add_numeric_handler(struct serv_numeric *ptr)
{
  ptr->next = serv_numeric_table;
  serv_numeric_table = ptr;
}

/* del_numeric_handler()
 *
 * input        - numeric handler
 * output       -
 * side effects - handler (if found) is removed from handler list
 */
void
del_numeric_handler(struct serv_numeric *ptr)
{
  struct serv_numeric *temp_ptr;
  struct serv_numeric *last_ptr = NULL;

  for(temp_ptr = serv_numeric_table; temp_ptr;
      temp_ptr = temp_ptr->next)
  {
    if(temp_ptr == ptr)
      break;

    last_ptr = temp_ptr;
  }

  if(last_ptr != NULL)
    last_ptr->next = ptr->next;
  else
    serv_numeric_table = ptr->next;
}

/* hash_command()
 *
 * input        - command
 * output       -
 * side effects - command is changed into its hash value
 */
static int
hash_command(const char *p)
{
  int hash_val = 0;

  while(*p)
  {
    hash_val += ((int)(*p)&0xDF);
    p++;
  }

  return(hash_val % MAX_HASH);
}

