/*
 *  tcm-hybrid: an advanced irc connection monitor
 *  handler.c: management of usable/parsable dcc and server messages
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
 *    $Id: handler.c,v 1.11 2004/06/10 23:20:23 bill Exp $
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
#include "stdcmds.h"
#include "parse.h"
#include "handler.h"

struct serv_numeric *serv_numeric_table;

static int hash_command(const char *);

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
  struct dcc_command *tptr;
  struct dcc_command *last_ptr = NULL;
  int hashval;

  hashval = hash_command(ptr->cmd);

  /* search the hash table for the command, we dont use
   * find_dcc_handler because we need last_ptr
   */
  for(tptr = dcc_command_table[hashval]; tptr; tptr = tptr->next)
  {
    if(tptr == ptr)
    {
      if(last_ptr != NULL)
	last_ptr->next = ptr->next;
      else
	dcc_command_table[hashval] = ptr->next;
      break;
    }
    last_ptr = tptr;
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
  struct serv_command *tptr;
  struct serv_command *last_tptr = NULL;
  int hashval;

  hashval = hash_command(ptr->cmd);

  for(tptr = serv_command_table[hashval]; tptr; tptr = tptr->next)
  {
    if(tptr == ptr)
    {
      if(last_tptr != NULL)
	last_tptr->next = tptr->next;
      else
	serv_command_table[hashval] = tptr->next;
      break;
    }
    last_tptr = tptr;
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
  struct serv_numeric *tptr;
  struct serv_numeric *last_ptr = NULL;

  for(tptr = serv_numeric_table; tptr; tptr = tptr->next)
  {
    if(tptr == ptr)
      {
	if(last_ptr != NULL)
	  last_ptr->next = ptr->next;
	else
	  serv_numeric_table = ptr->next;
	break;
      }
    last_ptr = tptr;
  }
}

void
add_serv_notice_handler(struct serv_command *ptr)
{
  ptr->next = serv_notice_table;
  serv_notice_table = ptr;
}

void
del_serv_notice_handler(struct serv_command *ptr)
{
  struct serv_command *tptr;
  struct serv_command *last_ptr = NULL;

  for(tptr = serv_notice_table; tptr; tptr = tptr->next)
  {
    if(tptr == ptr)
    {
      if(last_ptr != NULL)
	last_ptr->next = ptr->next;
      else
	serv_notice_table = ptr->next;
      break;
    }
    last_ptr = tptr;
  }
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

/* m_unregistered()
 *
 * sent to an oper who needs to register to use a command
 */
void
m_unregistered(struct connection *connection_p, int argc, char *argv[])
{
  send_to_connection(connection_p, "You have not registered");
}

/* m_not_admin()
 *
 * sent to an oper who tries to execute an admin only command
 */
void
m_not_admin(struct connection *connection_p, int argc, char *argv[])
{
  send_to_connection(connection_p,
                     "Only authorized admins may use this command");
}
