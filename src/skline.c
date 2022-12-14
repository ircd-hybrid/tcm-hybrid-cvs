/*
 *  tcm-hybrid: an advanced irc connection monitor
 *  skline.c: dynamic klines for dynamic hostnames
 *
 *  Copyright (C) 2004 by William Bierman
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
 *    $Id: skline.c,v 1.5 2004/06/10 23:20:23 bill Exp $
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "tcm.h"
#include "tools.h"
#include "tcm_io.h"
#include "hash.h"
#include "userlist.h"
#include "config.h"
#include "skline.h"
#include "match.h"

static int
find_dynamic_info(char *hostmask)
{
  struct dynamic_info *dyn;
  dlink_node *ptr;

  DLINK_FOREACH(ptr, dynamic_hosts.head)
  {
    dyn = ptr->data;

    if (strcasecmp(dyn->host, hostmask) == 0)
      return YES;
  }

  return NO;
}

/*
 * isdynamic()
 *
 * inputs	-	pointer to user struct
 * outputs	-	YES for dynamic, NO otherwise
 * side effects	-	none
 */
int
isdynamic(char *host)
{
  struct dynamic_info *dyn;
  dlink_node *ptr;

  DLINK_FOREACH(ptr, dynamic_hosts.head)
  {
    dyn = ptr->data;

    if (!match(dyn->host, host)) 
      return YES;
  }

  return NO;
}

/*
 * dynamic_empty()
 *
 * inputs	-	none
 * outputs	-	YES if dlink list is empty, NO otherwise
 * side effects	-	none
 */
int
dynamic_empty()
{
  if (dynamic_hosts.count == 0)
    return YES;

  return NO;
}

/*
 * init_dynamic_info()
 *
 * inputs	-	none
 * outputs	-	none
 * side effects	-	initalizes dlink list
 */
void
init_dynamic_info()
{
  dynamic_hosts.head = dynamic_hosts.tail = NULL;
  dynamic_hosts.count = 0;
}

/*
 * clear_dynamic_info()
 *
 * inputs	-	none
 * outputs	-	none
 * side effects	-	walks through dlink list, free()ing everything
 */
void
clear_dynamic_info()
{
  dlink_node *ptr, *next_ptr;

  DLINK_FOREACH_SAFE(ptr, next_ptr, dynamic_hosts.head)
  {
    dlink_delete(ptr, &dynamic_hosts);
    xfree(ptr->data);
    xfree(ptr);
  }
}

/*
 * add_dynamic_info()
 *
 * inputs	-	hostmask
 * outputs	-	YES for success, NO otherwise
 * side effects	-	adds hostmask to dlink list
 */
int
add_dynamic_info(char *hostmask)
{
  struct dynamic_info *dyn;
  dlink_node *ptr;

  if (BadPtr(hostmask))
    return NO;

  ptr = dlink_create();
  dyn = (struct dynamic_info *) xmalloc(sizeof(struct dynamic_info));

  if (ptr == NULL || dyn == NULL)
    return NO;

  if (find_dynamic_info(hostmask) == YES)
  {
    send_to_all(NULL, FLAGS_ALL, "Error: duplicate dynamic hostmask %s",
                hostmask);
    return NO;
  }

  memset(dyn, 0, sizeof(struct dynamic_info));
  snprintf(dyn->host, sizeof(dyn->host), "%s", hostmask);
  dlink_add_tail(dyn, ptr, &dynamic_hosts);

  return YES;
}

/*
 * load_dynamic_info()
 *
 * inputs	-	filename to load from
 * outputs	-	number of hostmasks read, -1 for failure
 * side effects	-	clears dlink list and repopulates it
 */
int
load_dynamic_info(char *fname)
{
  char *filename = BadPtr(fname) ? SKLINE_FILE : fname;
  char fromfile[MAX_HOST+3];
  FILE *infile;
  int added=0;

  memset((char *)&fromfile, 0, sizeof(fromfile));

  if ((infile = fopen(filename, "r")) == NULL)
  {
    send_to_all(NULL, FLAGS_ALL, "Error opening dynamic hostmask file: %s",
                strerror(errno));
    return -1;
  }

  while (!feof(infile))
  {
    fgets((char *)&fromfile, sizeof(fromfile), infile);
    if (fromfile[0] == '\0' || fromfile[0] == '#')
      continue;

    if (fromfile[strlen(fromfile)-1] == '\n')
      fromfile[strlen(fromfile)-1] = '\0';
    if (fromfile[strlen(fromfile)-1] == '\r')
      fromfile[strlen(fromfile)-1] = '\0';

    if (add_dynamic_info(fromfile) == YES)
      ++added;
    memset((char *)&fromfile, 0, sizeof(fromfile));
  }

  fclose(infile);

  return added;
}
