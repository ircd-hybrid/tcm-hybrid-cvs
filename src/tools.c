/*
 *  tcm-hybrid: an advanced irc connection monitor
 *  tools.c: linked list routines
 *
 *  Copyright (C) 2002-2004 by William Bierman and the Hybrid Development Team
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
 *    $Id: tools.c,v 1.8 2004/06/10 23:20:24 bill Exp $
 */

#include <stdlib.h>
#include "tcm.h"
#include "tools.h"

dlink_node *
dlink_create(void)
{
  dlink_node *m;

  m = (dlink_node *) xmalloc(sizeof(dlink_node));
  m->data = NULL;
  m->next = NULL;
  m->prev = NULL;

  return m;
}

/* XXX - macro? */
void
dlink_free(dlink_node *m)
{
  xfree(m);
}

void
dlink_add(void *data, dlink_node *m, dlink_list *list)
{
  m->data = data;
  m->next = list->head;
  m->prev = NULL;

  if(list->head != NULL)
    list->head->prev = m;
  else if(list->tail == NULL)
    list->tail = m;

  list->head = m;
  list->count++;
}

void
dlink_add_tail(void *data, dlink_node *m, dlink_list *list)
{
  m->data = data;
  m->next = NULL;
  m->prev = list->tail;
  
  if(list->head == NULL)
    list->head = m;
  else if(list->tail != NULL)
    list->tail->next = m;

  list->tail = m;
  list->count++;
}

void
dlink_delete(dlink_node *m, dlink_list *list)
{
  /* item is at head */
  if(m->prev == NULL)
    list->head = m->next;
  else
    m->prev->next = m->next;

  /* item is at tail */
  if(m->next == NULL)
    list->tail = m->prev;
  else
    m->next->prev = m->prev;

  list->count--;
}

dlink_node *
dlink_find(void *data, dlink_list *list)
{
  dlink_node *ptr;

  for(ptr = list->head; ptr; ptr = ptr->next)
  {
    if(ptr->data == data)
      return ptr;
  }

  return NULL;
}

int
dlink_length(dlink_list *list)
{
  return list->count;
}
