/*  tcm-hybrid/src/tools.c by fl_
 *  Copyright (C) 2002 ircd-hybrid development team
 *
 *  $Id: tools.c,v 1.4 2002/06/24 14:56:10 leeh Exp $
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
}

void
dlink_delete(void *data, dlink_node *m, dlink_list *list)
{
  /* item is at head */
  if(m->prev == NULL)
    list->head = m->next;

  /* item is at tail */
  else if(m->next == NULL)
    list->tail = m->prev;

  /* item is in middle somewhere */
  else
  {
    m->next->prev = m->prev;
    m->prev->next = m->next;
  }
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

