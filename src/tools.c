/*  tcm-hybrid/src/tools.c by fl_
 *  Copyright (C) 2002 ircd-hybrid development team
 *
 *  $Id: tools.c,v 1.3 2002/06/21 23:14:04 leeh Exp $
 */

#include <stdlib.h>
#include "tcm.h"
#include "tools.h"

slink_node *
slink_create(void)
{
  slink_node *m;

  m = (slink_node *) xmalloc(sizeof(slink_node));
  m->data = NULL;
  m->next = NULL;

  return m;
}

void
slink_add(void *data, slink_node *m, slink_node **list)
{
  m->data = data;
  m->next = *list;
  *list = m;
}

void
slink_add_tail(void *data, slink_node *m, slink_node **list)
{
  slink_node *ptr;

  ptr = *list;
  m->data = data;
  m->next = NULL;

  if(ptr == NULL)
  {
    *list = m;
  }
  else
  {
    while(ptr->next)
      ptr = ptr->next;
  
    ptr->next = m;
  }
}

void
slink_delete(void *data, slink_node *m, slink_node *prev,
            slink_node *list)
{
  if(prev)
    prev->next = m->next;
  else
    list = m->next;
}

slink_node *
slink_find(void *data, slink_node *list)
{
  slink_node *ptr;

  for(ptr = list; ptr; ptr = list->next)
  {
    if(ptr->data == data)
      return ptr;
  }

  return NULL;
}

