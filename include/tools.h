/* $Id: tools.h,v 1.4 2002/06/24 15:44:53 leeh Exp $ */
#ifndef __TOOLS_H
#define __TOOLS_H

typedef struct _dlink_node dlink_node;
typedef struct _dlink_list dlink_list;

struct _dlink_node
{
  void *data;
  dlink_node *next;
  dlink_node *prev;
};

struct _dlink_list
{
  dlink_node *head;
  dlink_node *tail;
};

dlink_node *dlink_create(void);
void dlink_free(dlink_node *m);

void dlink_add(void *data, dlink_node *m, dlink_list *list);
void dlink_add_tail(void *data, dlink_node *m, dlink_list *list);
void dlink_delete(dlink_node *m, dlink_list *list);
dlink_node *dlink_find(void *data, dlink_list *list);

#endif

