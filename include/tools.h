/* $Id: tools.h,v 1.2 2002/06/21 23:14:01 leeh Exp $ */
#ifndef __TOOLS_H
#define __TOOLS_H

typedef struct _slink_node slink_node;

struct _slink_node
{
  void *data;
  slink_node *next;
};

slink_node *slink_create(void);
void slink_add(void *data, slink_node *m, slink_node **list);
void slink_add_tail(void *data, slink_node *m, slink_node **list);

void slink_delete(void *data, slink_node *m, slink_node *prev, 
		  slink_node *list);
slink_node *slink_find(void *data, slink_node *list);

#endif

