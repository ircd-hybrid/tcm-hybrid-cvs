/* $Id: tools.h,v 1.1 2002/06/21 18:36:32 leeh Exp $ */
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
void slink_delete(void *data, slink_node *m, slink_node *prev, 
		  slink_node *list);
slink_node *slink_find(void *data, slink_node *list);

#endif

