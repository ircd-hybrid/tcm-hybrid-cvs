/*
 * skline.h - Smart K-Lines
 *
 * $Id: skline.h,v 1.3 2004/06/09 21:22:58 bill Exp $
 */

#ifndef __SKLINE_H_
#define __SKLINE_H_

#ifndef SKLINE_PATH
#define SKLINE_PATH "etc/dynamic.hosts"
#endif

struct dynamic_info
{
  char host[MAX_HOST];
};

dlink_list dynamic_hosts;

int isdynamic(char *);
int dynamic_empty();

void init_dynamic_info();
void clear_dynamic_info();

int add_dynamic_info(char *);
int load_dynamic_info(char *);

#endif /* __SKLINE_H_ */
