/*
 * skline.h - Smart K-Lines
 *
 * $Id: skline.h,v 1.1 2003/04/14 08:50:34 bill Exp $
 */

#define DEFAULT_DYNAMIC_INFO_FILENAME	"dynamic.hosts"

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
