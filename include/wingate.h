/* wingate.h
 *
 * the include files for the wingate/proxy check
 * 
 * $Id: wingate.h,v 1.4 2002/06/01 13:04:21 wcampbel Exp $
 */
#ifndef __WINGATE_H
#define __WINGATE_H

struct plus_c_info;

void user_signon(struct plus_c_info *info_p);
void config(int connnum, int argc, char * argv[]);

#endif
