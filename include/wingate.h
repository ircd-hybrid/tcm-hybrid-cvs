/* wingate.h
 *
 * the include files for the wingate/proxy check
 * 
 * $Id: wingate.h,v 1.5 2002/06/03 20:22:25 db Exp $
 */
#ifndef __WINGATE_H
#define __WINGATE_H

void user_signon(struct user_entry *info_p);
void config(int connnum, int argc, char * argv[]);

#endif
