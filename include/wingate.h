/* wingate.h
 *
 * the include files for the wingate/proxy check
 * 
 * $Id: wingate.h,v 1.2 2002/05/26 05:48:01 db Exp $
 */
#ifndef __WINGATE_H
#define __WINGATE_H

void user_signon(struct plus_c_info *info_p);
void reload_wingate(int connnum, int argc, char *argv[]);
void config(int connnum, int argc, char * argv[]);

#endif
