/* wingate.h
 *
 * the include files for the wingate/proxy check
 * 
 * $Id: wingate.h,v 1.1 2002/05/25 17:10:29 wcampbel Exp $
 */
#ifndef __WINGATE_H
#define __WINGATE_H

void _scontinuous(int connnum, int argc, char *argv[]);
void _continuous(int connnum, int argc, char *argv[]);
void _user_signon(int connnum, int argc, char *argv[]);
void _reload_wingate(int connnum, int argc, char *argv[]);
void _config(int connnum, int argc, char * argv[]);

#endif
