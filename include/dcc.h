/* dcc.h
 *
 * 
 * $Id: dcc.h,v 1.4 2002/06/04 23:49:44 db Exp $
 */
#ifndef __DCC_H
#define __DCC_H

extern	void initiate_dcc_chat(const char *, const char *, const char *);
extern  int accept_dcc_connection(const char *host_name, const char *port,
				  const char *nick, char *userhost);

#endif
