/* dcc.h
 *
 * 
 * $Id: dcc.h,v 1.3 2002/06/01 13:04:21 wcampbel Exp $
 */
#ifndef __DCC_H
#define __DCC_H

extern	void initiate_dcc_chat(const char *, const char *, const char *);
extern  int accept_dcc_connection(const char *hostport,
			  const char *nick, char *userhost);

#endif
