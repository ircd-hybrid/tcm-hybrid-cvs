/* dcc.h
 *
 * 
 * $Id: dcc.h,v 1.2 2002/05/31 01:54:13 wcampbel Exp $
 */
#ifndef __DCC_H
#define __DCC_H

extern	int initiated_dcc_socket;
extern	time_t initiated_dcc_socket_time;
extern	void initiate_dcc_chat(const char *, const char *, const char *);
extern  int accept_dcc_connection(const char *hostport,
			  const char *nick, char *userhost);

#endif
