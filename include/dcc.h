/* dcc.h
 *
 * 
 * $Id: dcc.h,v 1.1 2002/05/29 18:47:46 db Exp $
 */
#ifndef __TCM_IO_H
#define __TCM_IO_H

extern	int initiated_dcc_socket;
extern	time_t initiated_dcc_socket_time;
extern	void initiate_dcc_chat(const char *, const char *, const char *);
extern  int accept_dcc_connection(const char *hostport,
			  const char *nick, char *userhost);

#endif
