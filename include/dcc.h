/* dcc.h
 *
 * 
 * $Id: dcc.h,v 1.6 2002/06/05 00:21:40 db Exp $
 */
#ifndef __DCC_H
#define __DCC_H

extern	void initiate_dcc_chat(const char *, const char *, const char *);
extern  int accept_dcc_connection(struct source_client *source_p,
		                  const char *host_name, const int port);

#endif
