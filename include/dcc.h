/* dcc.h
 *
 * 
 * $Id: dcc.h,v 1.5 2002/06/05 00:10:53 leeh Exp $
 */
#ifndef __DCC_H
#define __DCC_H

extern	void initiate_dcc_chat(const char *, const char *, const char *);
extern  int accept_dcc_connection(struct source_client *source_p,
		                  const char *host_name, const char *port);

#endif
