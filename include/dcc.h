/* dcc.h
 *
 * 
 * $Id: dcc.h,v 1.7 2002/06/05 01:00:58 db Exp $
 */
#ifndef __DCC_H
#define __DCC_H

extern	void initiate_dcc_chat(struct source_client *source_p);
extern  int  accept_dcc_connection(struct source_client *source_p,
				   const char *host_name, const int port);

#endif
