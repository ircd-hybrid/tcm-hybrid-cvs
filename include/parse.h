/* $Id: parse.h,v 1.1 2002/05/22 22:03:27 leeh Exp $ */
#ifndef __PARSE_H
#define __PARSE_H

extern void parse_server(void);
extern void parse_client(int, int, char *argv[]);

extern void _wallops(int connnum, int argc, char *argv[]);
extern void _onjoin(int connnum, int argc, char *argv[]);
extern void _signon (int connnum, int argc, char *argv[]);

extern void check_clones(void *);

#ifdef SERVICES
extern void check_services(void);
#endif

#endif
