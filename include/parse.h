/* $Id: parse.h,v 1.2 2002/05/23 08:57:49 einride Exp $ */
#ifndef __PARSE_H
#define __PARSE_H

extern void parse_server(void);
extern void parse_client(int, int, char *argv[]);

extern void _wallops(int connnum, int argc, char *argv[]);
extern void _onjoin(int connnum, int argc, char *argv[]);
extern void _signon (int connnum, int argc, char *argv[]);

extern void check_clones(void *);

#ifdef SERVICES
extern void check_services(void *);
#endif

#endif
