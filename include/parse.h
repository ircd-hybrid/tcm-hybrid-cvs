/* $Id: parse.h,v 1.3 2002/05/25 15:08:06 leeh Exp $ */
#ifndef __PARSE_H
#define __PARSE_H

#define EOL(c) ((c=='\r')||(c=='\n'))

extern void parse_server(void);
extern void parse_client(int, int, char *argv[]);

extern void expand_args(char *, int, int, char *argv[]);
extern int parse_args(char *, char *argv[]);

extern void _wallops(int connnum, int argc, char *argv[]);
extern void _onjoin(int connnum, int argc, char *argv[]);
extern void _signon (int connnum, int argc, char *argv[]);

extern void check_clones(void *);

#ifdef SERVICES
extern void check_services(void *);
#endif

#endif
