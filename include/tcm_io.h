/* tcm_io.h
 *
 * the include files for the tcm IO
 * 
 * $Id: tcm_io.h,v 1.2 2002/05/24 02:31:48 db Exp $
 */
#ifndef __TCM_IO_H
#define __TCM_IO_H

extern int initiated_dcc_socket;
extern time_t initiated_dcc_socket_time;
extern void initiate_dcc_chat(char *, char *, char *);

extern fd_set readfds;
extern fd_set writefds;

extern void read_packet(void);
extern void linkclosed(int, int, char *argv[]);

extern void print_to_socket(int, const char *, ...);
extern void print_to_server(const char *, ...);
#endif
