#ifndef __STDCMDS_H
#define __STDCMDS_H

/* $Id: stdcmds.h,v 1.33 2002/08/08 18:10:35 bill Exp $ */

void op(char *chan,char *nick);
void kick(char* chan,char* nick,char *comment);
void join(void);
void leave(char *chan);
void newnick(char *nick);
void print_motd(struct connection *connection_p);
void report(int type, char *format,...);

void do_a_kline(int kline_time, char *pattern, char *reason,
                char *who_did_command);

void init_hash(void);
void oper();

#endif
