#ifndef __STDCMDS_H
#define __STDCMDS_H

/* $Id: stdcmds.h,v 1.25 2002/05/27 22:03:22 db Exp $ */

void op(char *chan,char *nick);
void kick(char* chan,char* nick,char *comment);
void join(char *chan,char *key);
void set_modes(char *chan,char *mode,char *key);
void leave(char *chan);
void newnick(char *nick);
void print_motd(int sock);

void do_a_kline(char *command_name,int kline_time, char *pattern, char *reason,
                char *who_did_command);

void initopers(void);
void inithash(void);
void oper();

struct s_testline
{
  char umask[MAX_USER+MAX_HOST+2]; /* umask for TESTLINE */
  int index;                       /* index in connections[]
				    * of who did command
				    */
};

#endif
