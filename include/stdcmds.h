#ifndef __STDCMDS_H
#define __STDCMDS_H

/* $Id: stdcmds.h,v 1.8 2001/10/29 00:12:13 wcampbel Exp $ */

void op(char *chan,char *nick);
void kick(char* chan,char* nick,char *comment);
void join(char *chan,char *key);
void leave(char *chan);
void notice(char *nick,...);
void privmsg(char *nick,...);
void newnick(char *nick);
void print_help(int sock,char *text);
void print_motd(int sock);
void list_nicks(int sock,char *nick);
void list_virtual_users(int sock,char *userhost);
void report_multi_host(int sock,int nclones);
void report_mem(int sock);
void report_clones(int sock);
void report_nick_flooders(int sock);
void report_vbots(int sock,int nclones);
void report_domains(int sock,int num);
void report_multi(int sock,int nclones);
void report_multi_user(int sock,int nclones);
void report_multi_virtuals(int sock,int nclones);
void report_failures(int sock,int num);
void do_a_kline(char *command_name,int kline_time, char *pattern, char *reason,
                char *who_did_command);
void kill_list_users(int sock,char *userhost, char *reason);
void list_class(int sock,char *class_to_find,int total_only);
void list_users(int sock,char *userhost);
void suggest_action(int type, char *nick, char *user, char *host, int different, int identd);
void initopers(void);
void inithash(void);

struct s_testline
{
  char umask[MAX_USER+MAX_HOST+2]; /* umask for TESTLINE */
  int index;                       /* index in connections[] of who did command */
};

#endif
