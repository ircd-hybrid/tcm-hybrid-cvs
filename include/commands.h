#ifndef __COMMANDS_H
#define __COMMANDS_H

/* $Id: commands.h,v 1.14 2002/05/25 16:49:15 wcampbel Exp $ */

void init_allow_nick();

extern void init_commands(void);

#if defined(DETECT_WINGATE) || defined(DETECT_SOCKS) || defined(DETECT_SQUID)
extern void init_wingates(void);
#endif

void m_vlist(int connnum, int argc, char *argv[]);
void m_class(int connnum, int argc, char *argv[]);
void m_classt(int connnum, int argc, char *argv[]);
void m_killlist(int connnum, int argc, char *argv[]);
void m_kline(int connnum, int argc, char *argv[]);
void m_kclone(int connnum, int argc, char *argv[]);
void m_kflood(int connnum, int argc, char *argv[]);
void m_kperm(int connnum, int argc, char *argv[]);
void m_klink(int connnum, int argc, char *argv[]);
void m_kdrone(int connnum, int argc, char *argv[]);
void m_kbot(int connnum, int argc, char *argv[]);
void m_kill(int connnum, int argc, char *argv[]);
void m_use_kaction(int connnum, int argc, char *argv[]);
void m_kaction(int connnum, int argc, char *argv[]);
void m_kspam(int connnum, int argc, char *argv[]);
void m_hmulti(int connnum, int argc, char *argv[]);
void m_umulti(int connnum, int argc, char *argv[]);
void m_register(int connnum, int argc, char *argv[]);
void m_opers(int connnum, int argc, char *argv[]);
void m_testline(int connnum, int argc, char *argv[]);
void m_actions(int connnum, int argc, char *argv[]);
void m_action(int connnum, int argc, char *argv[]);
void m_set(int connnum, int argc, char *argv[]);
void m_uptime(int connnum, int argc, char *argv[]);
void m_exemptions(int connnum, int argc, char *argv[]);
void m_umode(int connnum, int argc, char *argv[]);
void m_connections(int connnum, int argc, char *argv[]);
void m_disconnect(int connnum, int argc, char *argv[]);
void m_help(int connnum, int argc, char *argv[]);
void m_motd(int connnum, int argc, char *argv[]);
void m_save(int connnum, int argc, char *argv[]);
void m_close(int connnum, int argc, char *argv[]);
void m_op(int connnum, int argc, char *argv[]);
void m_cycle(int connnum, int argc, char *argv[]);
void m_die(int connnum, int argc, char *argv[]);
void m_restart(int connnum, int argc, char *argv[]);
void m_info(int connnum, int argc, char *argv[]);
void m_locops(int connnum, int argc, char *argv[]);
void m_unkline(int connnum, int argc, char *argv[]);
void m_vbots(int connnum, int argc, char *argv[]);
void m_dline(int connnum, int argc, char *argv[]);
void m_quote(int connnum, int argc, char *argv[]);
void m_mem(int connnum, int argc, char *argv[]);
void m_clones(int connnum, int argc, char *argv[]);
void m_nflood(int connnum, int argc, char *argv[]);
void m_rehash(int connnum, int argc, char *argv[]);
void m_trace(int connnum, int argc, char *argv[]);
void m_failures(int connnum, int argc, char *argv[]);
void m_domains(int connnum, int argc, char *argv[]);
void m_bots(int connnum, int argc, char *argv[]);
void m_vmulti(int connnum, int argc, char *argv[]);
void m_nfind(int connnum, int argc, char *argv[]);
void m_list(int connnum, int argc, char *argv[]);
void m_ulist(int connnum, int argc, char *argv[]);
void m_hlist(int connnum, int argc, char *argv[]);

#endif
