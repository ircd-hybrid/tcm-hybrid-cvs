#ifndef __COMMANDS_H
#define __COMMANDS_H

/* $Id: commands.h,v 1.9 2002/05/10 00:26:24 bill Exp $ */

void init_allow_nick();
void dccproc(int connnum, int argc, char *argv[]);	

/* hybrid-7 stuff again.  this time it's verbatim because ultimately,
 * waaay down the line, the modules we're loading here will work in
 * both stand-alone tcm AND ircd-hybrid-7.  :)
 *
 * i've also duped the Message struct into a TcmMessage struct.  if
 * problems are found in hybrid-7 or in here with the first one, chances
 * are we'll have problems with the second.
 */

#ifdef IRCD_HYBRID
#define MAX_MSG_HASH  387
typedef void (*MessageHandler)(struct Client*, struct Client*, int, char*[]);

struct MessageHash
{
  char   *cmd;
  struct Message      *msg;
  struct MessageHash  *next;
};

struct MessageHash *msg_hash_table[MAX_MSG_HASH];

struct  Message
{
  char  *cmd;
  unsigned int  count;      /* number of times command used */
  unsigned int  parameters; /* at least this many args must be passed
                             * or an error will be sent to the user
                             * before the m_func is even called
                             */
  unsigned int  maxpara;    /* maximum permitted parameters */
  unsigned int  flags;      /* bit 0 set means that this command is allowed
                             * to be used only on the average of once per 2
                             * seconds -SRB
                             */
  unsigned long bytes;  /* bytes received for this message */
  /*
   * client_p = Connected client ptr
   * source_p = Source client ptr
   * parc = parameter count
   * parv = parameter variable array
   */
  /* handlers:
   * UNREGISTERED, CLIENT, SERVER, OPER, LAST
   */
  MessageHandler handlers[5];
};

#else
#define MAX_MSG_HASH  200
typedef void (*TcmMessageHandler)(int connum, int argc, char *argv[]);

struct TcmMessageHash
{
  char   *cmd;
  struct TcmMessage      *msg;
  struct TcmMessageHash  *next;
};

struct TcmMessageHash msg_hash_table[MAX_MSG_HASH];

struct TcmMessage
{
  char  *cmd;
  unsigned int  parameters; /* at least this many args must be passed
                             * or an error will be sent to the user
                             * before the function is even called
                             */
  unsigned int  maxpara;    /* maximum permitted parameters */
  /*
   * connnum - index in connections[] of user doing command
   * argc    - obvious.  number of args passed
   * argv    - obvious * 2.  array of args passed, of size argc.
   */
  /* handlers:
   * UNREGISTERED, NON_OPER, OPER, ADMIN
   */
  TcmMessageHandler handlers[4];
};

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
void m_ban(int connnum, int argc, char *argv[]);
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
#ifdef WANT_ULIST
void m_ulist(int connnum, int argc, char *argv[]);
#endif
#ifdef WANT_HLIST
void m_hlist(int connnum, int argc, char *argv[]);
#endif

#endif

#endif
