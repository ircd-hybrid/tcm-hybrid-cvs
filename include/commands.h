#ifndef __COMMANDS_H
#define __COMMANDS_H

/* $Id: commands.h,v 1.5 2001/10/29 00:12:13 wcampbel Exp $ */

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
#endif

#endif
