/************************************************************
* MrsBot by Hendrix <jimi@texas.net>                        *
* stdcmds.c                                                 *
*   Simple interfaces to send out most types of IRC messages*
*   Contains interface to msg an entire file to a user      *
* Includes routines:                                        *
*   void op                                                 *
*   void kick                                               *
*   void who                                                *
*   void whois                                              *
*   void names                                              *
*   void join                                               *
*   void leave                                              *
*   void notice                                             *
*   void msg                                                *
*   void say                                                *
*   void action                                             *
*   void newnick                                            *
*   void invite                                             *
*   void get_userhost                                       *
*   void msg                                                *
************************************************************/

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdarg.h>
#include "config.h"
#include "tcm.h"
#include "logging.h"
#include "serverif.h"
#include "stdcmds.h"

#ifdef DMALLOC
#include "dmalloc.h"
#endif

static char *version="$Id: stdcmds.c,v 1.1 2000/09/02 04:30:49 bill Exp $";


/* The following are primitives that send messages to the server to perform
 * certain things.  The names are quite self explanatory, so I am not going
 * to document each.  By no means are they complex.
 */

void op(char *chan,char *nick)
{
  toserv("MODE %s +oooo %s\n", chan, nick);
}

void kick(char* chan,char* nick,char *comment)
{
  toserv("KICK %s %s :%s\n", chan, nick, comment);
}

void who(char *nick)
{
  toserv("WHO %s\n", nick);
}

void whois(char *nick)
{
  toserv("WHOIS %s\n", nick);
}

void names(char *chan)
{
  toserv("NAMES %s\n", chan);
}

void join(char *chan,char *key)
{
  if(key)
    toserv("JOIN %s %s\n", chan, key);
  else
    toserv("JOIN %s\n", chan);
}

void leave(char *chan)
{
  toserv("PART %s\n", chan);
}

void notice(char *nick,...)
{
  va_list va;
  char msg[MAX_BUFF];
  char *format;

  va_start(va,nick);

  format = va_arg(va, char*);
  vsprintf(msg, format, va );

  toserv("NOTICE %s :%s\n", nick, msg);
  va_end(va);
}

void msg(char *nick,...)
{
  va_list va;
  char msg[MAX_BUFF];
  char *format;

  va_start(va,nick);

  format = va_arg(va, char*);
  vsprintf(msg, format, va );
  toserv("PRIVMSG %s :%s", nick, msg);

  va_end(va);
}

void say(char *chan,...)
{
  va_list va;
  char msg[MAX_BUFF];
  char *format;

  va_start(va,chan);

  format = va_arg(va, char*);
  vsprintf(msg, format, va );
  toserv("PRIVMSG %s :%s", chan, msg);

  va_end(va);
}

void action(char *chan,char *msg)
{
#ifdef IRC_MESSAGES
  toserv("PRIVMSG %s :\001ACTION %s\001", chan, msg);
#endif
}

void newnick(char *nick)
{
  toserv("NICK %s\n", nick);
}

void invite(char *nick,char *chan)
{
  toserv("INVITE %s %s\n", nick, chan);
}



