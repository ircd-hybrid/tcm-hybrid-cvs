/* $Id: serv_commands.c,v 1.6 2002/09/24 15:22:36 bill Exp $ */

#include "setup.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <stdarg.h>
#include <time.h>

#include "config.h"
#include "tcm.h"
#include "event.h"
#include "parse.h"
#include "bothunt.h"
#include "userlist.h"
#include "logging.h"
#include "stdcmds.h"
#include "modules.h"
#include "tcm_io.h"
#include "wild.h"
#include "match.h"
#include "actions.h"
#include "handler.h"
#include "hash.h"

static void ms_notice(struct source_client *, int, char **);
static void ms_nick(struct source_client *, int, char **);
static void ms_join(struct source_client *, int, char **);
static void ms_kick(struct source_client *, int, char **);
static void ms_wallops(struct source_client *, int, char **);

struct serv_command notice_msgtab = {
  "NOTICE", NULL, ms_notice
};
struct serv_command wallops_msgtab = {
  "WALLOPS", NULL, ms_wallops
};
struct serv_command nick_msgtab = {
  "NICK", NULL, ms_nick
};
struct serv_command join_msgtab = {
  "JOIN", NULL, ms_join
};
struct serv_command kick_msgtab = {
  "KICK", NULL, ms_kick
};

void
init_serv_commands(void)
{
  add_serv_handler(&notice_msgtab);
  add_serv_handler(&nick_msgtab);
  add_serv_handler(&join_msgtab);
  add_serv_handler(&kick_msgtab);
  add_serv_handler(&wallops_msgtab);
}

void
ms_notice(struct source_client *source_p, int argc, char *argv[])
{
  struct serv_command *ptr;

  for(ptr = serv_notice_table; ptr; ptr = ptr->next)
    ptr->handler(source_p, argc, argv);
}

void
ms_nick(struct source_client *source_p, int argc, char *argv[])
{
  if(*argv[2] == ':')
    argv[2]++;

  if(strcmp(source_p->name, tcm_status.my_nick) == 0)
    strcpy(tcm_status.my_nick, source_p->name);
}

void
ms_join(struct source_client *source_p, int argc, char *argv[])
{
  if(*argv[2] == ':')
    argv[2]++;

  if(strcmp(tcm_status.my_nick, source_p->name) == 0)
    strlcpy(tcm_status.my_channel, argv[2], MAX_CHANNEL);
}

void
ms_kick(struct source_client *source_p, int argc, char *argv[])
{
  if(strcmp(tcm_status.my_nick, argv[3]) == 0)
    join();
}

void
ms_wallops(struct source_client *source_p, int argc, char *argv[])
{
  if(strncmp(argv[2], ":OPERWALL - ", 12) == 0)
    send_to_all(NULL, FLAGS_WALLOPS, "OPERWALL %s -> %s",
		source_p->name, argv[2]+12);
  else if(strncmp(argv[2], ":LOCOPS - ", 10) == 0)
    send_to_all(NULL, FLAGS_LOCOPS, "LOCOPS %s -> %s",
                source_p->name, argv[2]+10);
  else if(strncmp(argv[2], ":WALLOPS - ", 11) == 0)
    send_to_all(NULL, FLAGS_WALLOPS, "WALLOPS %s -> %s",
                source_p->name, argv[2]+11);
  else
    send_to_all(NULL, FLAGS_WALLOPS, "WALLOPS %s -> %s",
                source_p->name, argv[2]+1);
}
