/* services.c
 *
 * module used to interact with efnets services
 *
 * $Id: services.c,v 1.25 2002/12/12 19:30:27 bill Exp $
 */

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>

#include "config.h"
#include "tcm.h"
#include "event.h"
#include "bothunt.h"
#include "userlist.h"
#include "parse.h"
#include "numeric.h"
#include "hash.h"
#include "logging.h"
#include "stdcmds.h"
#include "wild.h"
#include "tcm_io.h"
#include "serno.h"
#include "patchlevel.h"
#include "modules.h"
#include "actions.h"
#include "handler.h"

#ifdef SERVICES
void services_handler(struct source_client *source_p, int argc, char *argv[]);

struct serv_command services_msgtab = {
  "NOTICE", NULL, services_handler
};

struct services_entry
{
  char cloning_host[MAX_HOST];
  int clone_amount;
  int clones_displayed;
  int kline_suggested;
};

struct services_entry services;

void
init_services(void)
{
  add_serv_notice_handler(&services_msgtab);
  eventAdd("check_services", check_services, NULL, SERVICES_CHECK_TIME);
  init_one_action(&act_sclone, "sclone", HS_SCLONE, REASON_SCLONE);
#ifdef SERVICES_DRONES
  init_one_action(&act_drone, "drone", HS_DRONE, REASON_DRONE);
#endif
}

void
services_handler(struct source_client *source_p, int argc, char *argv[])
{
  char userathost[MAX_HOST];
  char *user;
  char *host;
  char *nick;
  char *p;

  if(strcasecmp(source_p->name, SERVICES_NAME))
    return;

#ifdef SERVICES_DRONES
  /* kludge. but if there is a ! seen in parm1, its a drone report */
  if((p = strchr(argv[3],'!' )) != NULL)
  {
    nick = argv[3];
    if(*nick == ':')
      nick++;

    *p++ = '\0';
    user = p;

    if((host = strchr(p, '@')) == NULL)
      return;

    *host++ = '\0';

    if((p = strchr(host, ' ')) != NULL)
      *p = '\0';

    if (ok_host(user, host, act_drone))
      return;

    if (actions[act_drone].method & METHOD_DCC_WARN)
      send_to_all(NULL, FLAGS_ALL, "%s reports drone %s", SERVICES_NAME, nick);

    if (actions[act_drone].method & METHOD_IRC_WARN && config_entries.channel != '\0')
      privmsg(config_entries.channel, "%s reports drone %s", SERVICES_NAME, nick);

    handle_action(act_drone, nick, user, host, 0, 0);
    tcm_log(L_NORM, "%s reports drone %s [%s@%s]",
            SERVICES_NAME, nick, user, host);
    return;
  }
#endif
	  
  if((p = strrchr(argv[3], ' ')) == NULL)
    return;

  p -= 2;

  /* the services clones header, giving user@host and amount */
  if((strcmp(p+3, "users") == 0) && (strncmp(p, "on", 2) != 0))
  {
    char *s;

    if((p = strchr(argv[3], ' ')) == NULL)
      return;

    *p = '\0';
    p += 3;

    if((s = strchr(argv[3], ' ')) != NULL)
      *s = '\0';

    strlcpy(services.cloning_host, argv[3], MAX_HOST);

    services.clones_displayed = 0;
    services.kline_suggested = NO;
    services.clone_amount = atoi(p);
    return;
  }

  if((p = strrchr(argv[3], ' ')) == NULL)
    return;

  p -= 2;

  if((strncmp(p, "on", 2) == 0) &&
     (strcasecmp(tcm_status.my_server, p+3) == 0))
  {	    
    nick = argv[3] + 1;

    while(*nick == ' ')
      ++nick;

    /* when could this happen? -bill */
    if(services.clones_displayed == 3)
      return;

    services.clones_displayed++;

    strlcpy(userathost, services.cloning_host, MAX_HOST);

    if((host = strchr(userathost, '@')) == NULL)
      return;

    user = userathost;
    *host++ = '\0';

    if (ok_host(user, host, act_sclone))
      return;

    if (actions[act_sclone].method & METHOD_DCC_WARN)
      send_to_all(NULL, FLAGS_ALL, "%s reports %d cloning %s@%s nick %s",
                  SERVICES_NAME, services.clone_amount, user, host, nick);

    if (actions[act_sclone].method & METHOD_IRC_WARN && config_entries.channel != '\0')
      privmsg(config_entries.channel, "%s reports %d cloning %s@%s nick %s",
              SERVICES_NAME, services.clone_amount, user, host, nick);

    if(services.kline_suggested == NO)
    {
      handle_action(act_sclone, nick, user, host, 0, 0);
      services.kline_suggested = YES;
    }
  }
}

void
check_services(void *unused)
{
  /* no point in this unless we are operd */
  if (tcm_status.am_opered == NO)
    return;

  privmsg(SERVICES_NICK,"clones %d", SERVICES_CLONE_THRESHOLD);
#ifdef SERVICES_DRONES
  privmsg(SERVICES_NICK,"drones %s", tcm_status.my_server);
#endif
}

#endif
