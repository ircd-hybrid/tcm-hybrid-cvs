/* services.c
 *
 * module used to interact with efnets services
 *
 * $Id: services.c,v 1.2 2002/05/26 02:06:47 leeh Exp $
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
#include "serverif.h"
#include "parse.h"
#include "numeric.h"
#include "logging.h"
#include "stdcmds.h"
#include "commands.h"
#include "wild.h"
#include "tcm_io.h"
#include "serno.h"
#include "patchlevel.h"
#include "modules.h"

#ifdef SERVICES
void services_handler(int argc, char *argv[]);

struct serv_command services_msgtab = {
  "NOTICE", NULL, NULL, services_handler
};

struct services_entry
{
  char cloning_host[MAX_HOST];
  int clones_displayed;
  int kline_suggested;
};

struct services_entry services;

void
init_services(void)
{
  add_serv_handler(&services_msgtab);
  eventAdd("check_services", check_services, NULL, SERVICES_CHECK_TIME);
}

void
services_handler(int argc, char *argv[])
{
  char userathost[MAX_HOST];
  char *user;
  char *host;
  char *nick;
  char *p;

  if(strcasecmp(argv[0], SERVICES_NAME))
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

    report(SEND_ALL, CHANNEL_REPORT_DRONE, 
           "%s reports drone %s", SERVICES_NAME, nick);

    handle_action(act_drone, 1, nick, user, host, 0, 0);
    log("%s reports drone %s [%s@%s]", SERVICES_NAME, nick, user, host);
    return;
  }
#endif
	  
  if((p = strrchr(argv[3], ' ')) == NULL)
    return;

  p -= 2;

  /* the services clones header, giving user@host and amount */
  if((strcmp(p+3, "users") == 0) && (strncmp(p, "on", 2) != 0))
  {
    if((p = strchr(argv[3], ' ')) == NULL)
      return;

    *p = '\0';
    p += 3;

    strncpy(services.cloning_host, argv[3], MAX_HOST-1);

    services.clones_displayed = 0;
    services.kline_suggested = NO;
    return;
  }

  if((p = strrchr(argv[3], ' ')) == NULL)
    return;

  p -= 2;

  if((strncmp(p, "on", 2) == 0) &&
     (strcasecmp(config_entries.rserver_name, p+3) == 0))
  {	    
    nick = argv[3] + 1;

    while(*nick == ' ')
      ++nick;

    if(services.clones_displayed == 3)
      return;

    services.clones_displayed++;

    strncpy(userathost, services.cloning_host, MAX_HOST);

    if((host = strchr(userathost, '@')) == NULL)
      return;

    user = userathost;
    *host++ = '\0';

    if(services.kline_suggested == NO)
    {
      handle_action(act_sclone, (*user != '~'), nick, user, host, 0, 0);
      services.kline_suggested = YES;
    }
  }
}

void
check_services(void *unused)
{
  privmsg(SERVICES_NICK,"clones %d", SERVICES_CLONE_THRESHOLD);
#ifdef SERVICES_DRONES
  privmsg(SERVICES_NICK,"drones %s", config_entries.rserver_name);
#endif
}

#endif