/* parse.c
 * 
 * handles all functions related to parsing
 *
 * $Id: parse.c,v 1.1 2002/05/22 22:03:34 leeh Exp $
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

#ifdef HAVE_SYS_STREAM_H
# include <sys/stream.h>
#endif

#ifdef HAVE_SYS_SOCKETVAR_H
# include <sys/socketvar.h>
#endif

#ifdef AIX
# include <sys/select.h>
#endif

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include "config.h"
#include "tcm.h"
#include "event.h"
#include "token.h"
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


static void proc(char *source,char *function, char *body);
static void privmsgproc(char *nick,char *userhost, int argc, char *argv[]);

static void send_umodes(char *nick);
static void onkick(char *nick);
static void onnick(char *old_nick, char *new_nick);
static void onnicktaken(void);
static void cannotjoin(char *channel);

#ifdef SERVICES
static void on_services_notice(int argc, char *argv[]);
#endif

extern struct connection connections[MAXDCCCONNS+1];

int  maxconns = 0;
int act_drone, act_sclone;

#ifdef SERVICES
/* For talking to services */
struct services_entry services;
#endif

/*
 * parse_server()
 *
 * inputs       - NONE
 * output       - NONE
 * side effects - process server message
 */
void parse_server(void)
{
  char *buffer = connections[0].buffer;
  char *p;
  char *source;
  char *fctn;
  char *body = NULL;

  if (*buffer == ':')
  {
    source = buffer+1;
    if ((p = strchr(buffer,' ')) != NULL)
    {
      *p = '\0';
      p++;
      fctn = p;

      if ((p = strchr(fctn,' ')) != NULL)
      {
        *p = '\0';
        p++;
        body = p;
      }
    }
    else
      return;
  }
  else
  {
    source = "";

    fctn = buffer;

    if ((p = strchr(fctn,' ')) != NULL)
    {
      *p = '\0';
      p++;
      body = p;
    }
    else
      return;
  }

  if (config_entries.debug && outfile)
  {
    fprintf(outfile, ">source=[%s] fctn=[%s] body=[%s]\n",
            source, fctn, body);        /* - zaph */
    fflush(outfile);
  }

  proc(source,fctn,body);
}

/*
 * parse_client
 *
 * inputs       - index into connections array
 *              - integer argument count
 *              - array of pointers to split up argvs
 * output       - none
 * side effects -
 */

void
parse_client(int i, int argc, char *argv[])
{
  int j;
  struct common_function *temp;

  for (j = 0; j < MAX_MSG_HASH; j++)
    {
      if (msg_hash_table[j].msg != NULL)
        {
          if (strcasecmp(msg_hash_table[j].cmd, argv[0]) == 0)
            {
              if (connections[i].type & TYPE_ADMIN)
                msg_hash_table[j].msg->handlers[3](i, argc, argv);
              else if (connections[i].type & TYPE_OPER)
                msg_hash_table[j].msg->handlers[2](i, argc, argv);
              else if (connections[i].type & TYPE_REGISTERED)
                msg_hash_table[j].msg->handlers[1](i, argc, argv);
              else
                msg_hash_table[j].msg->handlers[0](i, argc, argv);
              return;
            }
        }
    }
  for (temp=dcc;temp;temp=temp->next)
    temp->function(i, argc, argv);
}

/*
 * proc()
 *   Parse server messages based on the function and handle them.
 *   Parameters:
 *     source - nick!user@host or server host that sent the message
 *     fctn - function for the server msgs (e.g. PRIVMSG, MODE, etc.)
 *     param - The remainder of the server message
 *   Returns: void
 *
 *     If the source is in nick!user@host format, split the nickname off
 *     from the userhost.  Split the body off from the parameter for the
 *     message.  The parameter is generally either our nickname or the
 *     nickname directly affected by this message.  You can kind of figure
 *     the rest of the giant 'if' statement out.  Occasionally we need to
 *     parse additional parameters out of the body.  To find out what all
 *     the numeric messages are, check out 'numeric.h' that comes with the
 *     server code.  ADDED: watch out for partial PRIVMSGs received from the
 *     server... hold them up and make sure to stay synced with the timer
 *     signals that may be ongoing.
 */
static void proc(char *source,char *fctn,char *param)
{
    char *userhost;
    int numeric=0;      /* if its a numeric */
    int argc=0;
    char *p, *q;
    char *argv[MAX_ARGV];
    struct common_function *temp;

    if (source && *source)
      argv[argc++] = source;
    if (fctn && *fctn)
      argv[argc++] = fctn;
    p = param;
    if (*p == ':')
      argv[argc++] = p;
    else
    {
      q = strchr(p, ' ');

      for (; (argc < MAX_ARGV-1) && q; q=strchr(p, ' '))
      {
        *q++ = '\0';
        if (*q == ':')
        {
          argv[argc++] = p;
          argv[argc++] = q+1;
          numeric = 1;
          break;
        }
        argv[argc++] = p;
        p = q;
      }

      if (*p != '\0' && !numeric)
        argv[argc++] = p;
    }

    numeric=0;
    if (strcmp(argv[1],"PRIVMSG") == 0)
    {
      if(strcasecmp(argv[2],mynick) == 0)
      {
        if ((userhost = strchr(argv[0], '!')) != NULL)
          *userhost++ = '\0';
        if (argv[3][0] == '\001')       /* it's a CTCP something */
          for (temp=onctcp;temp;temp=temp->next)
            temp->function(0, argc, argv);
        else
          privmsgproc(source,userhost,argc,argv);
      }
    }
    else if (strcmp(argv[0], "PING") == 0) /* PING to a client can only
                                           ** occur without a prefix,
                                           ** such as ping cookies
                                           ** and the server simply
                                           ** seeing if the TCM is still
                                           ** alive.
                                           */
    {
      toserv("PONG %s\n", argv[1]);
    }
    else if (strcmp(argv[0],"ERROR") == 0)
    {
      if (strncmp(argv[1], ":Closing Link: ", 15) == 0)
      {
        if (strstr(argv[1], "collision)"))
          onnicktaken();
        for (temp=signoff;temp;temp=temp->next)
          temp->function(0, argc, argv);
      }
    }
    else if ((strcmp(argv[1],"WALLOPS")) == 0)
    {
      for (temp = wallops; temp; temp=temp->next)
	temp->function(0, argc, argv);
    }
    else if ((strcmp(argv[1],"JOIN")) == 0)
    {
      for (temp=onjoin;temp;temp=temp->next)
	temp->function(0, argc, argv);
    }
    else if ((strcmp(argv[1],"KICK")) == 0)
    {
      onkick(argv[3]);
    }
    else if (strcmp(argv[1],"NICK") == 0)
    {
      onnick(source,argv[2]);
    }
    else if (strcmp(fctn,"NOTICE") == 0)
    {
      if(strcasecmp(source,config_entries.rserver_name) == 0)
      {
        for (temp=server_notice;temp;temp=temp->next)
          temp->function(0, argc, argv);
      }
#ifdef SERVICES
      else if(strcasecmp(source,SERVICES_NAME) == 0)
      {
        on_services_notice(argc, argv);
      }
#endif
    }

    if(isdigit((int) fctn[0]) && isdigit((int) fctn[1]) &&
       isdigit((int) fctn[2]))
      numeric = atoi(fctn);
    else
      numeric = (-1);

    switch(numeric)
      {
      case RPL_STATSYLINE:
        if (!strcasecmp(argv[4], myclass))
          pingtime = atoi(argv[5]) * 2 + 15;
        break;
      case ERR_NICKNAMEINUSE:
        onnicktaken();
        break;
      case  ERR_NOTREGISTERED:
        argv[0] = "Not registered";
        linkclosed(0, 1, argv);
        break;
      case ERR_CHANNELISFULL: case ERR_INVITEONLYCHAN:
      case ERR_BANNEDFROMCHAN: case ERR_BADCHANNELKEY:
        cannotjoin(argv[3]);
        break;
      case RPL_MYINFO:
        strncpy(config_entries.rserver_name, argv[3], MAX_CONFIG);

        if ((p = strstr(argv[4],"hybrid")))
          {
            config_entries.hybrid = YES;

            p += 7;
            if(*p == '5')
              config_entries.hybrid_version = 5;
            else if(*p == '6')
              config_entries.hybrid_version = 6;
            else if(*p == '7')
              config_entries.hybrid_version = 7;
          }
        else
           config_entries.hybrid = NO;
        if (!amianoper)
          do_init();
        else
          send_umodes(mynick);
        break;

      case RPL_YOUREOPER:
        amianoper = YES;
        oper_time = time(NULL);
        send_umodes(mynick);
        inithash();
        toserv("STATS Y\n");
        break;
      case RPL_TRACEOPERATOR:
      case RPL_TRACEUSER:
        for (temp=ontraceuser;temp;temp=temp->next)
          temp->function(0, argc, argv);
        break;
      case RPL_TRACECLASS:
        for (temp=ontraceclass;temp;temp=temp->next)
          temp->function(0, argc, argv);
        break;
      case RPL_STATSILINE:
        for (temp=statsi;temp;temp=temp->next)
          temp->function(0, argc, argv);
        break;
      case RPL_STATSKLINE:
        for (temp=statsk;temp;temp=temp->next)
          temp->function(0, argc, argv);
        break;
      case RPL_STATSOLINE:
        for (temp=statso;temp;temp=temp->next)
          temp->function(0, argc, argv);
        break;
      case RPL_ENDOFSTATS:
        break;
      case RPL_VERSION:
        /* version_reply(body); */
        break;
      case ERR_PASSWDMISMATCH:
      case ERR_NOOPERHOST:              /* Can't oper! */
        argv[0] = "Can't oper";
        linkclosed(0, 1, argv);
        break;
      case RPL_STATSELINE:
      case RPL_STATSFLINE:
        for (temp=statse;temp;temp=temp->next)
          temp->function(0, argc, argv);
        break;
      default:
        break;
      }
}

#ifdef SERVICES
/*
 * check_services
 *
 * inputs       - NONE
 * output       - NONE
 * side effects -
 */

void
check_services(void *unused)
{
  privmsg(SERVICES_NICK,"clones %d\n", SERVICES_CLONE_THRESHOLD );

#ifdef SERVICES_DRONES
  privmsg(SERVICES_NICK,"drones %s\n", config_entries.rserver_name);
#endif
}

/*
 * on_services_notice
 *
 * inputs       - body from message sent to us from service.us
 * output       - NONE
 * side effects - reports of global cloners
 */
static
void on_services_notice(int argc, char *argv[])
{
  char userathost[MAX_HOST];
  char *p;
  char *user, *host, *nick;

#ifdef SERVICES_DRONES
  /* kludge. but if there is a ! seen in parm1, its a drone report */
  if ((p = strchr(argv[3],'!' )) != NULL)
  {
    nick = argv[3];
    if (*nick == ':')
      ++nick;

    *p++ = '\0';
    user = p;

    if ((host = strchr(p,'@')) == NULL)
      return;
    host++;

    if ((p = strchr(host,' ')) != NULL)
      *p = '\0';

    report(SEND_ALL_USERS, CHANNEL_REPORT_DRONE, "%s reports drone %s\n",
           SERVICES_NAME, nick);

    handle_action(act_drone, 1, nick, user, host, 0, 0);
    log("%s reports drone %s [%s@%s]\n", SERVICES_NAME, nick, user, host);
    return;
  }

#endif
  if ((p = strrchr(argv[3], ' ')) == NULL)
    return;
  p -= 2;
  if (strcmp(p+3,"users") == 0 && strncmp(p, "on", 2) != 0)
  {
    if ((p = strchr(argv[3], ' ')) == NULL)
      return;
    *p = '\0';
    p += 3;
    strncpy(services.cloning_host,argv[3],MAX_HOST-1);
    if (!services.last_cloning_host[0])
      strncpy(services.last_cloning_host,argv[3],MAX_HOST-1);
    strncpy(services.user_count,p,SMALL_BUFF-1);
    services.kline_suggested = NO;
    return;
  }

  if ((p = strrchr(argv[3], ' ')) == NULL)
    return;
  p -= 2;
  if ((strncmp(p, "on", 2) == 0) &&
      (strcasecmp(config_entries.rserver_name,p+3) == 0))
  {
    nick = argv[3]+1;
    while (*nick == ' ') ++nick;

    if (strcmp(services.last_cloning_host,services.cloning_host) != 0)
      services.clones_displayed = 0;

    strncpy(services.last_cloning_host,services.cloning_host,MAX_HOST-1);

    if (services.clones_displayed == 3)
      return;
    services.clones_displayed++;

    strncpy(userathost,services.cloning_host,sizeof(userathost));

    if ((host = strchr(userathost, '@')) == NULL)
      return;

    user = userathost;
    *host++ = '\0';

    if (services.kline_suggested == NO)
    {
      handle_action(act_sclone, (*user != '~'), nick, user, host, 0, 0);
      services.kline_suggested = YES;
    }
  }
  else
    services.clones_displayed = 0;
}

#endif

/*
 * privmsgproc()
 *
 * inputs       - nick
 *              - user@host string
 *              - message body
 * output       - none
 * side effects -
 */
void privmsgproc(char *nick, char *userhost, int argc, char *argv[])
{
  int token;
  char *user;   /* user portion */
  char *host;   /* host portion */
  char *p;

  user = userhost;
  if ((p = strchr(userhost,'@')) == NULL)
    return;

  *p++ = '\0';

  host = p;

  if (argv[3][0] != '.')
  {
    sendtoalldcc(SEND_OPERS_PRIVMSG_ONLY,
                 "[%s!%s@%s] %s", nick, user, host, argv[3]);
    return;
  }

  token = get_token(argv[3]+1);

  if (config_entries.opers_only)
  {
    if (!isoper(user,host))
    {
      notice(nick,"You are not an operator");
      return;
    }
  }

  switch(token)
  {
  case K_CHAT:
    if (initiated_dcc_socket > 0)
    {
      if ((initiated_dcc_socket_time + 60) < time(NULL))
      {
        (void)close(initiated_dcc_socket);
        initiated_dcc_socket = -1;
        initiate_dcc_chat(nick,user,host);
      }
      else
        notice(nick,"Unable to dcc chat right now, wait a minute");
    }
    else
      initiate_dcc_chat(nick,user,host);
    break;
  }
}

void
do_init(void)
{
  oper();

  toserv("VERSION\n");
  join(config_entries.defchannel, config_entries.defchannel_key);
  set_modes(config_entries.defchannel, config_entries.defchannel_mode,
            config_entries.defchannel_key);
}

/*
 * wallops()
 * inputs       - source, params, body as char string pointers
 * outputs      - sends messages to appropriate DCC users
 * side effects -
 */

void
_wallops(int connnum, int argc, char *argv[])
{
  char *nick=argv[0], *p;

  if ((p = strchr(nick, '!')) == NULL)
    return;
  *p = '\0';

  if (*nick == ':')
    ++nick;

  if (!strncmp(argv[2], ":OPERWALL - ", 12))
    sendtoalldcc(SEND_OPERWALL_ONLY, "OPERWALL %s -> %s\n", nick, argv[2]+12);
  else if (!strncmp(argv[2], ":LOCOPS - ", 9))
    sendtoalldcc(SEND_LOCOPS_ONLY, "LOCOPS %s -> %s\n", nick, argv[2]+9);
  else
    sendtoalldcc(SEND_OPERWALL_ONLY, "WALLOPS %s -> %s\n", nick, argv[2]+11);
}

/*
 * send_umodes()
 *
 * inputs       - Nick to change umodes for
 * output       - NONE
 * side effects - Hopefully, set proper umodes for this tcm
 */

static void send_umodes(char *nick)
{
  if (config_entries.hybrid && (config_entries.hybrid_version >= 6))
    toserv("MODE %s :+bcdfknrswxyzl\nSTATS I\n", nick );
  else
    toserv("FLAGS +ALL\nSTATS E\nSTATS F\n");
  initopers();
}

/*
 * _onjoin()
 *
 * inputs       - nick, channel, as char string pointers
 * output       - NONE
 * side effects -
 */

void
_onjoin(int connnum, int argc, char *argv[])
{
  char *channel = argv[2];
  char *nick = argv[0];
  char *p;

  if (*channel == ':')
    ++channel;
  if (*nick == ':')
    ++nick;
  if ((p = strchr(nick, '!')) == NULL)
    return;
  *p = '\0';
  if (strcmp(mynick, nick) == 0)
  {
    strncpy(mychannel,channel,MAX_CHANNEL-1);
    mychannel[MAX_CHANNEL-1] = 0;
  }
}

static void
onkick(char *nick)
{
  if (strcmp(mynick,nick) == 0)
  {
    join(config_entries.defchannel,config_entries.defchannel_key);
    set_modes(config_entries.defchannel, config_entries.defchannel_mode,
              config_entries.defchannel_key);
  }
}

static void onnick(char *old_nick,char *new_nick)
{
  char *p;

  if (*new_nick == ':')
    ++new_nick;
  if (*old_nick == ':')
    ++old_nick;

  if ((p = strchr(old_nick, '!')) != NULL)
    *p = '\0';

  if (strcmp(old_nick,mynick) == 0)
    strcpy(mynick,new_nick);
}

/*
 * onnicktaken
 *
 * inputs       - NONE
 * output       - NONE
 * side effects -
 */

static void
onnicktaken(void)
{
  char randnick[MAX_NICK];

  (void)snprintf(randnick,sizeof(randnick) - 1,"%s%1d",config_entries.dfltnick,
                 (int) random() % 10);

  if (*mychannel == '\0')
  {
    newnick(randnick);
    strcpy(mynick,randnick);

    join(config_entries.defchannel,config_entries.defchannel_key);
    set_modes(config_entries.defchannel, config_entries.defchannel_mode,
              config_entries.defchannel_key);
  }
  else if (strncmp(randnick,config_entries.dfltnick,
                   strlen(config_entries.dfltnick)))
  {
    newnick(randnick);
    strcpy(mynick,randnick);
  }
}

/*
 * cannotjoin
 *
 * inputs       - channel
 * output       - none
 * side effects -
 */

static void
cannotjoin(char *channel)
{
  char newchan[MAX_CHANNEL];
  int i;

  if (strcmp(channel,config_entries.defchannel) == 0)
    (void)snprintf(newchan,sizeof(newchan) - 1,"%.78s2",
                  config_entries.defchannel);
  else
  {
    channel += strlen(config_entries.defchannel);
    i = atoi(channel);
    (void)snprintf(newchan,sizeof(newchan) - 1,"%.78s%1d",
                   config_entries.defchannel,i+1);
  }

  join(newchan, config_entries.defchannel_key);
  set_modes(newchan, config_entries.defchannel_mode,
            config_entries.defchannel_key);
}

void
_signon (int connnum, int argc, char *argv[])
{

    connections[0].nbuf = 0;
    if (*mynick == '\0')
      strcpy (mynick,config_entries.dfltnick);

    if( config_entries.server_pass[0] )
      toserv("PASS %s\n", config_entries.server_pass);

    toserv("USER %s %s %s :%s\r\n",
           config_entries.username_config,
           ourhostname,
           config_entries.server_name,
           config_entries.ircname_config);

    toserv("NICK %s\r\n", mynick);
}

/*
 * check_clones
 *
 * inputs       - NONE
 * output       - NONE
 * side effects - check for "unseen" clones, i.e. ones that have
 *                crept onto the server slowly
 */

void
check_clones(void *unused)
{
  struct hashrec *userptr;
  struct hashrec *top;
  struct hashrec *temp;
  int numfound;
  int i;
  int notip;

  for (i=0; i < HASHTABLESIZE; i++)
  {
    for (top = userptr = domaintable[i]; userptr; userptr = userptr->collision)
    {
      /* Ensure we haven't already checked this user & domain */
      for( temp = top, numfound = 0; temp != userptr;
           temp = temp->collision )
      {
        if (!strcmp(temp->info->user,userptr->info->user) &&
            !strcmp(temp->info->domain,userptr->info->domain))
          break;
      }

      if (temp == userptr)
      {
        for( temp = temp->collision; temp; temp = temp->collision )
        {
          if (!strcmp(temp->info->user,userptr->info->user) &&
              !strcmp(temp->info->domain,userptr->info->domain))
            numfound++; /* - zaph & Dianora :-) */
        }
        if (numfound > MIN_CLONE_NUMBER)
        {
          notip = strncmp(userptr->info->domain,userptr->info->host,
                          strlen(userptr->info->domain)) ||
            (strlen(userptr->info->domain) ==
             strlen(userptr->info->host));

          sendtoalldcc(SEND_WARN_ONLY,
                       "clones> %2d connections -- %s@%s%s {%s}\n",
                       numfound,userptr->info->user,
                       notip ? "*" : userptr->info->domain,
                       notip ? userptr->info->domain : "*",
                       userptr->info->class);
        }
      }
    }
  }
}

