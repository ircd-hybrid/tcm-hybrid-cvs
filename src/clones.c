/* clones.c
 *
 * contains the code for clone functions
 * $Id: clones.c,v 1.2 2002/05/29 06:26:13 db Exp $
 */

#include <assert.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <dirent.h>
#include <unistd.h>
#include "config.h"
#include "tcm.h"
#include "tcm_io.h"
#include "commands.h"
#include "bothunt.h"
#include "modules.h"
#include "stdcmds.h"
#include "wild.h"
#include "parse.h"
#include "hash.h"
#include "handler.h"
#include "userlist.h"
#include "actions.h"

static void m_bots(int, int, char *argv[]);
static void m_umulti(int, int, char *argv[]);
static void m_hmulti(int, int, char *argv[]);
static void m_clones(int, int, char *argv[]);

static void check_clones(void *);

static void report_clones(int);
static void report_multi(int, int);
static void report_multi_user(int, int);
static void report_multi_host(int, int);

struct dcc_command bots_msgtab = {
  "bots", NULL, {m_unregistered, m_bots, m_bots}
};
struct dcc_command umulti_msgtab = {
  "umulti", NULL, {m_unregistered, m_umulti, m_umulti}
};
struct dcc_command hmulti_msgtab = {
  "hmulti", NULL, {m_unregistered, m_hmulti, m_hmulti}
};
struct dcc_command clones_msgtab = {
  "clones", NULL, {m_unregistered, m_clones, m_clones}
};

void init_clones(void)
{
  add_dcc_handler(&bots_msgtab);
  add_dcc_handler(&umulti_msgtab);
  add_dcc_handler(&hmulti_msgtab);
  add_dcc_handler(&clones_msgtab);
  eventAdd("check_clones", check_clones, NULL, CLONE_CHECK_TIME);
}

void
m_bots(int connnum, int argc, char *argv[])
{
  if (argc >= 2)
    report_multi(connections[connnum].socket, atoi(argv[1]));
  else
    report_multi(connections[connnum].socket, 3);
}

void
m_umulti(int connnum, int argc, char *argv[])
{
  int t;

  if (argc >= 2)
  {
    if ((t = atoi(argv[1])) < 3)
    {
      print_to_socket(connections[connnum].socket,
           "Using a threshold less than 3 is forbidden, changed to 3");
      t = 3;
    }
  }
  else
    t = 3;

  report_multi_user(connections[connnum].socket, t);
}

void
m_hmulti(int connnum, int argc, char *argv[])
{
  int t;

  if (argc >= 2)
  {
    if ((t = atoi(argv[1])) < 3)
    {
      print_to_socket(connections[connnum].socket,
           "Using a threshold less than 3 is forbidden, changed to 3\n");
      t = 3;
    }
  }
  else
    t = 3;
  report_multi_host(connections[connnum].socket, t);
}

void
m_clones(int connnum, int argc, char *argv[])
{
  report_clones(connections[connnum].socket);
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
      for(temp = top, numfound = 0; temp != userptr;
          temp = temp->collision)
      {
        if (!strcmp(temp->info->user,userptr->info->user) &&
            !strcmp(temp->info->domain,userptr->info->domain))
          break;
      }

      if (temp == userptr)
      {
        for(temp = temp->collision; temp; temp = temp->collision)
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

          send_to_all(FLAGS_WARN,
                       "clones> %2d connections -- %s@%s%s {%s}",
                       numfound,userptr->info->user,
                       notip ? "*" : userptr->info->domain,
                       notip ? userptr->info->domain : "*",
                       userptr->info->class);
        }
      }
    }
  }
}


/*
 * check_reconnect_clones()
 *
 * inputs       - host
 * outputs      - none
 * side effects -
 */
void
check_reconnect_clones(char *host)
{
  int i;
  time_t now = time(NULL);

  if (host == NULL)  /* I don't know how this could happen.  ::shrug:: */
    return;

  for (i=0; i<RECONNECT_CLONE_TABLE_SIZE ; ++i)
  {
    if (!strcasecmp(reconnect_clone[i].host, host))
    {
      ++reconnect_clone[i].count;

      if ((reconnect_clone[i].count > CLONERECONCOUNT) &&
          (now - reconnect_clone[i].first <= CLONERECONFREQ))
      {
        handle_action(act_rclone, 0, "", "", host, 0, 0);
        reconnect_clone[i].host[0] = 0;
        reconnect_clone[i].count = 0;
        reconnect_clone[i].first = 0;
      }
      return;
    }
  }

  for (i=0; i < RECONNECT_CLONE_TABLE_SIZE; ++i)
  {
    if ((reconnect_clone[i].host[0]) &&
        (now - reconnect_clone[i].first > CLONERECONFREQ))
    {
      reconnect_clone[i].host[0] = 0;
      reconnect_clone[i].count = 0;
      reconnect_clone[i].first = 0;
    }
  }

  for (i=0 ; i < RECONNECT_CLONE_TABLE_SIZE ; ++i)
  {
    if (!reconnect_clone[i].host[0])
    {
      strncpy(reconnect_clone[i].host, host, MAX_HOST);
      reconnect_clone[i].host[MAX_HOST] = 0;
      reconnect_clone[i].first = now;
      reconnect_clone[i].count = 1;
      break;
    }
  }
}

/*
 * report_clones
 *
 * inputs       - socket to report on
 * output       - NONE
 * side effects - NONE
 */
void
report_clones(int sock)
{
  struct hashrec *userptr;
  struct hashrec *top;
  struct hashrec *temp;
  int  numfound;
  int i;
  int j=0;
  int k;
  int foundany = NO;
  time_t connfromhost[MAXFROMHOST];

  if(sock < 0)
    return;

  for (i = 0; i < HASHTABLESIZE; ++i)
    {
      for(top = userptr = hosttable[i]; userptr; userptr = userptr->collision)
        {
          /* Ensure we haven't already checked this host */
          for(temp = top, numfound = 0; temp != userptr;
               temp = temp->collision)
            {
              if (!strcmp(temp->info->host,userptr->info->host))
                break;
            }

          if (temp == userptr)
            {
              connfromhost[numfound++] = temp->info->connecttime;
              for(temp = temp->collision; temp; temp = temp->collision)
                {
                  if (!strcmp(temp->info->host,userptr->info->host) &&
                      numfound < MAXFROMHOST)
                    connfromhost[numfound++] = temp->info->connecttime;
                }
              if (numfound > 2)
                {
                  for (k=numfound-1; k>1; --k)
                    {
                      for (j=0; j<numfound-k; ++j)
                        {
                          if (connfromhost[j] &&
                              connfromhost[j] - connfromhost[j+k] <= (k+1)
                              * CLONEDETECTINC)
                            goto getout;  /* goto rules! */
                        }
                    }
                getout:

                  if (k > 1)
                    {
                      if (!foundany)
                        {
                            print_to_socket(sock,
                                 "Possible clonebots from the following hosts:\n");
                          foundany = YES;
                        }
                        print_to_socket(sock,
                             "  %2d connections in %3d seconds (%2d total) from %s\n",
                             k+1,
                             connfromhost[j] - connfromhost[j+k],
                             numfound+1,
                             userptr->info->host);
                    }
                }
            }
        }
    }

  if (foundany == 0)
    {
        print_to_socket(sock, "No potential clonebots found.");
    }
}

/*
 * report_multi()
 *
 * inputs       - socket to print out
 * output       - NONE
 * side effects -
 */
void
report_multi(int sock,int nclones)
{
  struct hashrec *userptr,*top,*temp;
  int numfound,i;
  int notip;
  int foundany = NO;

  nclones-=2;  /* maybe someday i'll figure out why this is nessecary */
  for (i=0; i<HASHTABLESIZE; ++i)
    {
      for(top = userptr = domaintable[i]; userptr;
          userptr = userptr->collision)
        {
          /* Ensure we haven't already checked this user & domain */
          for(temp = top, numfound = 0; temp != userptr;
              temp = temp->collision)
            {
              if (!strcmp(temp->info->user,userptr->info->user) &&
                  !strcmp(temp->info->domain,userptr->info->domain))
                break;
            }

          if (temp == userptr)
            {
              for(temp = temp->collision; temp; temp = temp->collision)
                {
                  if (!strcmp(temp->info->user,userptr->info->user) &&
                      !strcmp(temp->info->domain,userptr->info->domain))
                    numfound++; /* - zaph & Dianora :-) */
                }

              if ( numfound > nclones )
                {
                  if (!foundany)
                    {
                      foundany = YES;
                      print_to_socket(sock,
                           "Multiple clients from the following userhosts:\n");
                    }

                  notip = strncmp(userptr->info->domain,userptr->info->host,
                                  strlen(userptr->info->domain)) ||
                    (strlen(userptr->info->domain) ==
                     strlen(userptr->info->host));
                  numfound++;   /* - zaph and next line*/
                  print_to_socket(sock,
                       " %s %2d connections -- %s@%s%s {%s}\n",
                       (numfound-nclones > 2) ? "==>" :
                       "   ",numfound,userptr->info->user,
                       notip ? "*." : userptr->info->domain,
                       notip ? userptr->info->domain : ".*",
                       userptr->info->class);
                }
            }
        }
    }
  if (!foundany)
    print_to_socket(sock, "No multiple logins found.\n");
}


/*
 * report_multi_user()
 *
 * inputs       - socket to print out
 * output       - NONE
 * side effects -
 */
void
report_multi_user(int sock, int nclones)
{
  struct hashrec *userptr,*top,*temp;
  int numfound;
  int i;
  int foundany = NO;

  nclones-=1;
  for (i=0;i<HASHTABLESIZE;++i)
    {
      for (top = userptr = usertable[i]; userptr;
           userptr = userptr->collision)
        {
          numfound = 0;
          /* Ensure we haven't already checked this user & domain */

          for(temp = top; temp != userptr; temp = temp->collision)
            {
              if (!match(temp->info->user,userptr->info->user))
                break;
            }

          if (temp == userptr)
            {
              numfound=1;       /* fixed minor boo boo -bill */
              for(temp = temp->collision; temp; temp = temp->collision)
                {
                  if (!match(temp->info->user,userptr->info->user))
                    numfound++; /* - zaph & Dianora :-) */
                }

              if ( numfound > nclones )
                {
                  if (!foundany)
                    {
                      print_to_socket(sock,
                           "Multiple clients from the following usernames:\n");
                      foundany = YES;
                    }

                  print_to_socket(sock,
                       " %s %2d connections -- %s@* {%s}\n",
                       (numfound-nclones > 2) ? "==>" : "   ",
                       numfound,userptr->info->user,
                       userptr->info->class);
                }
            }
        }
    }

  if(foundany == 0)
    {
      print_to_socket(sock, "No multiple logins found.\n");
    }
}

/*
 * report_multi_host()
 *
 * inputs       - socket to print out
 * output       - NONE
 * side effects -
 */
void report_multi_host(int sock,int nclones)
{
  struct hashrec *userptr,*top,*temp;
  int numfound,i;
  int foundany = NO;

  nclones-=1;
  for (i = 0; i < HASHTABLESIZE; ++i)
    {
      for (top = userptr = hosttable[i]; userptr; userptr = userptr->collision)
        {
          /* Ensure we haven't already checked this user & domain */

          for(temp = top, numfound = 0; temp != userptr;
              temp = temp->collision)
            {
              if (!strcmp(temp->info->host,userptr->info->host))
                break;
            }

          if (temp == userptr)
            {
              for (temp = userptr; temp; temp = temp->collision)
                {
                  if (!strcmp(temp->info->host,userptr->info->host))
                    numfound++; /* - zaph & Dianora :-) */
                }

              if ( numfound > nclones )
                {
                  if (!foundany)
                    {
                      foundany = YES;
                      print_to_socket(sock,
                           "Multiple clients from the following userhosts:\n");
                    }

                  print_to_socket(sock,
                       " %s %2d connections -- *@%s {%s}\n",
                       (numfound-nclones > 2) ? "==>" : "   ",
                       numfound,
                       userptr->info->host,
                       userptr->info->class);
                }
            }
        }
    }

  if (foundany == 0)
    print_to_socket(sock, "No multiple logins found.");
}

