/* clones.c
 *
 * contains the code for clone functions
 * $Id: clones.c,v 1.14 2002/06/02 23:13:18 db Exp $
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
#include "bothunt.h"
#include "modules.h"
#include "stdcmds.h"
#include "wild.h"
#include "parse.h"
#include "hash.h"
#include "handler.h"
#include "userlist.h"
#include "actions.h"
#include "event.h"
#include "match.h"

static void m_bots(int, int, char *argv[]);
static void m_umulti(int, int, char *argv[]);
static void m_hmulti(int, int, char *argv[]);
static void m_clones(int, int, char *argv[]);

static void check_clones(void *);
static void report_clones(int);
static void report_multi_user_host_domain(struct hash_rec *table[], int, int);
static int is_an_ip(const char *host);

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

#define USER_CHECK	0
#define HOST_CHECK	1
#define DOMAIN_CHECK	2

void
m_bots(int connnum, int argc, char *argv[])
{
  if (argc >= 2)
    report_multi_user_host_domain(domain_table, connections[connnum].socket,
				  atoi(argv[1]));
  else
    report_multi_user_host_domain(domain_table, connections[connnum].socket,
				  3);
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

  report_multi_user_host_domain(user_table, connections[connnum].socket, t);
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

  report_multi_user_host_domain(host_table, connections[connnum].socket, t);
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
  struct hash_rec *ptr;
  struct hash_rec *top;
  struct hash_rec *tptr;
  int num_found;
  int i;
  int notip=0;

  for (i=0; i < HASHTABLESIZE; i++)
  {
    for (top = ptr = domain_table[i]; ptr; ptr = ptr->next)
    {
      /* Ensure we haven't already checked this user & domain */
      for(tptr = top, num_found = 0; tptr != ptr; tptr = tptr->next)
      {
        if (!strcmp(tptr->info->user, ptr->info->user) &&
            !strcmp(tptr->info->domain, ptr->info->domain))
          break;
      }

      if (tptr == ptr)
      {
        for(tptr = tptr->next; tptr; tptr = tptr->next)
        {
          if (!strcmp(tptr->info->user, ptr->info->user) &&
              !strcmp(tptr->info->domain, ptr->info->domain))
            num_found++; /* - zaph & Dianora :-) */
        }

        if (num_found > MIN_CLONE_NUMBER)
        {
          notip = strncmp(ptr->info->domain, ptr->info->host,
                          strlen(ptr->info->domain)) ||
            (strlen(ptr->info->domain) ==
             strlen(ptr->info->host));

          send_to_all(FLAGS_WARN,
                       "clones> %2d connections -- %s@%s%s {%s}",
                       num_found, ptr->info->user,
                       notip ? "*" : ptr->info->domain,
                       notip ? ptr->info->domain : "*",
                       ptr->info->class);
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
        reconnect_clone[i].host[0] = '\0';
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
      strlcpy(reconnect_clone[i].host, host, MAX_HOST);
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
  struct hash_rec *ptr;
  struct hash_rec *top;
  struct hash_rec *tptr;
  int  num_found;
  int i;
  int j=0;
  int k;
  int foundany = NO;
  time_t connfromhost[MAXFROMHOST];

  if(sock < 0)
    return;

  for (i = 0; i < HASHTABLESIZE; ++i)
    {
      for(top = ptr = host_table[i]; ptr; ptr = ptr->next)
        {
          /* Ensure we haven't already checked this host */
	  for(tptr = top, num_found = 0; tptr != ptr; tptr = tptr->next)
            {
              if (!strcmp(tptr->info->host, ptr->info->host))
                break;
            }

          if (tptr == ptr)
            {
              connfromhost[num_found++] = tptr->info->connecttime;
              for(tptr = tptr->next; tptr; tptr = tptr->next)
                {
                  if (!strcmp(tptr->info->host, ptr->info->host) &&
                      num_found < MAXFROMHOST)
                    connfromhost[num_found++] = tptr->info->connecttime;
                }
              if (num_found > 2)
                {
                  for (k=num_found-1; k>1; --k)
                    {
                      for (j=0; j<num_found-k; ++j)
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
                             num_found+1,
                             ptr->info->host);
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
 * report_multi_user_host_domain()
 *
 * inputs       - table either user_table or host_table or domain_table
 *		- socket to print out
 * output       - NONE
 * side effects -
 */
void
report_multi_user_host_domain(struct hash_rec *table[], int sock, int nclones)
{
  struct hash_rec *ptr;
  struct hash_rec *top;
  struct hash_rec *tptr;
  int num_found;
  int i;
  int foundany = NO;
  int check_type;
  int is_ip = 0;

  nclones--;

  if (table == user_table)
    check_type = USER_CHECK;
  else if(table == host_table)
    check_type = HOST_CHECK;
  else
    check_type = DOMAIN_CHECK;

  for (i=0; i < HASHTABLESIZE; ++i)
    {
      for (top = ptr = table[i]; ptr; ptr = ptr->next)
        {
          num_found = 0;
          /* Ensure we haven't already checked this user & domain */

	  for(tptr = top; tptr != ptr; tptr = tptr->next)
            {
	      if (check_type == USER_CHECK)
		{
		  if (!match(tptr->info->user, ptr->info->user))
		    break;
		}
	      else if(check_type == HOST_CHECK)
		{
		  if (!match(tptr->info->host, ptr->info->host))
		    break;
		}
	      else if(check_type == DOMAIN_CHECK)
		{
		  if (!strcmp(tptr->info->user, ptr->info->user) &&
		      !strcmp(tptr->info->domain, ptr->info->domain))
		    break;
		}
            }

	  if (tptr == ptr)
            {
              num_found=1;       /* fixed minor boo boo -bill */
              for(tptr = tptr->next; tptr; tptr = tptr->next)
                {
		  if (check_type == USER_CHECK)
		    {
		      if (!match(tptr->info->user, ptr->info->user))
			num_found++; /* - zaph & Dianora :-) */
		    }
		  else if(check_type == HOST_CHECK)
		    {
		      if (!strcmp(tptr->info->host, ptr->info->host))
			num_found++; /* - zaph & Dianora :-) */
		    }
		  else if(check_type == DOMAIN_CHECK)
		    {
		      if (!strcmp(tptr->info->user, ptr->info->user) &&
			  !strcmp(tptr->info->domain, ptr->info->domain))
			num_found++; /* - zaph & Dianora :-) */
		    }
		}
	    }

	  if (num_found > nclones)
	    {
	      if (!foundany)
		{
		  if (check_type == USER_CHECK)
		    {
		      print_to_socket(sock,
		      "Multiple clients from the following usernames:\n");
		    }
		  else if(check_type == HOST_CHECK)
		    {
		      print_to_socket(sock,
                      "Multiple clients from the following userhosts:\n");
		    }
		  else if(check_type == DOMAIN_CHECK)
		    {
		      print_to_socket(sock,
		      "Multiple clients from the following userhosts:\n");
		    }
		  foundany = YES;
		}

	      if (check_type == USER_CHECK)
		{
		  print_to_socket(sock,
				  " %s %2d connections -- %s@* {%s}\n",
				  (num_found-nclones > 2) ? "==>" : "   ",
				  num_found, ptr->info->user, ptr->info->class);
		}
	      else if(check_type == HOST_CHECK)
		{
		  print_to_socket(sock,
				  " %s %2d connections -- *@%s {%s}\n",
				  (num_found-nclones > 2) ? "==>" : "   ",
				  num_found,
				  ptr->info->host,
				  ptr->info->class);
		}
	      else if (check_type == DOMAIN_CHECK)
		{
		  is_ip = is_an_ip((const char *)ptr->info->domain);
		  print_to_socket(sock,
				  " %s %2d connections -- %s@%s%s {%s}\n",
				  (num_found-nclones > 2) ? "==>" :
				  "   ",num_found,ptr->info->user,
				  is_ip ? ptr->info->domain : "*.",
				  is_ip ? ".*" :ptr->info->domain,
				  ptr->info->class);
		}
	    }
        }
    }

  if(foundany == 0)
    {
      print_to_socket(sock, "No multiple logins found.\n");
    }
}

/* XXX */
/* initial version */
static int
is_an_ip(const char *host)
{
  if (strpbrk(host, "GgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz") != NULL)
    return(NO);
  return(YES);
}
