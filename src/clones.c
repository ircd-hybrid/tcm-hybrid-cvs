/* clones.c
 *
 * contains the code for clone functions
 * $Id: clones.c,v 1.27 2003/03/30 00:27:27 bill Exp $
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
#include "client_list.h"

static void m_bots(struct connection *, int, char *argv[]);
static void m_umulti(struct connection *, int, char *argv[]);
static void m_hmulti(struct connection *, int, char *argv[]);
static void m_clones(struct connection *, int, char *argv[]);

static void check_clones(void *);
static void report_clones(struct connection *);
static void report_multi_user_host_domain(struct hash_rec *table[], 
					  struct connection *, int, char *);
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
m_bots(struct connection *connection_p, int argc, char *argv[])
{
  if (argc >= 2)
  {
    if (strcasecmp(argv[1], "-l") == 0)
      report_multi_user_host_domain(domain_table, connection_p,
                                    (argc >= 4) ? atoi(argv[3]) : 3, argv[2]);
    else
      report_multi_user_host_domain(domain_table, connection_p,
                                    atoi(argv[1]), NULL);
  }
  else
    report_multi_user_host_domain(domain_table, connection_p,
				  3, NULL);
}

void
m_umulti(struct connection *connection_p, int argc, char *argv[])
{
  if (argc >= 2)
  {
    if (strcasecmp(argv[1], "-l") == 0)
      report_multi_user_host_domain(user_table, connection_p,
                                    (argc >= 4) ? atoi(argv[3]) : 3, argv[2]);
    else
      report_multi_user_host_domain(user_table, connection_p,
                                    atoi(argv[1]), NULL);
  }
  else
    report_multi_user_host_domain(user_table, connection_p,
                                  3, NULL);
}

void
m_hmulti(struct connection *connection_p, int argc, char *argv[])
{
  if (argc >= 2)
  {
    if (strcasecmp(argv[1], "-l") == 0)
      report_multi_user_host_domain(host_table, connection_p,
                                    (argc >= 4) ? atoi(argv[3]) : 3, argv[2]);
    else
      report_multi_user_host_domain(host_table, connection_p,
                                    atoi(argv[1]), NULL);
  }
  else
    report_multi_user_host_domain(host_table, connection_p, 3, NULL);
}

void
m_clones(struct connection *connection_p, int argc, char *argv[])
{
  report_clones(connection_p);
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

  /*
   * if we are not operd, there is nothing we can do about these
   * clones anyway.  we do not even know for sure that they are
   * still connected.  so we do not continue if we are not operd.
   */
  if (tcm_status.am_opered == NO)
    return;

  for (i=0; i < HASHTABLESIZE; i++)
  {
    for (top = ptr = domain_table[i]; ptr; ptr = ptr->next)
    {
      /* Ensure we haven't already checked this user & domain */
      for(tptr = top, num_found = 0; tptr != ptr; tptr = tptr->next)
      {
        if (!strcmp(tptr->info->username, ptr->info->username) &&
            !strcmp(tptr->info->domain, ptr->info->domain))
          break;
      }

      if (tptr == ptr)
      {
        for(tptr = tptr->next; tptr; tptr = tptr->next)
        {
          if (!strcmp(tptr->info->username, ptr->info->username) &&
              !strcmp(tptr->info->domain, ptr->info->domain))
            num_found++; /* - zaph & Dianora :-) */
        }

        if (num_found > MIN_CLONE_NUMBER)
        {
          notip = strncmp(ptr->info->domain, ptr->info->host,
                          strlen(ptr->info->domain)) ||
            (strlen(ptr->info->domain) ==
             strlen(ptr->info->host));

          send_to_all(NULL, FLAGS_WARN,
		      "clones> %2d connections -- %s@%s%s {%s}",
		      num_found, ptr->info->username,
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
check_reconnect_clones(char *host, char *ip)
{
  int i;

  if (host == NULL)  /* I don't know how this could happen.  ::shrug:: */
    return;

  /* first, search the table for previous entries from this host */
  for (i=0; i<RECONNECT_CLONE_TABLE_SIZE ; ++i)
  {
    if (!strcasecmp(reconnect_clone[i].host, host))
    {
      ++reconnect_clone[i].count;

      if ((reconnect_clone[i].count > CLONERECONCOUNT) &&
          (current_time - reconnect_clone[i].first <= CLONERECONFREQ))
      {
        handle_action(act_rclone, "", "", host, (reconnect_clone[i].ip[0] ? reconnect_clone[i].ip : NULL), 0);
        reconnect_clone[i].host[0] = '\0';
        reconnect_clone[i].count = 0;
        reconnect_clone[i].first = 0;
      }
      return;
    }
  }

  /* new host? second, eliminate any expired entries */
  for (i=0; i < RECONNECT_CLONE_TABLE_SIZE; ++i)
  {
    if ((reconnect_clone[i].host[0]) &&
        (current_time - reconnect_clone[i].first > CLONERECONFREQ))
    {
      reconnect_clone[i].host[0] = 0;
      reconnect_clone[i].count = 0;
      reconnect_clone[i].first = 0;
    }
  }

  /* finally, find an empty record and add the host. */
  for (i=0 ; i < RECONNECT_CLONE_TABLE_SIZE ; ++i)
  {
    if (!reconnect_clone[i].host[0])
    {
      strlcpy(reconnect_clone[i].host, host,
              sizeof(reconnect_clone[i].host));
      if (ip != NULL)
        strlcpy(reconnect_clone[i].ip, ip,
                sizeof(reconnect_clone[i].ip));
      reconnect_clone[i].first = current_time;
      reconnect_clone[i].count = 1;
    }
    return;
  }

  /*
   * if we get here, it means we failed to add the host to the table.
   * the only way this can happen is if the last for() failed, which
   * means the table is full.  let an admin know.
   */
  send_to_all(NULL, FLAGS_ADMIN, "*** Error adding *@%s to reconnect clone table.  The table is full.", host);
}

/*
 * report_clones
 *
 * inputs       - pointer to connection struct
 * output       - NONE
 * side effects - NONE
 */
void
report_clones(struct connection *connection_p)
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
                  for (k = num_found-1; k > 1; --k)
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
                            send_to_connection(connection_p,
                                 "Possible clonebots from the following hosts:");
                          foundany = YES;
                        }
                        send_to_connection(connection_p,
                             "  %2d connections in %3d seconds (%2d total) from %s",
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
        send_to_connection(connection_p, "No potential clonebots found.");
    }
}


/*
 * report_multi_user_host_domain()
 *
 * inputs       - table either user_table or host_table or domain_table
 *		- pointer to connection
 *		- threshold
 *		- list name
 * output       - NONE
 * side effects -
 */
void
report_multi_user_host_domain(struct hash_rec *table[], 
			      struct connection *connection_p, int nclones, char *list_name)
{
  struct hash_rec *ptr;
  struct hash_rec *top;
  struct hash_rec *tptr;
  int num_found;
  int i, idx=-1;
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

  if (!BadPtr(list_name))
  {
    if ((idx = find_list(list_name)) == -1 &&
        create_list(connection_p, list_name) == NULL)
    {
      send_to_connection(connection_p, "Error creating list!");
      return;
    }

    idx = find_list(list_name);
  }

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
		  if (!match(tptr->info->username, ptr->info->username))
		    break;
		}
	      else if(check_type == HOST_CHECK)
		{
		  if (!match(tptr->info->host, ptr->info->host))
		    break;
		}
	      else if(check_type == DOMAIN_CHECK)
		{
		  if (!strcmp(tptr->info->username, ptr->info->username) &&
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
		      if (!match(tptr->info->username, ptr->info->username))
                      {
			num_found++; /* - zaph & Dianora :-) */
                        if (idx >= 0)
                        {
                          if (!add_client_to_list(tptr->info, idx))
                          {
                            send_to_connection(connection_p,
                                               "Failed to add %s (%s@%s) [%s] {%s} to the list",
                                               tptr->info->nick, tptr->info->username, tptr->info->host,
                                               tptr->info->ip_host, tptr->info->class);
                            continue;
                          }
                        }
                      }
		    }
		  else if(check_type == HOST_CHECK)
		    {
		      if (!strcmp(tptr->info->host, ptr->info->host))
                      {
			num_found++; /* - zaph & Dianora :-) */
                        if (idx >= 0)
                        {
                          if (!add_client_to_list(tptr->info, idx))
                          {
                            send_to_connection(connection_p,
                                               "Failed to add %s (%s@%s) [%s] {%s} to the list",
                                               tptr->info->nick, tptr->info->username, tptr->info->host,
                                               tptr->info->ip_host, tptr->info->class);
                            continue;
                          }
                        }
                      }
		    }
		  else if(check_type == DOMAIN_CHECK)
		    {
		      if (!strcmp(tptr->info->username, ptr->info->username) &&
			  !strcmp(tptr->info->domain, ptr->info->domain))
                      {
			num_found++; /* - zaph & Dianora :-) */
                        if (idx >= 0)
                        {
                          if (!add_client_to_list(tptr->info, idx))
                          {
                            send_to_connection(connection_p,
                                               "Failed to add %s (%s@%s) [%s] {%s} to the list",
                                               tptr->info->nick, tptr->info->username, tptr->info->host,
                                               tptr->info->ip_host, tptr->info->class);
                            continue;
                          }
                        }
                      }
		    }
		}
	    }

	  if (num_found > nclones)
	    {
              if (idx >= 0)
              {
                if (!add_client_to_list(ptr->info, idx))
                {
                  send_to_connection(connection_p,
                                     "Failed to add %s (%s@%s) [%s] {%s} to the list",
                                     ptr->info->nick, ptr->info->username, ptr->info->host,
                                     ptr->info->ip_host, ptr->info->class);
                }
                foundany = YES;
                continue;
              }

	      if (!foundany)
		{
		  if (check_type == USER_CHECK)
		    {
		      send_to_connection(connection_p,
			 "Multiple clients from the following usernames:");
		    }
		  else if(check_type == HOST_CHECK)
		    {
		      send_to_connection(connection_p,
                      "Multiple clients from the following userhosts:");
		    }
		  else if(check_type == DOMAIN_CHECK)
		    {
		      send_to_connection(connection_p,
		      "Multiple clients from the following userhosts:");
		    }
		  foundany = YES;
		}

	      if (check_type == USER_CHECK)
		{
		  send_to_connection(connection_p,
				     " %s %2d connections -- %s@* {%s}",
				     (num_found-nclones > 2) ? "==>" : "   ",
				     num_found, ptr->info->username,
				     ptr->info->class);
		}
	      else if(check_type == HOST_CHECK)
		{
		  send_to_connection(connection_p,
				     " %s %2d connections -- *@%s {%s}",
				     (num_found-nclones > 2) ? "==>" : "   ",
				     num_found,
				     ptr->info->host,
				     ptr->info->class);
		}
	      else if (check_type == DOMAIN_CHECK)
		{
		  is_ip = is_an_ip((const char *)ptr->info->domain);
		  send_to_connection(connection_p,
				     " %s %2d connections -- %s@%s%s {%s}",
				     (num_found-nclones > 2) ? "==>" :
				     "   ",num_found,ptr->info->username,
				     is_ip ? ptr->info->domain : "*.",
				     is_ip ? ".*" :ptr->info->domain,
				     ptr->info->class);
		}
	    }
        }
    }

  if(foundany == 0)
    {
      send_to_connection(connection_p, "No multiple logins found.");
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
