/* vclones.c
 *
 * contains code for monitoring virtual hosted clones
 * $Id: vclones.c,v 1.19 2004/04/22 08:32:16 bill Exp $
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
#include "match.h"
#include "client_list.h"

#ifdef HAVE_REGEX_H
#include <regex.h>
#endif

#ifdef VIRTUAL

static void m_vmulti(struct connection *, int, char *argv[]);
static void m_vbots(struct connection *, int, char *argv[]);
static void m_vlist(struct connection *, int, char *argv[]);

static void report_vbots(struct connection *, int, int, char *);
static void list_virtual_users(struct connection *, char *, int, char *);

struct dcc_command vmulti_msgtab = {
  "vmulti", NULL, {m_unregistered, m_vmulti, m_vmulti}
};
struct dcc_command vbots_msgtab = {
  "vbots", NULL, {m_unregistered, m_vbots, m_vbots}
};
struct dcc_command vlist_msgtab = {
  "vlist", NULL, {m_unregistered, m_vlist, m_vlist}
};

void
init_vclones(void)
{
  add_dcc_handler(&vmulti_msgtab);
  add_dcc_handler(&vbots_msgtab);
  add_dcc_handler(&vlist_msgtab);
}

void
m_vmulti(struct connection *connection_p, int argc, char *argv[])
{
  if (argc >= 2)
  {
    if (strcasecmp(argv[1], "-l") == 0)
      report_vbots(connection_p, (argc >= 4) ? atoi(argv[3]) : 3, NO, argv[2]);
    else
      report_vbots(connection_p, atoi(argv[1]), NO, NULL);
  }
  else
    report_vbots(connection_p, 3, NO, NULL);
}

void
m_vbots(struct connection *connection_p, int argc, char *argv[])
{
  if (argc >= 2)
  {
    if (strcasecmp(argv[1], "-l") == 0)
      report_vbots(connection_p, (argc >= 4) ? atoi(argv[3]) : 3, YES, argv[2]);
    else
      report_vbots(connection_p, atoi(argv[1]), YES, NULL);
  }
  else
    report_vbots(connection_p, 3, YES, NULL);
}

void
m_vlist(struct connection *connection_p, int argc, char *argv[])
{
#ifdef HAVE_REGEX_H
  if(!(argc >= 2) || !(argc <= 5) ||
     /* .vlist -l list -r [0-9]  */
     (strcasecmp(argv[1], "-l") == 0 && argc >= 4 && strcasecmp(argv[3], "-r") == 0 && argc < 5) ||
     /* .vlist -l list ?*@*      */
     (strcasecmp(argv[1], "-l") == 0 && argc >= 4 && strcasecmp(argv[3], "-r") != 0 && argc < 4) ||
     /* .vlist -r [0-9]          */
     (strcasecmp(argv[1], "-l") != 0 && argc >= 2 && strcasecmp(argv[1], "-r") == 0 && argc < 3) ||
     /* .vlist ?*@*              */
     (strcasecmp(argv[1], "-l") != 0 && argc >= 2 && strcasecmp(argv[1], "-r") != 0 && argc < 2) )
  {
    send_to_connection(connection_p,
		       "Usage: %s [-l list] <[wildcard ip]|[-r regexp]>",
		       argv[0]);
    return;
  }

  if (strcasecmp(argv[1], "-l") == 0)
  {
    if (strcasecmp(argv[3], "-r") == 0)
      list_virtual_users(connection_p, argv[4], YES, argv[2]);
    else
      list_virtual_users(connection_p, argv[3], NO, argv[2]);
  }
  else if (argc == 2)
    list_virtual_users(connection_p, argv[1], NO, NULL);
  else
    list_virtual_users(connection_p, argv[2], YES, NULL);
#else
  if(!(argc >= 2) || !(argc <= 4) ||
     /* .vlist -l list ?*@*      */
     (strcasecmp(argv[1], "-l") == 0 && argc < 4) ||
     /* .vlist ?*@*              */
     (strcasecmp(argv[1], "-l") != 0 && argc < 2) )
  {
    send_to_connection(connection_p,
		       "Usage %s [-l list] <wildcard ip>", argv[0]);
    return;
  }

  if (strcasecmp(argv[1], "-l") == 0)
    list_virtual_users(connection_p, argv[3], NO, argv[2]);
  else
    list_virtual_users(connection_p, argv[1], NO, NULL);
#endif /* HAVE_REGEX_H */

}

/*
 * report_vbots()
 *
 * inputs       - pointer to struct connection
 *              - number to consider as clone
 *		- check_user YES means check user name as well as IP block
 *              - desired list name
 * output       - NONE
 * side effects -
 */

static void
report_vbots(struct connection *connection_p, int nclones, int check_user, char *list_name)
{
  struct hash_rec *ptr;
  struct hash_rec *top;
  struct hash_rec *tptr;
  int num_found;
  int i, idx=-1;
  int foundany = 0;

  if(nclones == 0)
    nclones = 5;

  nclones--;

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

  for (i=0; i<HASHTABLESIZE; ++i)
    {
      for (top = ptr = ip_table[i]; ptr; ptr = ptr->next)
        {
          num_found = 0;

          for (tptr = top; tptr != ptr; tptr = tptr->next)
            {
              if (check_user)
		{
		  if (!strcmp(tptr->info->username, ptr->info->username) &&
		      !strcmp(tptr->info->ip_class_c, ptr->info->ip_class_c))
		    break;
		}
	      else
		{
		  if (!strcmp(tptr->info->ip_class_c, ptr->info->ip_class_c))
		  break;
		}
            }

          if (tptr == ptr)
            {
              num_found=1;
              for(tptr = tptr->next; tptr; tptr = tptr->next)
                {
		  if (check_user)
		    {
		      if (!strcmp(tptr->info->username, ptr->info->username) &&
			  !strcmp(tptr->info->ip_class_c, ptr->info->ip_class_c))
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
                          }
                        }
                      }
		    }
		  else
		    {
		      if (!strcmp(tptr->info->ip_class_c, ptr->info->ip_class_c))
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
		      if (check_user)
			{
			  send_to_connection(connection_p,
			  "Multiple clients from the following userhosts:");
			}
		      else
			{
			  send_to_connection(connection_p,
			  "Multiple clients from the following ip blocks:");
			}
                      foundany = YES;
                    }

		  if (check_user)
		    {
		      send_to_connection(connection_p,
				  " %s %2d connections -- %s@%s%s {%s}",
				      (num_found-nclones > 2) ? "==>" :
				      "   ", num_found, ptr->info->username,
				      ptr->info->ip_class_c,
				      strchr(ptr->info->ip_class_c, ':') ? "/64" : ".*",
				      ptr->info->class);
		    }
		    else
		    {
		      send_to_connection(connection_p,
					 " %s %2d connections -- %s%s",
					 (num_found-nclones > 3) ? "==>" : "   ",
					 num_found,
					 ptr->info->ip_class_c,
				         strchr(ptr->info->ip_class_c, ':') ? "/64" : ".*");
		    }

                }
            }
        }
    }

  if (!foundany)
    send_to_connection(connection_p, "No multiple virtual logins found.");
}

/*
 * list_virtual_users()
 *
 * inputs       - pointer to struct connection
 *              - ipblock to match on
 *              - regex or no?
 * output       - NONE
 * side effects -
 */

void
list_virtual_users(struct connection *connection_p, char *userhost, int regex, char *list_name)
{
  struct hash_rec *ipptr;
  char uhost[MAX_USERHOST];
  char format[100];
  int i, idx=-1, num_found=0;
#ifdef HAVE_REGEX_H
  regex_t reg;
  regmatch_t m[1];

  if (regex == YES && (i = regcomp((regex_t *)&reg, userhost, 1)))
  {
    char errbuf[REGEX_SIZE];
    regerror(i, (regex_t *)&reg, errbuf, REGEX_SIZE);
    send_to_connection(connection_p, "Error compiling regular expression: %s",
		       errbuf);
    return;
  }
#endif

  if (!strcmp(userhost,"*") || !strcmp(userhost,"*@*"))
    {
      send_to_connection(connection_p,
                         "Listing all users is not recommended.  To do it anyway, use '.vlist ?*@*'.");
      return;
    }

  if (!BadPtr(list_name))
  {
    if ((idx = find_list(list_name)) == -1 &&
        create_list(connection_p, list_name) == NULL)
    {
      send_to_connection(connection_p,
                         "Error creating list!");
      return;
    }

    idx = find_list(list_name);
  }

  for (i=0; i < HASHTABLESIZE; ++i)
  {
    for (ipptr = ip_table[i]; ipptr; ipptr = ipptr->next)
    {
      snprintf(uhost, MAX_USERHOST,
	       "%s@%s", ipptr->info->username, ipptr->info->ip_host);
#ifdef HAVE_REGEX_H
      if ((regex == YES &&
          !regexec((regex_t *)&reg, uhost, 1, m, REGEXEC_FLAGS))
          || (regex == NO && !match(userhost, uhost)))
#else
      if (!match(userhost, uhost))
#endif
      {
        if (num_found++ == 0)
        {
          if (idx == -1)
            send_to_connection(connection_p,
		  	       "The following clients match %s:", userhost);
          else
            send_to_connection(connection_p,
                               "Adding matches to list %s", list_name);
        }

        if (idx == -1)
        {
#ifndef AGGRESSIVE_GECOS
          if (ipptr->info->gecos[0] == '\0')
            snprintf(format, sizeof(format), "  %%%ds (%%s@%%s) [%%s] {%%s}",
                     MAX_NICK);
          else
#endif
            snprintf(format, sizeof(format), "  %%%ds (%%s@%%s) [%%s] {%%s} [%%s]",
                     MAX_NICK);

          send_to_connection(connection_p, format,
                             ipptr->info->nick, ipptr->info->username, ipptr->info->host,
                             ipptr->info->ip_host, ipptr->info->class, ipptr->info->gecos);
        }
        else
        {
          if (!add_client_to_list(ipptr->info, idx))
          {
            send_to_connection(connection_p,
                               "Failed to add %s (%s@%s) [%s] {%s} to the list",
                               ipptr->info->nick, ipptr->info->username, ipptr->info->host,
                               ipptr->info->ip_host, ipptr->info->class);
            continue;
          }
        }
      }
    }
  }

  if (num_found > 0)
    send_to_connection(connection_p,
		       "%d match%s for %s found", num_found, (num_found == 1) ? "" : "es", userhost);
  else
    send_to_connection(connection_p, "No matches for %s found", userhost);
}

#endif

