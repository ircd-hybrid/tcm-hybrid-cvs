/* vclones.c
 *
 * contains code for monitoring virtual hosted clones
 * $Id: vclones.c,v 1.13 2002/06/23 21:09:16 db Exp $
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

#ifdef VIRTUAL

static void m_vmulti(int, int, char *argv[]);
static void m_vbots(int, int, char *argv[]);
static void m_vlist(int, int, char *argv[]);

static void report_vbots(int, int, int);
static void list_virtual_users(int, char *, int);

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
m_vmulti(int connnum, int argc, char *argv[])
{
  if (argc >= 2)
    report_vbots(connections[connnum].socket, atoi(argv[1]), NO);
  else
    report_vbots(connections[connnum].socket, 3, NO);
}

void
m_vbots(int connnum, int argc, char *argv[])
{
  if (argc >= 2)
    report_vbots(connections[connnum].socket, atoi(argv[1]), YES);
  else
    report_vbots(connections[connnum].socket, 3, YES);
}

void
m_vlist(int connnum, int argc, char *argv[])
{
#ifdef HAVE_REGEX_H
  if ((argc < 2) || (argc > 2 && strcasecmp(argv[1], "-r")))
    send_to_connection(connections[connnum].socket,
                    "Usage: %s <wildcarded/regexp ip>",
                    argv[0]);
  else if (argc == 2)
    report_vbots(connections[connnum].socket, atoi(argv[1]), YES);
  else
    list_virtual_users(connections[connnum].socket, argv[2], YES);
#else
  if (argc < 2)
    send_to_connection(connections[connnum].socket,
                    "Usage %s <wildcarded ip>", argv[0]);
  else
    list_virtual_users(connections[connnum].socket, argv[1], NO);
#endif
}

/*
 * report_vbots()
 *
 * inputs       - socket to print out
 *              - number to consider as clone
 *		- check_user YES means check user name as well as IP block
 * output       - NONE
 * side effects -
 */

static void
report_vbots(int sock, int nclones, int check_user)
{
  struct hash_rec *ptr;
  struct hash_rec *top;
  struct hash_rec *tptr;
  int num_found;
  int i;
  int foundany = 0;

  if(nclones == 0)
    nclones = 5;

  nclones--;

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
			num_found++; /* - zaph & Dianora :-) */
		    }
		  else
		    {
		      if (!strcmp(tptr->info->ip_class_c, ptr->info->ip_class_c))
			num_found++; /* - zaph & Dianora :-) */
		    }
                }

              if (num_found > nclones)
                {
                  if (!foundany)
                    {
		      if (check_user)
			{
			  send_to_connection(sock,
			  "Multiple clients from the following userhosts:");
			}
		      else
			{
			  send_to_connection(sock,
			  "Multiple clients from the following ip blocks:");
			}
                      foundany = YES;
                    }

		  if (check_user)
		    {
		      send_to_connection(sock,
				  " %s %2d connections -- %s@%s.* {%s}",
				      (num_found-nclones > 2) ? "==>" :
				      "   ", num_found, ptr->info->username,
				      ptr->info->ip_class_c,
				      ptr->info->class);
		    }
		    else
		    {
		      send_to_connection(sock,
				      " %s %2d connections -- %s.*",
				      (num_found-nclones > 3) ? "==>" : "   ",
				      num_found,
				      ptr->info->ip_class_c);
		    }

                }
            }
        }
    }

  if (!foundany)
    send_to_connection(sock, "No multiple virtual logins found.");
}

/*
 * list_virtual_users()
 *
 * inputs       - socket to reply on
 *              - ipblock to match on
 *              - regex or no?
 * output       - NONE
 * side effects -
 */

void
list_virtual_users(int sock, char *userhost, int regex)
{
  struct hash_rec *ipptr;
#ifdef HAVE_REGEX_H
  regex_t reg;
  regmatch_t m[1];
#endif
  char uhost[MAX_USERHOST];
  int i;
  int num_found = 0;

#ifdef HAVE_REGEX_H
  if (regex == YES && (i = regcomp((regex_t *)&reg, userhost, 1)))
  {
    char errbuf[REGEX_SIZE];
    regerror(i, (regex_t *)&reg, errbuf, REGEX_SIZE);
    send_to_connection(sock, "Error compiling regular expression: %s",
                    errbuf);
    return;
  }
#endif
  if (!strcmp(userhost,"*") || !strcmp(userhost,"*@*"))
    {
      send_to_connection(sock,
"Listing all users is not recommended.  To do it anyway, use '.vlist ?*@*'.");
      return;
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
        if (num_found == 0)
          send_to_connection(sock, "The following clients match %s:", userhost);

	num_found++;
        send_to_connection(sock, "  %s (%s@%s) [%s] {%s}", ipptr->info->nick,
             ipptr->info->username, ipptr->info->host, ipptr->info->ip_host,
             ipptr->info->class);
      }
    }
  }
  if (num_found > 0)
    send_to_connection(sock, "%d matches for %s found", num_found, userhost);
  else
    send_to_connection(sock, "No matches for %s found", userhost);
}

#endif
