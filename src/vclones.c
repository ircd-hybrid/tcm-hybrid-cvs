/* vclones.c
 *
 * contains code for monitoring virtual hosted clones
 * $Id: vclones.c,v 1.6 2002/05/30 22:40:58 db Exp $
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

#ifdef VIRTUAL

static void m_vmulti(int, int, char *argv[]);
static void m_vbots(int, int, char *argv[]);
static void m_vlist(int, int, char *argv[]);

static void report_multi_virtuals(int, int);
static void report_vbots(int, int);
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
    report_multi_virtuals(connections[connnum].socket, atoi(argv[1]));
  else
    report_multi_virtuals(connections[connnum].socket, 3);
}

void
m_vbots(int connnum, int argc, char *argv[])
{
  if (argc >= 2)
    report_vbots(connections[connnum].socket, atoi(argv[1]));
  else
    report_vbots(connections[connnum].socket, 3);
}

void
m_vlist(int connnum, int argc, char *argv[])
{
#ifdef HAVE_REGEX_H
  if ((argc < 2) || (argc > 2 && strcasecmp(argv[1], "-r")))
    print_to_socket(connections[connnum].socket,
                    "Usage: %s <wildcarded/regexp ip>",
                    argv[0]);
  else if (argc == 2)
    list_virtual_users(connections[connnum].socket, argv[1], NO);
  else
    list_virtual_users(connections[connnum].socket, argv[2], YES);
#else
  if (argc < 2)
    print_to_socket(connections[connnum].socket,
                    "Usage %s <wildcarded ip>", argv[0]);
  else
    list_virtual_users(connections[connnum].socket, argv[1], NO);
#endif
}

/*
 * report_multi_virtuals()
 *
 * inputs       - socket to print out
 *              - number to consider as clone
 * output       - NONE
 * side effects -
 */
void
report_multi_virtuals(int sock,int nclones)
{
  struct hash_rec *ptr;
  struct hash_rec *top;
  struct hash_rec *temp;
  int num_found;
  int i;
  int foundany = 0;

  if(!nclones)
    nclones = 5;

  nclones--;

  for (i=0; i<HASHTABLESIZE; ++i)
    {
      for (top = ptr = ip_table[i]; ptr; ptr = ptr->next)
        {
          num_found = 0;

          for (temp = top; temp != ptr; temp = temp->next)
            {
              if (!strcmp(temp->info->ip_class_c, ptr->info->ip_class_c))
                break;
            }

          if (temp == ptr)
            {
              num_found=1;
              for(temp = temp->next; temp; temp = temp->next)
                {
                  if (!strcmp(temp->info->ip_class_c, ptr->info->ip_class_c))
                    num_found++; /* - zaph & Dianora :-) */
                }

              if (num_found > nclones)
                {
                  if (!foundany)
                    {
                      print_to_socket(sock,
                           "Multiple clients from the following ip blocks:\n");
                      foundany = YES;
                    }

                  print_to_socket(sock,
                       " %s %2d connections -- %s.*\n",
                       (num_found-nclones > 3) ? "==>" : "   ",
                       num_found,
                       ptr->info->ip_class_c);
                }
            }
        }
    }

  if (!foundany)
    print_to_socket(sock, "No multiple virtual logins found.\n");
}


void
report_vbots(int sock, int nclones)
{
  struct hash_rec *ptr;
  struct hash_rec *top;
  struct hash_rec *temp;
  int num_found;
  int i;
  int foundany = NO;

  nclones-=2;  /* ::sigh:: I have no idea */
  for (i=0; i<HASHTABLESIZE; ++i)
    {
      for (top = ptr = ip_table[i]; ptr; ptr = ptr->next)
        {
          /* Ensure we haven't already checked this user & domain */
          for (temp = top, num_found = 0; temp != ptr; temp = temp->next)
            {
              if (!strcmp(temp->info->user, ptr->info->user) &&
                  !strcmp(temp->info->ip_class_c, ptr->info->ip_class_c))
                break;
            }

          if (temp == ptr)
            {
              for (temp = temp->next; temp; temp = temp->next)
                {
                  if (!strcmp(temp->info->user, ptr->info->user) &&
                      !strcmp(temp->info->ip_class_c, ptr->info->ip_class_c))
                    num_found++; /* - zaph & Dianora :-) */
                }

              if (num_found > nclones)
                {
                  if (!foundany)
                    {
                      foundany = YES;
                      print_to_socket(sock,
                           "Multiple clients from the following userhosts:\n");
                    }

                  num_found++;   /* - zaph and next line*/
                  print_to_socket(sock,
                       " %s %2d connections -- %s@%s.* {%s}\n",
				  (num_found-nclones > 2) ? "==>" :
				  "   ", num_found, ptr->info->user,
				  ptr->info->ip_class_c,
				  ptr->info->class);
                }
            }
        }
    }
  if (!foundany)
    print_to_socket(sock, "No multiple logins found.\n");
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
list_virtual_users(int sock,char *userhost,int regex)
{
  struct hash_rec *ipptr;
#ifdef HAVE_REGEX_H
  regex_t reg;
  regmatch_t m[1];
#endif
  char uhost[1024];
  int i;
  int num_found = 0;

#ifdef HAVE_REGEX_H
  if (regex == YES && (i = regcomp((regex_t *)&reg, userhost, 1)))
  {
    char errbuf[REGEX_SIZE];
    regerror(i, (regex_t *)&reg, errbuf, REGEX_SIZE);
    print_to_socket(sock, "Error compiling regular expression: %s\n",
                    errbuf);
    return;
  }
#endif
  if (!strcmp(userhost,"*") || !strcmp(userhost,"*@*"))
    {
      print_to_socket(sock,
"Listing all users is not recommended.  To do it anyway, use '.vlist ?*@*'.\n");
      return;
    }

  for (i=0; i < HASHTABLESIZE; ++i)
  {
    for (ipptr = ip_table[i]; ipptr; ipptr = ipptr->next)
    {
      snprintf(uhost, 1024, "%s@%s", ipptr->info->user, ipptr->info->ip_host);
#ifdef HAVE_REGEX_H
      if ((regex == YES &&
          !regexec((regex_t *)&reg, uhost, 1, m, REGEXEC_FLAGS))
          || (regex == NO && !match(userhost, uhost)))
#else
      if (!match(userhost, uhost))
#endif
      {
        if (!num_found++)
          print_to_socket(sock, "The following clients match %s:\n", userhost);

        print_to_socket(sock, "  %s (%s@%s) [%s] {%s}\n", ipptr->info->nick,
             ipptr->info->user, ipptr->info->host, ipptr->info->ip_host,
             ipptr->info->class);
      }
    }
  }
  if (num_found > 0)
    print_to_socket(sock, "%d match%sfor %s found\n", num_found,
         (num_found > 1 ? "es " : " "), userhost);
  else
    print_to_socket(sock, "No matches for %s found\n", userhost);
}

#endif
