/* hash.c
 *
 * $Id: hash.c,v 1.65 2003/03/29 10:06:05 bill Exp $
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <assert.h>

#include "setup.h"
#include "config.h"
#include "tcm.h"
#include "tcm_io.h"
#include "stdcmds.h"
#include "parse.h"
#include "bothunt.h"
#include "userlist.h"
#include "logging.h"
#include "wild.h"
#include "serno.h"
#include "patchlevel.h"
#include "hash.h"
#include "actions.h"
#include "match.h"
#include "wingate.h"
#include "client_list.h"

#ifdef IPV6
#include "ipv6.h"
#endif

#ifdef HAVE_REGEX_H
#include <regex.h>
#endif

#ifndef INADDR_NONE
#define INADDR_NONE ((unsigned int) 0xffffffff)
#endif

static int hash_func(const char *string);
static char* find_domain(char* domain);
static void check_host_clones(char *);
#ifdef VIRTUAL
static void make_ip_class_c(char *p);
#ifdef VIRTUAL_IPV6
static void make_ip_slash_64(char *p);
#endif
static void check_virtual_host_clones(char *);
#endif

struct hash_rec *user_table[HASHTABLESIZE];
struct hash_rec *host_table[HASHTABLESIZE];
struct hash_rec *domain_table[HASHTABLESIZE];
struct hash_rec *ip_table[HASHTABLESIZE];

/*
 * free_hash_links
 *
 * inputs       - pointer to link list to free
 * output       - none
 * side effects -
 */
static void 
free_hash_links(struct hash_rec *ptr)
{
  struct hash_rec *next_ptr = NULL;  /* Quell warnings */

  if(ptr == NULL)
    return;

  for(; next_ptr != NULL; ptr = next_ptr);
    {
      next_ptr = ptr->next;

      if(ptr->info->link_count > 0)
        ptr->info->link_count--;

      if(ptr->info->link_count == 0)
          (void)free(ptr->info);

      (void)free(ptr);
    }
}

/*
 * clear_hash()
 *
 * inputs               - NONE
 * output               - NONE
 * side effects         - clear all allocated memory hash tables
 *
 */
void 
clear_hash(void)
{
  struct hash_rec *ptr;
  int i;

  for (i=0; i<HASHTABLESIZE; i++)
    {
      if((ptr = user_table[i]) != NULL)
	{
	  free_hash_links(ptr);
	  user_table[i] = NULL;
	}

      if((ptr = host_table[i]) != NULL)
	{
	  free_hash_links(ptr);
	  host_table[i] = NULL;
	}

      if((ptr = domain_table[i]) != NULL)
	{
	  free_hash_links(ptr);
	  domain_table[i] = NULL;
	}

#ifdef VIRTUAL
      if((ptr = ip_table[i]) != NULL)
	{
	  free_hash_links(ptr);
	  ip_table[i] = NULL;
	}
#endif
    }

  tcm_status.doing_trace = YES;
  send_to_server("TRACE");
}

/*
 * find_nick_or_host
 *
 * Returns an user_entry for the given nick, host, or NULL if not found
 *
 */

struct user_entry *
find_nick_or_host(const char *find, int find_nick)
{
  int i;
  struct hash_rec *ptr;

  if(find == NULL)
    return (NULL);

  for (i=0; i<HASHTABLESIZE; ++i)
    {
      for (ptr = domain_table[i]; ptr; ptr = ptr->next)
	{
	  if(find_nick)
	    {
	      if(!wldcmp((char *)find, ptr->info->nick))
		return (ptr->info);
	    }
	  else
	    {
	      if(!wldcmp((char *)find, ptr->info->host))
		return (ptr->info);
	    }
	}
    }
  return (NULL);
}

/*
 * add_to_hash_table()
 *
 * inputs	- pointer to hash table
 *		- pointer to key being used for hash
 *		- pointer to user_entry to add
 * output	- none
 * side	effects	- 
 */

void
add_to_hash_table(struct hash_rec *table[],
		       const char *key, struct user_entry *new_user)
{
  int ind;
  struct hash_rec *new_hash;

  assert(new_user != NULL);

  new_hash = (struct hash_rec *)xmalloc(sizeof(struct hash_rec));
  memset(new_hash, 0, sizeof(new_hash));

  new_hash->info = new_user;
  new_hash->next = NULL;

  ind = hash_func(key);
  if(table[ind] == NULL)
    {
      table[ind] = new_hash;
    }
  else
    {
      new_hash->next = table[ind];
      table[ind] = new_hash;
    }
  new_user->link_count++;
}


/*
 * remove_from_hash_table()
 *
 * inputs	- pointer to hash table
 *		- pointer to key being used for hash
 *		- pointer to hostname to match
 *		- pointer to username to match
 *		- pointer to nickname to match
 * output	- 1 if found and removed, 0 if not found
 * side effects	- removes entry from hash_table if found
 */

int
remove_from_hash_table(struct hash_rec *table[],
		       const char *key, const char *host_match,
		       const char *user_match, const char *nick_match)
{
  struct hash_rec *find;
  struct hash_rec *prev=NULL;
  int hash_val;

  hash_val = hash_func(key);

  for (find = table[hash_val]; find; find = find->next)
  {
    if((!host_match	|| !strcmp(find->info->host, host_match)) &&
       (!user_match	|| !strcmp(find->info->username, user_match)) &&
       (!nick_match	|| !strcmp(find->info->nick, nick_match)))
    {
      if(prev != NULL)
	prev->next = find->next;
      else
	table[hash_val] = find->next;

      if(find->info->link_count > 0)
	{
	  find->info->link_count--;
	  if(find->info->link_count == 0)
	    {
	      xfree(find->info);
	    }
	}
      free(find);
      return (1);	/* Found the item, and deleted. */
    }
    prev = find;
  }
  return (0);
}

/*
 * add_user_host()
 * 
 * inputs	- pointer to struct user_entry
 * 		- from a trace YES or NO
 * 		- is this user an oper YES or NO
 * output	- NONE
 * side effects	-
 * 
 */

void
add_user_host(struct user_entry *user_info, int fromtrace)
{
  struct user_entry *new_user;
  char *domain;

#if defined(DETECT_WINGATE) || defined(DETECT_SOCKS) || defined(DETECT_SQUID)
  if(tcm_status.doing_trace == NO)
    user_signon(user_info);
#endif

  new_user = (struct user_entry *)xmalloc(sizeof(struct user_entry));
  memset(new_user, 0, sizeof(struct user_entry));

  strlcpy(new_user->nick, user_info->nick,
          sizeof(new_user->nick));
  strlcpy(new_user->username, user_info->username,
          sizeof(new_user->username));
  strlcpy(new_user->host, user_info->host,
          sizeof(new_user->host));
  strlcpy(new_user->class, user_info->class,
          sizeof(new_user->class));

#ifdef VIRTUAL
  if(user_info->ip_host[0] != '\0')
    strlcpy(new_user->ip_host, user_info->ip_host,
            sizeof(new_user->ip_host));
  else
    strlcpy(new_user->ip_host, "0.0.0.0",
            sizeof(new_user->ip_host));
  strlcpy(new_user->ip_class_c, new_user->ip_host,
          sizeof(new_user->ip_class_c));
#ifdef VIRTUAL_IPV6
  if (strchr(new_user->ip_host, ':'))
    make_ip_slash_64(new_user->ip_class_c);
  else
#endif
    make_ip_class_c(new_user->ip_class_c);
#endif

  new_user->connecttime = (fromtrace ? 0 : time(NULL));
  new_user->reporttime = 0;
  new_user->link_count = 0;

  /* Currently, hybrid-7 does not put gecos as part of the TRACE reply.
   * Until there is a better solution, we limit gecos matchable clients
   * to those that connect after the tcm has succesfully oper'd on its
   * server.
   */
  if (fromtrace == NO)
    strlcpy(new_user->gecos, user_info->gecos,
            sizeof(new_user->gecos));

  /* Determine the domain name */
  domain = find_domain(user_info->host);

  strlcpy(new_user->domain, domain,
          sizeof(new_user->domain));

  /* Add it to the hash tables */
  add_to_hash_table(user_table, new_user->username, new_user);
  add_to_hash_table(host_table, new_user->host, new_user);
  add_to_hash_table(domain_table, new_user->domain, new_user);

#ifdef VIRTUAL
  if(new_user->ip_class_c[0])
    add_to_hash_table(ip_table, new_user->ip_class_c, new_user);
#endif

  /* Clonebot check */
  if(!fromtrace)
    {
      check_host_clones(user_info->host);
#ifdef VIRTUAL
      check_virtual_host_clones(new_user->ip_class_c);
#endif
      check_reconnect_clones(user_info->host, new_user->ip_host);
    }
}

/*
 * remove_user_host()
 * 
 * input	- pointer to struct user_entry
 * output	- NONE
 * side effects	- 
 */

void
remove_user_host(struct user_entry *user_info)
{
  int idx=0;
#ifdef VIRTUAL
  char ip_class_c[MAX_IP];
#endif
  char *domain;

  domain = find_domain(user_info->host);

  if(!remove_from_hash_table(host_table, user_info->host,
			      user_info->host, user_info->username, 
			      user_info->nick)) 
    {
      if(!remove_from_hash_table(host_table, user_info->host,
				  user_info->host, user_info->username, NULL))
	{
          send_to_all(NULL, FLAGS_ALL, "*** Error removing %s!%s@%s from host table!",
                      user_info->nick, user_info->username, user_info->host);

	  if(config_entries.debug && outfile)
	    {
	      fprintf(outfile,"*** Error removing %s!%s@%s from host table!\n",
		      user_info->nick, user_info->username, user_info->host);
	    }
	}
    }
  if(!remove_from_hash_table(domain_table, domain,
			      user_info->host, user_info->username, 
			      user_info->nick))
    {
      if(!remove_from_hash_table(domain_table, domain,
				  user_info->host, user_info->username, NULL))
	{
          send_to_all(NULL, FLAGS_ALL, "*** Error removing %s!%s@%s from domain table!",
                      user_info->nick, user_info->username, user_info->host);

	  if(config_entries.debug && outfile)
	    {
	      fprintf(outfile,"*** Error removing %s!%s@%s from domain table!\n",
		      user_info->nick, user_info->username, user_info->host);
	    }
	}
    }
  if(!remove_from_hash_table(user_table, user_info->username,
			      user_info->host, user_info->username,
			      user_info->nick))
    {
      if(!remove_from_hash_table(user_table, user_info->username,
				  user_info->host, user_info->username, NULL))
	{
          send_to_all(NULL, FLAGS_ALL, "*** Error removing %s!%s@%s from user table!",
                      user_info->nick, user_info->username, user_info->host);

	  if(config_entries.debug && outfile)
	    {
	      fprintf(outfile,"*** Error removing %s!%s@%s from user table!\n",
		      user_info->nick, user_info->username, user_info->host);
	    }
	}
    }

#ifdef VIRTUAL
  if(user_info->ip_host[0])
    strlcpy(ip_class_c, user_info->ip_host,
            sizeof(ip_class_c));
  else
    strlcpy(ip_class_c, "0.0.0.0",
            sizeof(ip_class_c));
  make_ip_class_c(ip_class_c);
  if(!remove_from_hash_table(ip_table, ip_class_c,
			      user_info->host, user_info->username, 
			      user_info->nick))
    {
      if(!remove_from_hash_table(ip_table, ip_class_c,
				  user_info->host, user_info->username, NULL))
	{
          send_to_all(NULL, FLAGS_ALL, "*** Error removing %s!%s@%s [%s] from iptable!",
                      user_info->nick, user_info->username, user_info->host, ip_class_c);

	  if(config_entries.debug && outfile)
	    {
	      fprintf(outfile,
		      "*** Error removing %s!%s@%s [%s] from iptable table!\n",
		      user_info->nick, user_info->username,
		      user_info->host, ip_class_c);
	    }
	}
    }
#endif
}

/*
 * hash_func()
 *
 * inputs	- string to hash
 * output	- hash function result
 * side effects	-
 */

static int
hash_func(const char *string)
{
  int i;

  i = *(string++);
  if(*string)
    i |= (*(string++) << 8);
    if(*string)
      i |= (*(string++) << 16);
      if(*string)
        i |= (*string << 24);
  return (i % HASHTABLESIZE);
}

/*
 * find_domain
 *
 * inputs	- pointer to hostname found
 * output	- pointer to domain
 * side effects	- none
 *
 * return pointer to domain found from host name
 */
static char*
find_domain(char* host)
{
  char *ip_domain;
  char *found_domain;
  int  found_dots=0;
  int  two_letter_tld=NO;
  int  is_legal_ip = YES;
  static char iphold[MAX_IP];
  int i = 0;
 
  ip_domain = host;

  if (BadPtr(host))
    return NULL;

  if(isdigit((int)*ip_domain))
  {
    while (*ip_domain)
    {
      iphold[i++] = *ip_domain;
      if(*ip_domain == '.')
	found_dots++;
      else if(!isdigit((int)*ip_domain))
	{
	  is_legal_ip = NO;
	  break;
	}

      if(found_dots == 3 )
	break;

      ip_domain++;

      if(i > (MAX_IP-2))
      {
	is_legal_ip = NO;
	break;
      }
    }
    iphold[i++] = '*';
    iphold[i] = '\0';
    ip_domain = iphold;
  }

  if((found_dots != 3) || !is_legal_ip)
  {
    found_domain = host + (strlen(host) - 1);

    /* find tld "com" "net" "org" or two letter domain i.e. "ca" */
    while (found_domain != host)
    {
      if(*found_domain == '.')
      {
	if(found_domain[3] == '\0')
	{
	  two_letter_tld = YES;
	}
	found_domain--;
	break;
      }
      found_domain--;
    }

    while (found_domain != host)
    {
      if(*found_domain == '.')
      {
	if(!two_letter_tld)
	{
	  found_domain++;
	}
	else
	{
	  found_domain--;
	}
	break;
      }
      found_domain--;
    }

    if(two_letter_tld)
    {
      while (found_domain != host)
      {
	if(*found_domain == '.')
	{
	  found_domain++;
	  break;
	}
	found_domain--;
      }
    }
    return(found_domain);
  }
  else
  {
    return(ip_domain);
  }
}

/*
 * check_host_clones()
 * 
 * inputs	- host
 * output	- none
 * side effects	- 
 */

#define AFCLONECONFREQ(x) (strchr(x, ':') ? IPV6CLONECONNECTFREQ : CLONECONNECTFREQ)
#define AFCLONECONCOUNT(x) (strchr(x, ':') ? IPV6CLONECONNECTCOUNT : CLONECONNECTCOUNT)

static void
check_host_clones(char *host)
{
  struct hash_rec *find;
  int clonecount = 0;
  int reportedclones = 0;
  time_t now, lastreport, oldest;
  char notice1[MAX_BUFF];
  char notice0[MAX_BUFF];
  struct tm *tmrec;
  int ind;

  notice1[0] = '\0';
  notice0[0] = '\0';
  oldest = now = time(NULL);
  lastreport = 0;
  ind = hash_func(host);

  for (find = host_table[ind]; find; find = find->next)
  {
    if((strcmp(find->info->host, host) == 0) &&
	(now - find->info->connecttime < AFCLONECONFREQ(host) + 1))
    {
      if(find->info->reporttime > 0)
      {
	++reportedclones;
	if(lastreport < find->info->reporttime)
	  lastreport = find->info->reporttime;
      }
      else
      {
	++clonecount;
	if(find->info->connecttime < oldest)
	  oldest = find->info->connecttime;
      }
    }
  }

  if((reportedclones == 0 && clonecount < AFCLONECONCOUNT(host)) ||
      now - lastreport < 10)
    return;

  if(reportedclones)
  {
    report(FLAGS_WARN,
	   "%d more possible clones (%d total) from %s",
	   clonecount, clonecount+reportedclones, host);

    tcm_log(L_NORM, "%d more possible clones (%d total) from %s",
	clonecount, clonecount+reportedclones, host);
  }
  else
  {
    report(FLAGS_WARN,
	   "Possible clones from %s detected: %d connects in %d seconds",
	   host, clonecount, now - oldest);

    tcm_log(L_NORM, 
	    "Possible clones from %s detected: %d connects in %d seconds",
	    host, clonecount, now - oldest);
  }

  for (find = host_table[ind],clonecount = 0; find; find = find->next)
  {
    if((strcmp(find->info->host, host) == 0) &&
	(now - find->info->connecttime < AFCLONECONFREQ(host) + 1) &&
	find->info->reporttime == 0)
    {
      ++clonecount;
      tmrec = localtime(&find->info->connecttime);

      if(clonecount == 1)
      {
	(void)snprintf(notice1, MAX_BUFF,
		       "  %s is %s@%s (%2.2d:%2.2d:%2.2d)",
		       find->info->nick, find->info->username, find->info->host,
		       tmrec->tm_hour, tmrec->tm_min, tmrec->tm_sec);
      }
      else
      {
	(void)snprintf(notice0, MAX_BUFF,
		       "  %s is %s@%s (%2.2d:%2.2d:%2.2d)",
		       find->info->nick, find->info->username, find->info->host,
		       tmrec->tm_hour, tmrec->tm_min, tmrec->tm_sec);
      }

      if(clonecount == 2)
      {
	handle_action(act_clone, 
		      find->info->nick, find->info->username,
		      find->info->host, find->info->ip_host, 0);
      }

      find->info->reporttime = now;
      if(clonecount == 2)
      {
        if(notice1[0] != '\0')
        {
  	  report(FLAGS_WARN, "%s", notice1);
	  tcm_log(L_NORM, "%s", notice1);
        }
	if(notice0[0] != '\0')
        {
          report(FLAGS_WARN, "%s", notice0);
  	  tcm_log(L_NORM, "%s", notice0);
        }
      }
      else if(clonecount < 5)
      {
        if(notice0[0] != '\0')
        {
	  report(FLAGS_WARN, "%s", notice0);
	  tcm_log(L_NORM, "%s", notice0);
        }
      }
      else if(clonecount == 5)
      {
        if(notice0[0] != '\0')
        {
	  send_to_all(NULL, FLAGS_WARN, "%s", notice0);
	  tcm_log(L_NORM, "  [etc.]");
        }
      }
    }
  }
}

/*
 * check_virtual_host_clones()
 * 
 * inputs	- "class c" ip as string
 * output	- none
 * side effects	- 
 *
 */
#ifdef VIRTUAL
static void
check_virtual_host_clones(char *ip_class_c)
{
  struct hash_rec *find;
  int clonecount = 0;
  int reportedclones = 0;
  time_t now, lastreport, oldest;
  char notice1[MAX_BUFF];
  char notice0[MAX_BUFF];
  char user[MAX_USER];
  struct tm *tmrec;
  int ind, different=NO, ident=NO;

  oldest = now = time(NULL);
  lastreport = 0;

  ind = hash_func(ip_class_c);

  for (find = ip_table[ind]; find; find = find->next)
    {
      if(!strcmp(find->info->ip_class_c, ip_class_c) &&
	  (now - find->info->connecttime < AFCLONECONFREQ(ip_class_c) + 1))
      {
	if(find->info->reporttime > 0)
	  {
	    ++reportedclones;
	    if(lastreport < find->info->reporttime)
	      lastreport = find->info->reporttime;
	  }
	else
	  {
	    ++clonecount;
	    if(find->info->connecttime < oldest)
	      oldest = find->info->connecttime;
	  }
       }
    }

  if(((reportedclones == 0) && (clonecount < AFCLONECONCOUNT(ip_class_c))) ||
      (now - lastreport < 10))
    return;

  if(reportedclones)
    {
      report(FLAGS_WARN,
	     "%d more possible virtual host clones (%d total) from %s%s",
	     clonecount, clonecount+reportedclones, ip_class_c,
	     strchr(ip_class_c, ':') ? "/64" : ".*");

      tcm_log(L_NORM, 
	      "%d more possible virtual host clones (%d total) from %s%s",
	      clonecount, clonecount+reportedclones, ip_class_c,
	      strchr(ip_class_c, ':') ? "/64" : ".*");
    }
  else
    {
      report(FLAGS_WARN,
	     "Possible virtual host clones from %s%s detected: %d connects in %d seconds",
	     ip_class_c, strchr(ip_class_c, ':') ? "/64" : ".*", clonecount, now - oldest);

      tcm_log(L_NORM,
              "Possible virtual host clones from %s%s detected: %d connects in %d seconds",
	      ip_class_c, strchr(ip_class_c, ':') ? "/64" : ".*", clonecount, now - oldest);
    }

  clonecount = 0;

  memset(&user, 0, sizeof(user));
  for (find = ip_table[ind]; find; find = find->next)
    {
      if(!strcmp(find->info->ip_class_c, ip_class_c) &&
	  (now - find->info->connecttime < AFCLONECONFREQ(ip_class_c) + 1) &&
	  find->info->reporttime == 0)
	{
          /*
           * slight trick here.  using the first username always works,
           * because it will be the most recent addition to the hash table.
           * if we check for vhost clones each time we add to the table,
           * we know not to bother checking the other usernames, since if
           * there were vhost clones, they would already have been dealt
           * with.  does that make sense? -bill
           */
          if(user[0] == '\0')
	    snprintf(user, MAX_USER, "%s", find->info->username);

          if(strcasecmp(user, find->info->username))
	    different=YES;

          if(find->info->username[0] != '~')
	    ident = YES;

          if (different == NO || ident == NO)
            ++clonecount;
          tmrec = localtime(&find->info->connecttime);

	  if(clonecount == 1)
	    {
	      (void)snprintf(notice1,MAX_BUFF - 1,
			     "  %s is %s@%s [%s] (%2.2d:%2.2d:%2.2d)",
			     find->info->nick, find->info->username,
			     find->info->host, find->info->ip_host,
			     tmrec->tm_hour, tmrec->tm_min, tmrec->tm_sec);
	    }
          else
	    {
	      (void)snprintf(notice0,MAX_BUFF - 1,
			     "  %s is %s@%s [%s] (%2.2d:%2.2d:%2.2d)",
			     find->info->nick, find->info->username,
			     find->info->host, find->info->ip_host,
			     tmrec->tm_hour, tmrec->tm_min, tmrec->tm_sec);
	    }

          /*
           * apparently we do not want to kline
	   * *@some.net.block.0/24 if the idents differ
	   *
	   * we do, however, if they differ w/o ident
	   * (ie ~clone1, ~clone2, ~clone3)        
	   */
	   if ((different == NO || ident == NO) && (clonecount >= AFCLONECONCOUNT(ip_class_c)))
            {
	      handle_action(act_vclone,
			    find->info->nick, find->info->username,
			    find->info->ip_host, find->info->ip_host, 0);
	    }

	  find->info->reporttime = now;
	  if(clonecount == 1)
	    ;
	  else if(clonecount == 2)
	    {
	      report(FLAGS_WARN, "%s", notice1);
	      tcm_log(L_NORM, "%s", notice1);

	      report(FLAGS_WARN, "%s", notice0);
	      tcm_log(L_NORM, "%s", notice0);
	    }
	  else if(clonecount < 5)
	    {
	      report(FLAGS_WARN, "%s", notice0);
	      tcm_log(L_NORM, "%s", notice0);
	    }
	  else if(clonecount == 5)
	    {
	      send_to_all(NULL, FLAGS_WARN, "%s", notice0);
	      tcm_log(L_NORM, "  [etc.]");
	    }
	}

    }
}
#endif

/*
 * update_nick
 * 
 * inputs -	- user
 *		- host
 *		- original nick
 *		- new nick
 * output	- NONE
 * side effects - An user has changed nicks. update the nick
 *
 * There are presently four hash tables:
 * one for username, one for hostname, one for domain and one for IP.
 * each hashtable consists of hash_rec(s). Each hash_rec points
 * to =one= common user_entry. This is why there is a link_count
 * in the user_entry. It suffices to find the user_entry that
 * has the old nick, then update it. It really wouldn't matter
 * (except possibly for speed) if the user hash is searched, the host hash
 * is searched, or... whatever.
 * - Dianora
 *
 */
void
update_nick(char *user, char *host, char *old_nick, char *new_nick)
{
  struct hash_rec *find;
  int hash_val;

  hash_val = hash_func(user);
  
  for(find = user_table[hash_val]; find; find = find->next)
  {
    if((strcmp(find->info->username,user) == 0) &&
       (strcmp(find->info->host,host) == 0) &&
       (strcmp(find->info->nick, old_nick) == 0))
    {
      strlcpy(find->info->nick, new_nick,
              sizeof(find->info->nick));
      return;
    }
  }
}

#ifdef AGGRESSIVE_GECOS
/*
 * update_gecos
 *
 * inputs       - nick, user, host, gecos
 * outputs      - none
 * side effects - updates a user entry's gecos information
 */
void
update_gecos(char *nick, char *user, char *host, char *gecos)
{
  struct hash_rec *find;
  int hash_val;

  hash_val = hash_func(user);

  for(find = user_table[hash_val]; find; find = find->next)
  {
    if((strcmp(find->info->username, user) == 0) &&
       (strcmp(find->info->host, host) == 0) &&
       (strcmp(find->info->nick, nick) == 0))
    {
      strlcpy(find->info->gecos, gecos,
              sizeof(find->info->gecos));
      return;
    }
  }
}
#endif

/*
 * kill_add_report
 *
 * input	- server notice
 * output	- none
 * side effects	- local kills are logged
 *
 *  Log only local kills though....
 *
 *** Notice -- Received KILL message for Newbie2. From Dianora_ Path:
 *  ts1-4.ottawa.net!Dianora_ (clone)
 * Thanks Thembones for bug fix (Brian Kraemer kraemer@u.washington.edu)
 */

void
kill_add_report(char *server_notice)
{
  char *p, *q;
  char *nick, *by, *reason;
  struct hash_rec *ptr;
  int i=0;

  if((p = strstr(server_notice, ". From")) == NULL)
    return;
  *p = '\0';
  p+=7;
  if((nick = strrchr(server_notice, ' ')) == NULL)
    return;
  ++nick;
  by = p;
  if((p = strchr(by, ' ')) == NULL)
    return;
  *p = '\0';
  if(strchr(by, '.')) /* ignore kills by servers */
    return;
  p+=7;
    if((q = strchr(p, ' ')) == NULL)
     return;
  q+=2;
  if((p = strrchr(q, ')')) == NULL)
    return;
  *p = '\0';
  reason = q;
  for (i=0;i<HASHTABLESIZE;++i)
    {
      for (ptr = domain_table[i]; ptr; ptr = ptr->next)
	{
	  if(!strcasecmp(nick, ptr->info->nick))
	    {
	      send_to_all(NULL, FLAGS_VIEW_KLINES, "%s killed by %s: %s",
			  nick, by, reason);
	      tcm_log(L_NORM, "%s killed by %s: %s",
		      nick, by, reason);
	      break;
	    }
	}
    }
}


/*
 * report_domains
 * input        - sock
 *              - num
 * output       - NONE
 * side effects -
 */

struct sort_array sort[MAXDOMAINS];

void 
report_domains(struct connection *connection_p, int num)
{
  struct hash_rec *ptr;
  int inuse = 0;
  int i;
  int j;
  int maxx;
  int found;
  int foundany = NO;

  for (i = 0; i < HASHTABLESIZE; i++)
    {
      for (ptr = domain_table[i]; ptr; ptr = ptr->next)
        {
          for (j=0; j < inuse; ++j)
            {
              if(!strcasecmp(ptr->info->domain,
			      sort[j].domain_rec->info->domain))
                break;
            }

          if((j == inuse) && (inuse < MAXDOMAINS))
            {
              sort[inuse].domain_rec = ptr;
              sort[inuse++].count = 1;
            }
          else
            {
              ++sort[j].count;
            }
        }
    }
  /* Print 'em out from highest to lowest */
  FOREVER
    {
      maxx = num-1;
      found = -1;
      for (i=0;i<inuse;++i)
        if(sort[i].count > maxx)
          {
            found = i;
            maxx = sort[i].count;
          }
      if(found == -1)
        break;
      if(!foundany)
        {
          foundany = YES;
          send_to_connection(connection_p,
			     "Domains with most users on the server:");
        }

      send_to_connection(connection_p, "  %-40s %3d users",
			 sort[found].domain_rec->info->domain, maxx);
      sort[found].count = 0;
    }

  if(!foundany)
    {
      send_to_connection(connection_p,
			 "No domains have %d or more users.",num);
    }
  else
    {
      send_to_connection(connection_p, "%d domains found", inuse);
    }
}


/*
 * list_class()
 *
 * inputs       - integer socket to reply on
 *              - integer class to search for
 *              - integer show total only YES/NO
 * output       - NONE
 * side effects -
 */

void 
list_class(struct connection *connection_p, char *class_to_find,int total_only)
{
  struct hash_rec *ptr;
  int i;
  int num_found=0;
  int num_unknown=0;

  for (i=0; i < HASHTABLESIZE; ++i)
    {
      for (ptr = domain_table[i]; ptr; ptr = ptr->next)
        {
          if(strcmp(ptr->info->class, "unknown") == 0)
            num_unknown++;

          if(strcasecmp(class_to_find, ptr->info->class) == 0)
            {
              if(!total_only)
                {
                  if(num_found == 0)
                    {
                      /* Simply the header to the list of clients */
                      send_to_connection(connection_p,
                           "The following clients are in class %s",
                           class_to_find);
                    }

                    send_to_connection(connection_p,
				       "  %s (%s@%s)", ptr->info->nick,
				       ptr->info->username, ptr->info->host);
                }

              num_found++;
            }
        }
    }

  if(num_found != 0)
    send_to_connection(connection_p,
		       "%d are in class %s", num_found, class_to_find );
  else
    send_to_connection(connection_p,
		       "Nothing found in class %s", class_to_find);
  send_to_connection(connection_p, "%d unknown class", num_unknown);
}

/*
 * list_nicks()
 *
 * inputs       - struct connection
 * output       - NONE
 * side effects -
 */

void 
list_nicks(struct connection *connection_p, char *nick, int regex)
{
  struct hash_rec *ptr;
#ifdef HAVE_REGEX_H
  regex_t reg;
  regmatch_t m[1];
#endif
  int i=0;
  int numfound=0;

#ifdef HAVE_REGEX_H
  if(regex == YES && (i=regcomp((regex_t *)&reg, nick, 1)))
  {
    char errbuf[1024];
    regerror(i, (regex_t *)&reg, errbuf, 1024); 
    send_to_connection(connection_p,
		       "Error compiling regular expression: %s", errbuf);
    return;
  }
#endif

  for (i=0; i<HASHTABLESIZE; ++i)
    {
      for (ptr = domain_table[i]; ptr; ptr = ptr->next)
        {
#ifdef HAVE_REGEX_H
          if((regex == YES &&
               !regexec((regex_t *)&reg, ptr->info->nick,1,m,REGEXEC_FLAGS))
              || (regex == NO && !match(nick, ptr->info->nick)))
#else
          if(!match(nick, ptr->info->nick))
#endif
            {
              if(!numfound)
                {
                  send_to_connection(connection_p,
				     "The following clients match %.150s:",
				     nick);
                }
              numfound++;

              send_to_connection(connection_p,
				 "  %s (%s@%s) [%s] {%s}",
				 ptr->info->nick, ptr->info->username,
				 ptr->info->host, ptr->info->ip_host,
                                 ptr->info->class);
            }
        }
    }

  if(numfound)
    send_to_connection(connection_p,
		       "%d matches for %s found",numfound,nick);
  else
    send_to_connection(connection_p,
		       "No matches for %s found",nick);
}

/*
 * kill_or_list_users()
 *
 * inputs       - struct connection pointer
 *              - uhost to match on
 *              - regex or no?
 *		- action to take
 *		- list name to perform action on
 * output       - NONE
 * side effects -
 */

void 
kill_or_list_users(struct connection *connection_p, char *userhost, int regex,
		   int action, char *list_name, const char *reason)
{
  struct hash_rec *ptr;
  struct client_list *list;
  struct user_entry *user;
  char uhost[MAX_USERHOST], *rsn = BadPtr(reason) ? "No reason" : (char *)reason;
  int numfound = 0, i, idx;
  dlink_node *dptr;

#ifdef HAVE_REGEX_H
  regex_t reg;
  regmatch_t m[1];

  if(regex == YES && (i = regcomp((regex_t *)&reg, userhost, 1)))
  {
    char errbuf[REGEX_SIZE];
    regerror(i, (regex_t *)&reg, errbuf, REGEX_SIZE); 
    send_to_connection(connection_p, "Error compiling regular expression: %s",
		       errbuf);
    return;
  }
#endif

  if(!strcmp(userhost,"*") || !strcmp(userhost,"*@*"))
  {
    send_to_connection(connection_p,
                       "Listing all users is not recommended.  To do it anyway, use '.list ?*@*'.");
    return;
  }

  if(action == KILL && list_name != NULL)
  {
    if((i = find_list(list_name)) == -1)
    {
      send_to_connection(connection_p, "No such list.");
      return;
    }
    list = &client_lists[i];

    DLINK_FOREACH(dptr, list->dlink.head)
    {
      user = dptr->data;
      if (numfound++ == 0)
        tcm_log(L_NORM, "killlisted list %s", list_name);

      send_to_server("KILL %s :%s", user->nick, rsn);
    }
    return;
  }
  else if (action == DUMP && list_name != NULL)
  {
    print_list(connection_p, list_name);
    return;
  }

  if (action == MAKE)
  {
    if ((idx = find_list(list_name)) == -1 &&
        (create_list(connection_p, list_name) != NULL))
      idx = find_list(list_name);
  }

  for (i=0; i < HASHTABLESIZE; ++i)
  {
    for (ptr = domain_table[i]; ptr; ptr = ptr->next)
    {
      snprintf(uhost, MAX_USERHOST, "%s@%s", ptr->info->username,
               ptr->info->host);
#ifdef HAVE_REGEX_H
      if((regex == YES &&
          !regexec((regex_t *)&reg, uhost, 1, m, REGEXEC_FLAGS)) 
          || (regex == NO && !match(userhost, uhost)))
#else
      if(match(userhost, uhost) == 0)
#endif 
      {
        switch (action)
        {
          case KILL:
            if(numfound++ == 0)
              tcm_log(L_NORM, "killlisted %s", uhost);

            send_to_server("KILL %s :%s", ptr->info->nick, reason);
            break;

          case DUMP:
            if (numfound++ == 0)
              send_to_connection(connection_p,
                                 "The following clients match %s:",
                                 userhost);

	    if(ptr->info->ip_host[0] > '9' || ptr->info->ip_host[0] < '0')
	      send_to_connection(connection_p,
				 "  %s (%s@%s) {%s}", ptr->info->nick,
				 ptr->info->username,
				 ptr->info->host, ptr->info->class);
	    else
	      send_to_connection(connection_p,
				 "  %s (%s@%s) [%s] {%s}", ptr->info->nick,
				 ptr->info->username, ptr->info->host,
				 ptr->info->ip_host, ptr->info->class);
            break;

          case MAKE:
            if (numfound++ == 0)
              send_to_connection(connection_p,
                                 "Adding matches to list %s",
                                 list_name);

            if (!add_client_to_list(ptr->info, idx))
            {
              send_to_connection(connection_p,
                                 "Failed to add %s (%s@%s) [%s] {%s} to the list",
                                 ptr->info->nick, ptr->info->username, ptr->info->host,
                                 ptr->info->ip_host, ptr->info->class);
              continue;
            }
          default:
            break;
	}
      }
    }
  }

  if(numfound > 0)
    send_to_connection(connection_p,
		       "%d matches for %s found", numfound, userhost);
  else
    send_to_connection(connection_p, "No matches for %s found", userhost);
}

/*
 * list_gecos()
 * inputs	- struct connection pointer
 * 		- uhost to match on
 * 		- regex or no?
 * outputs	- none
 * side effects - 
 */

void
list_gecos(struct connection *connection_p, char *u_gecos, int regex)
{
  struct hash_rec *ptr;
#ifdef HAVE_REGEX_H
  regex_t reg;
  regmatch_t m[1];
#endif
  char gecos[MAX_GECOS];
  int i, numfound = 0;

#ifdef HAVE_REGEX_H
  if(regex == YES && (i = regcomp((regex_t *)&reg, u_gecos, 1)))
  {
    char errbuf[REGEX_SIZE];
    regerror(i, (regex_t *)&reg, errbuf, REGEX_SIZE);
    send_to_connection(connection_p, "Error compiling regular expression: %s",
                       errbuf); 
    return;
  }
#endif
  if (!strcmp(u_gecos,"*") || !strcmp(u_gecos,"*@*"))
  {
    send_to_connection(connection_p, "Listing all users is not recommended.  "
                       "To do it anyway, use '.gecos ?*'.");
    return;
  }

  for (i=0; i < HASHTABLESIZE; ++i)
  {
    for (ptr = domain_table[i]; ptr; ptr = ptr->next)
    {
      snprintf(gecos, MAX_GECOS, "%s", ptr->info->gecos);
#ifdef HAVE_REGEX_H
      if(((regex == YES &&
          !regexec((regex_t *)&reg, gecos, 1, m, REGEXEC_FLAGS))
          || (regex == NO && !match(u_gecos, gecos))) && (gecos[0] != '\0'))
#else
      if (match(u_gecos, gecos) == 0 && (gecos[0] != '\0'))
#endif
      {
        if (numfound == 0)
          send_to_connection(connection_p,
                             "The following clients match %s:", u_gecos);

        numfound++;
        if(ptr->info->ip_host[0] > '9' || ptr->info->ip_host[0] < '0')
          send_to_connection(connection_p,
                             "  %s (%s@%s) {%s} [%s]", ptr->info->nick,
                             ptr->info->username, ptr->info->host,
                             ptr->info->class, ptr->info->gecos);
        else
          send_to_connection(connection_p,
                             "  %s (%s@%s) [%s] {%s} [%s]", ptr->info->nick,
                             ptr->info->username, ptr->info->host,
                             ptr->info->ip_host, ptr->info->class,
                             ptr->info->gecos);
      }
    }
  }
  if(numfound > 0)
    send_to_connection(connection_p,
                       "%d matches for %s found", numfound, u_gecos);
  else
    send_to_connection(connection_p, "No matches for %s found", u_gecos);
}
   
/*
 * report_mem()
 * inputs       - pointer to connection
 * output       - none
 * side effects - rough memory usage is reported
 */

void report_mem(struct connection *connection_p)
{
  int i;
  struct hash_rec *current;
  unsigned long total_host_table=0L;
  int count_host_table=0;
  unsigned long total_domain_table=0L;
  int count_domain_table=0;
#ifdef VIRTUAL
  unsigned long total_ip_table=0L;
  int count_ip_table=0;
#endif
  unsigned long total_user_table=0L;
  int count_user_table=0;
  unsigned long total_user_entry=0L;
  int count_user_entry=0;

  /*  host_table,domain_table,ip_table */

  for (i = 0; i < HASHTABLESIZE; i++)
    {
      for (current = host_table[i]; current; current = current->next)
        {
          total_host_table += sizeof(struct hash_rec);
          count_host_table++;

          total_user_entry += sizeof(struct user_entry);
          count_user_entry++;
        }
    }

  for (i = 0; i < HASHTABLESIZE; i++)
    {
      for (current = domain_table[i]; current; current = current->next)
        {
          total_domain_table += sizeof(struct hash_rec);
          count_domain_table++;
        }
    }

#ifdef VIRTUAL
  for (i = 0; i < HASHTABLESIZE; i++)
    {
      for (current = ip_table[i]; current; current = current->next)
        {
          total_ip_table += sizeof(struct hash_rec);
          count_ip_table++;
        }
    }
#endif

  for (i = 0; i < HASHTABLESIZE; i++)
    {
      for (current = user_table[i]; current; current = current->next)
        {
          total_user_table += sizeof(struct hash_rec);
          count_user_table++;
        }
    }

  send_to_connection(connection_p,"Total host_table memory %lu/%d entries",
		     total_host_table, count_host_table);

  send_to_connection(connection_p, "Total usertable memory %lu/%d entries",
		     total_user_table, count_user_table);

  send_to_connection(connection_p, "Total domaintable memory %lu/%d entries",
		     total_domain_table, count_domain_table);

  send_to_connection(connection_p, "Total iptable memory %lu/%d entries",
		     total_ip_table, count_ip_table);

  send_to_connection(connection_p, "Total user entry memory %lu/%d entries",
		     total_user_entry, count_user_entry);

  send_to_connection(connection_p,"Total memory in use %lu",
		     total_host_table + total_domain_table +
		     total_ip_table + total_user_entry );
}

void
init_hash(void)
{
  memset(&user_table,0,sizeof(user_table));
  memset(&host_table,0,sizeof(user_table));
  memset(&domain_table,0,sizeof(user_table));
#ifdef VIRTUAL
  memset(&ip_table,0,sizeof(ip_table));
#endif
}

#ifdef VIRTUAL
/*
 * make_ip_class_c
 *
 * inputs	- pointer to ip string
 * output	- none
 * side effects	- input string is modified in-place
 */

static void
make_ip_class_c(char *p)
{
  int  found_dots=0;

  while(*p)
  {
    if(*p == '.')
      found_dots++;
    
    if(found_dots == 3)
    {
      *p = '\0';
      break;
    }
    p++;
  }
}

#ifdef VIRTUAL_IPV6
/*
 * make_ip_slash_64
 *
 * inputs	- pointer to ipv6 string
 * output	- none
 * side effects	- input string is modified in-place
 */

static void
make_ip_slash_64(char *p)
{
  u_int16_t words[8];

  if (inet_pton6(p, (char *)&words)) {
    words[4] = words[5] = words[6] = words[7] = 0;
    inet_ntop6((char *)&words, p, MAX_IP);
  }
}

#endif /* VIRTUAL_IPV6 */
#endif /* VIRTUAL */
