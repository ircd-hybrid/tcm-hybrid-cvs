/* hash.c
 *
 * $Id: hash.c,v 1.9 2002/05/30 18:22:15 db Exp $
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

#ifdef HAVE_REGEX_H
#include <regex.h>
#define REGCOMP_FLAGS REG_EXTENDED
#define REGEXEC_FLAGS 0
#endif

#ifndef INADDR_NONE
#define INADDR_NONE ((unsigned int) 0xffffffff)
#endif

static int hash_func(const char *string);
static char* find_domain(char* domain);
static void check_host_clones(char *);
#ifdef VIRTUAL
static void make_ip_class_c(char *p);
static void check_virtual_host_clones(char *);
#endif

struct hashrec *user_table[HASHTABLESIZE];
struct hashrec *host_table[HASHTABLESIZE];
struct hashrec *domain_table[HASHTABLESIZE];
struct hashrec *ip_table[HASHTABLESIZE];

/*
 * free_hash_links
 *
 * inputs       - pointer to link list to free
 * output       - none
 * side effects -
 */
static void 
free_hash_links(struct hashrec *ptr)
{
  struct hashrec *next_ptr;

  if (ptr == NULL)
    return;

  for(; ptr != NULL; ptr = next_ptr);
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
 * freehash()
 *
 * inputs               - NONE
 * output               - NONE
 * side effects         - clear all allocated memory hash tables
 *
*/

void 
freehash(void)
{
  struct hashrec *ptr;
  int i;

  for (i=0; i<HASHTABLESIZE; i++)
    {
      ptr = user_table[i];
      free_hash_links(ptr);
      user_table[i] = NULL;

      ptr = host_table[i];
      free_hash_links(ptr);
      host_table[i] = NULL;

      ptr = domain_table[i];
      free_hash_links(ptr);
      domain_table[i] = NULL;

#ifdef VIRTUAL
      ptr = ip_table[i];
      free_hash_links(ptr);
      ip_table[i] = NULL;
#endif
    }

  free_bothunt();
}

/*
 * find_nick
 *
 * Returns an userentry for the given nick, or NULL if not found
 *
 */

struct userentry *
find_nick(const char *nick)
{
  int i;
  struct hashrec *user_ptr;

  if (nick == NULL)
    return (NULL);

  for (i=0; i<HASHTABLESIZE; ++i)
    {
      for(user_ptr = domain_table[i]; user_ptr; user_ptr = user_ptr->next)
	{
	  if (!wldcmp((char *)nick, user_ptr->info->nick))
	    return (user_ptr->info);
	}
    }
  return (NULL);
}

/*
 * find_host
 *
 * Returns first userentry for the given host, or NULL if not found
 *
 */

struct userentry *
find_host(const char *host)
{
  int i;
  struct hashrec * user_ptr;

  if (host == NULL)
    return (NULL);

  for (i=0; i<HASHTABLESIZE; ++i)
    {
      for (user_ptr = domain_table[i]; user_ptr; user_ptr = user_ptr->next)
	{
	  if (!wldcmp((char *)host, user_ptr->info->host))
	    return (user_ptr->info);
	}
    }
  return (NULL);
}

/*
 * add_to_hash_table()
 *
 * inputs	- pointer to hash table
 *		- pointer to key being used for hash
 *		- pointer to userentry to add
 * output	- none
 * side effects	- 
 */

void
add_to_hash_table(struct hashrec *table[],
		       const char *key, struct hashrec *hashptr)
{
  int ind;
  
  ind = hash_func(key);
  if (table[ind] == NULL)
    {
      table[ind] = hashptr;
    }
  else
    {
      ((struct hashrec *)table[ind])->next = hashptr;
      hashptr->next = table[ind];
    }
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
remove_from_hash_table(struct hashrec *table[],
		       const char *key, const char *host_match,
		       const char *user_match, const char *nick_match)
{
  struct hashrec *find;
  struct hashrec *prev=NULL;
  int ind;

  for (find = table[(ind = hash_func(key))]; find; find = find->next)
  {
    if ((!host_match	|| !strcmp(find->info->host, host_match)) &&
	(!user_match	|| !strcmp(find->info->user, user_match)) &&
	(!nick_match	|| !strcmp(find->info->nick, nick_match)))
    {
      if (prev != NULL)
	prev->next = find->next;
      else
	table[ind] = find->next;
      find->info->link_count--;
      if (find->info->link_count == 0)
	xfree(find->info);
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
 * inputs	- pointer to struct plus_c_info
 * 		- from a trace YES or NO
 * 		- is this user an oper YES or NO
 * output	- NONE
 * side effects	-
 * 
 */

void
add_user_host(struct plus_c_info *user_info, int fromtrace, int is_oper)
{
  struct hashrec *new_hash;
  struct userentry *new_user;
  char *domain;

#if defined(DETECT_WINGATE) || defined(DETECT_SOCKS) || defined(DETECT_SQUID)
  if (!doingtrace)
    user_signon(user_info);
#endif

  new_hash = (struct hashrec *)xmalloc(sizeof(struct hashrec));
  new_user = (struct userentry *)xmalloc(sizeof(struct userentry));
  new_user->link_count = 0;

  strlcpy(new_user->nick, user_info->nick, MAX_NICK);
  strlcpy(new_user->user, user_info->user, MAX_NICK);
  strlcpy(new_user->host, user_info->host, MAX_HOST);
#ifdef VIRTUAL
  if (user_info->ip[0] != '\0')
    strlcpy(new_user->ip_host, user_info->ip, MAX_IP);
  else
    strcpy(new_user->ip_host,"0.0.0.0");
  make_ip_class_c(new_user->ip_class_c);
#endif

  new_user->connecttime = (fromtrace ? 0 : time(NULL));
  new_user->reporttime = 0;

  new_user->isoper = is_oper;
  strcpy(new_user->class, user_info->class);

  /* Determine the domain name */
  domain = find_domain(user_info->host);

  strlcpy(new_user->domain, domain, MAX_HOST);

  /* Add it to the hash tables */
  add_to_hash_table(user_table, user_info->user, new_hash);
  add_to_hash_table(host_table, user_info->host, new_hash);
  add_to_hash_table(domain_table, domain, new_hash);

#ifdef VIRTUAL
  if (new_user->ip_class_c[0])
    add_to_hash_table(ip_table, new_user->ip_class_c, new_hash);
#endif

  /* Clonebot check */
  if (!fromtrace)
    {
      check_host_clones(user_info->host);
#ifdef VIRTUAL
      check_virtual_host_clones(new_user->ip_class_c);
#endif
      check_reconnect_clones(user_info->host);
    }
}


/*
 * remove_user_host()
 * 
 * inputs	- nick
 * 		- pointer to struct plus_c_info
 * output	- NONE
 * side effects	- 
 */

void
remove_user_host(char *nick, struct plus_c_info *user_info)
{
#ifdef VIRTUAL
  char ip_class_c[MAX_IP];
#endif
  char *domain;

  domain = find_domain(user_info->host);

  if (!remove_from_hash_table(host_table, user_info->host,
			      user_info->host, user_info->user, nick)) 
    {
      if (!remove_from_hash_table(host_table, user_info->host,
				  user_info->host, user_info->user, NULL))
	{
	  if (config_entries.debug && outfile)
	    {
	      fprintf(outfile,"*** Error removing %s!%s@%s from host table!\n",
		      nick,
		      user_info->user,
		      user_info->host);
	    }
	}
    }

  if (!remove_from_hash_table(domain_table, domain,
			      user_info->host, user_info->user, nick))
    {
      if (!remove_from_hash_table(domain_table, domain,
				  user_info->host, user_info->user, NULL))
	{
	  if (config_entries.debug && outfile)
	    {
	      fprintf(outfile,"*** Error removing %s!%s@%s from domain table!\n",
		      nick,
		      user_info->user,
		      user_info->host);
	    }
	}
    }

  if (!remove_from_hash_table(user_table, user_info->user,
			      user_info->host, user_info->user, nick))
    {
      if (!remove_from_hash_table(user_table, user_info->user,
				  user_info->host, user_info->user, NULL))
	{
	  if (config_entries.debug && outfile)
	    {
	      fprintf(outfile,"*** Error removing %s!%s@%s from user table!\n",
		      nick,
		      user_info->user,
		      user_info->host);
	    }
	}
    }

#ifdef VIRTUAL
  if (user_info->ip[0])
    strlcpy(ip_class_c, user_info->ip, MAX_IP);
  else
    strcpy(ip_class_c, "0.0.0.0");
  make_ip_class_c(ip_class_c);

  if (!remove_from_hash_table(ip_table, ip_class_c,
			      user_info->host, user_info->user, nick))
    {
      if (!remove_from_hash_table(ip_table, ip_class_c,
				  user_info->host, user_info->user, NULL))
	{
	  if (config_entries.debug && outfile)
	    {
	      fprintf(outfile,
		      "*** Error removing %s!%s@%s [%s] from iptable table!\n",
		      nick,
		      user_info->user,
		      user_info->host,
		      ip_class_c);
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
  if (*string)
    i |= (*(string++) << 8);
    if (*string)
      i |= (*(string++) << 16);
      if (*string)
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
  static char iphold[MAX_IP+1];
  int i = 0;
 
  ip_domain = host;

  if (isdigit((int) *ip_domain))
  {
    while (*ip_domain)
    {
      iphold[i++] = *ip_domain;
      if (*ip_domain == '.')
	found_dots++;
      else if (!isdigit((int) *ip_domain))
	{
	  is_legal_ip = NO;
	  break;
	}

      if (found_dots == 3 )
	break;

      ip_domain++;

      if (i > (MAX_IP-2))
      {
	is_legal_ip = NO;
	break;
      }
    }
    iphold[i++] = '*';
    iphold[i] = '\0';
    ip_domain = iphold;
  }

  if ((found_dots != 3) || !is_legal_ip)
  {
    found_domain = host + (strlen(host) - 1);

    /* find tld "com" "net" "org" or two letter domain i.e. "ca" */
    while (found_domain != host)
    {
      if (*found_domain == '.')
      {
	if (found_domain[3] == '\0')
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
      if (*found_domain == '.')
      {
	if (!two_letter_tld)
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

    if (two_letter_tld)
    {
      while (found_domain != host)
      {
	if (*found_domain == '.')
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

static void
check_host_clones(char *host)
{
  struct hashrec *find;
  int clonecount = 0;
  int reportedclones = 0;
  char *last_user="";
  int current_identd;
  int different;
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
    if ((strcmp(find->info->host, host) == 0) &&
	(now - find->info->connecttime < CLONECONNECTFREQ + 1))
    {
      if (find->info->reporttime > 0)
      {
	++reportedclones;
	if (lastreport < find->info->reporttime)
	  lastreport = find->info->reporttime;
      }
      else
      {
	++clonecount;
	if (find->info->connecttime < oldest)
	  oldest = find->info->connecttime;
      }
    }
  }

  if ((reportedclones == 0 && clonecount < CLONECONNECTCOUNT) ||
      now - lastreport < 10)
    return;

  if (reportedclones)
  {
    report(FLAGS_WARN,
	   CHANNEL_REPORT_CLONES,
	   "%d more possible clones (%d total) from %s:\n",
	   clonecount, clonecount+reportedclones, host);

    tcm_log(L_NORM, "%d more possible clones (%d total) from %s:\n",
	clonecount, clonecount+reportedclones, host);
  }
  else
  {
    report(FLAGS_WARN,
	   CHANNEL_REPORT_CLONES,
	   "Possible clones from %s detected: %d connects in %d seconds\n",
	   host, clonecount, now - oldest);

    tcm_log(L_NORM, 
	    "Possible clones from %s detected: %d connects in %d seconds\n",
	    host, clonecount, now - oldest);
  }

  for(find = host_table[ind],clonecount = 0; find; find = find->next)
  {
    if ((strcmp(find->info->host, host) == 0) &&
	(now - find->info->connecttime < CLONECONNECTFREQ + 1) &&
	find->info->reporttime == 0)
    {
      ++clonecount;
      tmrec = localtime(&find->info->connecttime);

      if (clonecount == 1)
      {
	(void)snprintf(notice1, MAX_BUFF-1,
		       "  %s is %s@%s (%2.2d:%2.2d:%2.2d)\n",
		       find->info->nick, find->info->user, find->info->host,
		       tmrec->tm_hour, tmrec->tm_min, tmrec->tm_sec);
      }
      else
      {
	(void)snprintf(notice0, MAX_BUFF-1,
		       "  %s is %s@%s (%2.2d:%2.2d:%2.2d)\n",
		       find->info->nick, find->info->user, find->info->host,
		       tmrec->tm_hour, tmrec->tm_min, tmrec->tm_sec);
      }

      current_identd = YES;
      different = NO;

      if (clonecount == 1)
	last_user = find->info->user;
      else if (clonecount == 2)
      {
	char *current_user;
	
	if (*last_user == '~')
	{
	  last_user++;
	}

	current_user = find->info->user;
	if (*current_user != '~')
	  current_identd = YES;
	else
	  ++current_user;

	if (strcmp(last_user, current_user) && current_identd)
	  different = YES;

	handle_action(act_clone, current_identd, 
		      find->info->nick, find->info->user,
		      find->info->host, find->info->ip_host, 0);
      }

      find->info->reporttime = now;
      if (clonecount == 2)
      {
        if (notice1[0] != '\0')
        {
  	  report(FLAGS_WARN, CHANNEL_REPORT_CLONES, "%s", notice1);
	  tcm_log(L_NORM, "%s", notice1);
        }
	if (notice0[0] != '\0')
        {
          report(FLAGS_WARN, CHANNEL_REPORT_CLONES, "%s", notice0);
  	  tcm_log(L_NORM, "%s", notice0);
        }
      }
      else if (clonecount < 5)
      {
        if (notice0[0])
        {
	  report(FLAGS_WARN, CHANNEL_REPORT_CLONES, "%s", notice0);
	  tcm_log(L_NORM, "%s", notice0);
        }
      }
      else if (clonecount == 5)
      {
        if (notice0[0] != '\0')
        {
	  send_to_all( FLAGS_WARN, "%s", notice0);
	  tcm_log(L_NORM, "  [etc.]\n");
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
  struct hashrec *find;
  int clonecount = 0;
  int reportedclones = 0;
  time_t now, lastreport, oldest;
  char notice1[MAX_BUFF];
  char notice0[MAX_BUFF];
  char user[MAX_USER];
  struct tm *tmrec;
  int ind, different=NO, ident=YES;

  oldest = now = time(NULL);
  lastreport = 0;

  ind = hash_func(ip_class_c);

  for (find = ip_table[ind]; find; find = find->next)
    {
      if (!strcmp(find->info->ip_class_c, ip_class_c) &&
	  (now - find->info->connecttime < CLONECONNECTFREQ + 1))
      {
	if (find->info->reporttime > 0)
	  {
	    ++reportedclones;
	    if (lastreport < find->info->reporttime)
	      lastreport = find->info->reporttime;
	  }
	else
	  {
	    ++clonecount;
	    if (find->info->connecttime < oldest)
	      oldest = find->info->connecttime;
	  }
       }
    }

  if (((reportedclones == 0) && (clonecount < CLONECONNECTCOUNT)) ||
      (now - lastreport < 10))
    return;

  if (reportedclones)
    {
      report(FLAGS_WARN,
	     CHANNEL_REPORT_VCLONES,
	     "%d more possible virtual host clones (%d total) from %s.*:\n",
	     clonecount, clonecount+reportedclones, ip_class_c);

      tcm_log(L_NORM, 
	      "%d more possible virtual host clones (%d total) from %s.*:\n",
	      clonecount, clonecount+reportedclones, ip_class_c);
    }
  else
    {
      report(FLAGS_WARN,
	     CHANNEL_REPORT_VCLONES,
	     "Possible virtual host clones from %s.* detected: %d connects in %d seconds\n",
	     ip_class_c, clonecount, now - oldest);

      tcm_log(L_NORM,
"Possible virtual host clones from %s.* detected: %d connects in %d seconds\n",
	      ip_class_c, clonecount, now - oldest);
    }

  clonecount = 0;

  memset(&user, 0, sizeof(user));
  for (find = ip_table[ind]; find; find = find->next)
    {
      if (!strcmp(find->info->ip_class_c, ip_class_c) &&
	  (now - find->info->connecttime < CLONECONNECTFREQ + 1) &&
	  find->info->reporttime == 0)
	{
	  ++clonecount;
	  tmrec = localtime(&find->info->connecttime);

          if (user[0] == '\0')
	    snprintf(user, MAX_USER-1, "%s", find->info->user);

          if (strcasecmp(user, find->info->user))
	    different=YES;

          if (find->info->user[0] == '~')
	    ident = NO;
          else
	    ident = YES;

	  if (clonecount == 1)
	    {
	      (void)snprintf(notice1,MAX_BUFF - 1,
			     "  %s is %s@%s [%s] (%2.2d:%2.2d:%2.2d)\n",
			     find->info->nick, find->info->user,
			     find->info->host, find->info->ip_host,
			     tmrec->tm_hour, tmrec->tm_min, tmrec->tm_sec);
	    }
          else
	    {
	      (void)snprintf(notice0,MAX_BUFF - 1,
			     "  %s is %s@%s [%s] (%2.2d:%2.2d:%2.2d)\n",
			     find->info->nick, find->info->user,
			     find->info->host, find->info->ip_host,
			     tmrec->tm_hour, tmrec->tm_min, tmrec->tm_sec);
	    }

          /* apparently we do not want to kline
	   * *@some.net.block.0/24 if the idents differ
	   *
	   * we do, however, if they differ w/o ident
	   * (ie ~clone1, ~clone2, ~clone3)        
	   */
          if ((different == NO && ident == YES) || (ident == NO))
            {
	      handle_action(act_vclone, ident,
			    find->info->nick, find->info->user,
			    find->info->ip_host, find->info->ip_host, 0);
	    }

	  find->info->reporttime = now;
	  if (clonecount == 1)
	    ;
	  else if (clonecount == 2)
	    {
	      report(FLAGS_WARN, CHANNEL_REPORT_VCLONES, "%s", notice1);
	      tcm_log(L_NORM, "%s", notice1);

	      report(FLAGS_WARN, CHANNEL_REPORT_VCLONES, "%s", notice0);
	      tcm_log(L_NORM, "%s", notice0);
	    }
	  else if (clonecount < 5)
	    {
	      report(FLAGS_WARN, CHANNEL_REPORT_VCLONES, "%s", notice0);
	      tcm_log(L_NORM, "%s", notice0);
	    }
	  else if (clonecount == 5)
	    {
	      send_to_all(FLAGS_WARN, "%s", notice0);
	      tcm_log(L_NORM, "  [etc.]\n");
	    }
	}

    }
}
#endif

/*
 * update_nick
 * 
 * inputs -	- original nick
 *		- new nick
 * output	- NONE
 * side effects - A user has changed nicks. update the nick
 */

void
update_nick(char *nick1, char *nick2)
{
  struct hashrec *find;

  for (find = domain_table[hash_func(nick1)]; find; find = find->next)
    {
      if (strcmp(find->info->nick, nick1) == 0)
	{
	  strlcpy(find->info->nick, nick2, MAX_NICK);
	}
    }
}

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
  char buff[MAX_BUFF], *p, *q;
  char *nick, *by, *reason;
  struct hashrec *userptr;
  int i=0;

  if ((p = strstr(server_notice, ". From")) == NULL)
    return;
  *p = '\0';
  p+=7;
  if ((nick = strrchr(server_notice, ' ')) == NULL)
    return;
  ++nick;
  by = p;
  if ((p = strchr(by, ' ')) == NULL)
    return;
  *p = '\0';
  if (strchr(by, '.')) /* ignore kills by servers */
    return;
  p+=7;
    if ((q = strchr(p, ' ')) == NULL)
     return;
  q+=2;
  if ((p = strrchr(q, ')')) == NULL)
    return;
  *p = '\0';
  reason = q;
  for (i=0;i<HASHTABLESIZE;++i)
    {
      for (userptr = domain_table[i]; userptr; userptr = userptr->next)
	{
	  if (!strcasecmp(nick, userptr->info->nick))
	    {
/* XXX FIX THIS FAST */
char hack[128];
sprintf(hack,"%s killed by %s: %s", nick, by, reason); 
kline_report(hack);
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

struct sortarray sort[MAXDOMAINS+1];

void 
report_domains(int sock,int num)
{
  struct hashrec *userptr;
  int inuse = 0;
  int i;
  int j;
  int maxx;
  int found;
  int foundany = NO;

  for (i = 0; i < HASHTABLESIZE; i++)
    {
      for (userptr = domain_table[i]; userptr; userptr = userptr->next)
        {
          for (j=0; j < inuse; ++j)
            {
              if (!strcasecmp(userptr->info->domain,
			      sort[j].domainrec->info->domain))
                break;
            }

          if ((j == inuse) && (inuse < MAXDOMAINS))
            {
              sort[inuse].domainrec = userptr;
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
        if (sort[i].count > maxx)
          {
            found = i;
            maxx = sort[i].count;
          }
      if (found == -1)
        break;
      if (!foundany)
        {
          foundany = YES;
          print_to_socket(sock,"Domains with most users on the server:\n");
        }

      print_to_socket(sock,"  %-40s %3d users\n",
           sort[found].domainrec->info->domain, maxx);
      sort[found].count = 0;
    }

  if (!foundany)
    {
      print_to_socket(sock, "No domains have %d or more users.\n",num);
    }
  else
    {
      print_to_socket(sock, "%d domains found\n", inuse);
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
list_class(int sock,char *class_to_find,int total_only)
{
  struct hashrec *userptr;
  int i;
  int num_found=0;
  int num_unknown=0;

  for (i=0; i < HASHTABLESIZE; ++i)
    {
      for (userptr = domain_table[i]; userptr; userptr = userptr->next)
        {
          if(!strcmp(userptr->info->class, "unknown"))
            num_unknown++;

          if (!strcasecmp(class_to_find, userptr->info->class))
            {
              if(!num_found++)
                {
                  if(!total_only)
                    {
                      print_to_socket(sock,
                           "The following clients are in class %s\n",
                           class_to_find);
                    }
                }
              if(!total_only)
                {
                  print_to_socket(sock, "  %s (%s@%s)\n", userptr->info->nick,
				  userptr->info->user, userptr->info->host);
                }
            }
        }
    }

  if (num_found)
    print_to_socket(sock,
         "%d are in class %s\n", num_found, class_to_find );
  else
    print_to_socket(sock,
         "Nothing found in class %s\n", class_to_find);
  print_to_socket(sock,"%d unknown class\n", num_unknown);
}

/*
 * list_nicks()
 *
 * inputs       - socket to reply on, nicks to search for,regexpression?
 * output       - NONE
 * side effects -
 */

void 
list_nicks(int sock,char *nick,int regex)
{
  struct hashrec *userptr;
#ifdef HAVE_REGEX_H
  regex_t reg;
  regmatch_t m[1];
#endif
  int i=0;
  int numfound=0;

#ifdef HAVE_REGEX_H
  if (regex == YES && (i=regcomp((regex_t *)&reg, nick, 1)))
  {
    char errbuf[1024];
    regerror(i, (regex_t *)&reg, errbuf, 1024); 
    print_to_socket(sock, "Error compiling regular expression: %s\n", errbuf);
    return;
  }
#endif

  for (i=0; i<HASHTABLESIZE; ++i)
    {
      for (userptr = domain_table[i]; userptr; userptr = userptr->next)
        {
#ifdef HAVE_REGEX_H
          if ((regex == YES &&
               !regexec((regex_t *)&reg, userptr->info->nick,1,m,REGEXEC_FLAGS))
              || (regex == NO && !match(nick, userptr->info->nick)))
#else
          if (!match(nick, userptr->info->nick))
#endif
            {
              if(!numfound)
                {
                  print_to_socket(sock,
				  "The following clients match %.150s:\n",nick);
                }
              numfound++;

              print_to_socket(sock,
			      "  %s (%s@%s) {%s}\n",
			      userptr->info->nick, userptr->info->user,
			      userptr->info->host, userptr->info->class);
            }
        }
    }

  if (numfound)
    print_to_socket(sock,
		    "%d matches for %s found\n",numfound,nick);
  else
    print_to_socket(sock,
		    "No matches for %s found\n",nick);
}

/*
 * list_users()
 *
 * inputs       - socket to reply on
 *              - uhost to match on
 *              - regex or no?
 *		- list to save results to
 * output       - NONE
 * side effects -
 */

void 
list_users(int sock,char *userhost,int regex)
{
  struct hashrec *ipptr;
#ifdef HAVE_REGEX_H
  regex_t reg;
  regmatch_t m[1];
#endif
  char uhost[1024];
  int i;
  int numfound = 0;

#ifdef HAVE_REGEX_H
  if (regex == YES && (i = regcomp((regex_t *)&reg, userhost, 1)))
  {
    char errbuf[1024];
    regerror(i, (regex_t *)&reg, errbuf, 1024); 
    print_to_socket(sock, "Error compiling regular expression: %s\n",
		    errbuf);
    return;
  }
#endif
  if (!strcmp(userhost,"*") || !strcmp(userhost,"*@*"))
    {
      print_to_socket(sock,
"Listing all users is not recommended.  To do it anyway, use '.list ?*@*'.\n");
      return;
    }

  for (i=0; i < HASHTABLESIZE; ++i)
  {
    for (ipptr = ip_table[i]; ipptr; ipptr = ipptr->next)
    {
      snprintf(uhost, 1024, "%s@%s", ipptr->info->user, ipptr->info->host);
#ifdef HAVE_REGEX_H
      if ((regex == YES &&
          !regexec((regex_t *)&reg, uhost, 1, m, REGEXEC_FLAGS)) 
          || (regex == NO && !match(userhost, uhost)))
#else
      if (!match(userhost, uhost))
#endif 
      {
        if (!numfound++)
          print_to_socket(sock, "The following clients match %s:\n", userhost);

        if (ipptr->info->ip_host[0] > '9' || ipptr->info->ip_host[0] < '0')
          print_to_socket(sock, "  %s (%s@%s) {%s}\n", ipptr->info->nick,
               ipptr->info->user, ipptr->info->host, ipptr->info->class);
        else
          print_to_socket(sock, "  %s (%s@%s) [%s] {%s}\n", ipptr->info->nick,
			  ipptr->info->user, ipptr->info->host,
			  ipptr->info->ip_host, ipptr->info->class);
      }
    }
  }
  if (numfound > 0)
    print_to_socket(sock, "%d match%sfor %s found\n", numfound,
		    (numfound > 1 ? "es " : " "), userhost);
  else
    print_to_socket(sock, "No matches for %s found\n", userhost);
}

void kill_list_users(int sock, char *userhost, char *reason, int regex)
{
  struct hashrec *userptr;
#ifdef HAVE_REGEX_H
  regex_t reg;
  regmatch_t m[1];
#endif
  char fulluh[MAX_USERHOST+1];
  int i, numfound=0;

#ifdef HAVE_REGEX_H
  if (regex == YES && (i=regcomp((regex_t *)&reg, userhost, 1)))
    {
      char errbuf[REGEX_SIZE];
      regerror(i, (regex_t *)&reg, errbuf, REGEX_SIZE);
      print_to_socket(sock, "Error compiling regular expression: %s\n", errbuf);
      return;
    }
#endif

  for (i=0; i<HASHTABLESIZE; ++i)
    {
      for (userptr = domain_table[i]; userptr; userptr=userptr->next)
	{
	  snprintf(fulluh, sizeof(fulluh), "%s@%s",
		   userptr->info->user, userptr->info->host);
#ifdef HAVE_REGEX_H
	  if ((regex == YES &&
	       !regexec((regex_t *)&reg, fulluh, 1, m, REGEXEC_FLAGS))
	      || (regex == NO && !match(userhost, fulluh)))
#else
	    if (!match(userhost, fulluh))
#endif
	      {
		if (!numfound++)
		  tcm_log(L_NORM, "killlisted %s\n", fulluh);
		print_to_server("KILL %s :%s", userptr->info->nick, reason);
	      }
	}
    }
  if (numfound > 0)
    print_to_socket(sock, "%d matches for %s found\n", userhost);
  else
    print_to_socket(sock, "No matches for %s found\n", userhost);
}

/*
 * report_mem()
 * inputs       - socket to report to
 * output       - none
 * side effects - rough memory usage is reported
 */

void report_mem(int sock)
{
  int i;
  struct hashrec *current;
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
  unsigned long total_userentry=0L;
  int count_userentry=0;

  /*  host_table,domain_table,ip_table */

  for (i = 0; i < HASHTABLESIZE; i++)
    {
      for (current = host_table[i]; current; current = current->next)
        {
          total_host_table += sizeof(struct hashrec);
          count_host_table++;

          total_userentry += sizeof(struct userentry);
          count_userentry++;
        }
    }

  for (i = 0; i < HASHTABLESIZE; i++)
    {
      for( current = domain_table[i]; current; current = current->next)
        {
          total_domain_table += sizeof(struct hashrec);
          count_domain_table++;
        }
    }

#ifdef VIRTUAL
  for (i = 0; i < HASHTABLESIZE; i++)
    {
      for (current = ip_table[i]; current; current = current->next)
        {
          total_ip_table += sizeof(struct hashrec);
          count_ip_table++;
        }
    }
#endif

  for (i = 0; i < HASHTABLESIZE; i++)
    {
      for (current = user_table[i]; current; current = current->next)
        {
          total_user_table += sizeof(struct hashrec);
          count_user_table++;
        }
    }

  print_to_socket(sock,"Total host_table memory %lu/%d entries\n",
		  total_host_table, count_host_table);

  print_to_socket(sock, "Total usertable memory %lu/%d entries\n",
		  total_user_table, count_user_table);

  print_to_socket(sock, "Total domaintable memory %lu/%d entries\n",
		  total_domain_table, count_domain_table);

  print_to_socket(sock, "Total iptable memory %lu/%d entries\n",
		  total_ip_table, count_ip_table);

  print_to_socket(sock, "Total user entry memory %lu/%d entries\n",
		  total_userentry, count_userentry);

  print_to_socket(sock,"Total memory in use %lu\n",
		  total_host_table + total_domain_table +
		  total_ip_table + total_userentry );
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
    if (*p == '.')
      found_dots++;
    
    if (found_dots == 3)
    {
      *p = '\0';
      break;
    }
    p++;
  }
}
#endif
