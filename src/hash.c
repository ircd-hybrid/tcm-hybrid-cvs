/* hash.c
 *
 * $Id: hash.c,v 1.3 2002/05/28 03:26:58 db Exp $
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
#include "commands.h"
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

static int hash_func(char *string);
static char* find_domain(char* domain);
static void check_host_clones(char *);
#ifdef VIRTUAL
static void check_virtual_host_clones(char *);
#endif

static struct hashrec *usertable[HASHTABLESIZE];
static struct hashrec *hosttable[HASHTABLESIZE];
static struct hashrec *domaintable[HASHTABLESIZE];
static struct hashrec *iptable[HASHTABLESIZE];

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

  while(ptr != NULL)
    {
      next_ptr = ptr->collision;

      if(ptr->info->link_count > 0)
        ptr->info->link_count--;

      if(ptr->info->link_count == 0)
        {
          xfree(ptr->info);
        }

      xfree(ptr);
      ptr = next_ptr;
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
      ptr = usertable[i];
      free_hash_links(ptr);
      usertable[i] = NULL;

      ptr = hosttable[i];
      free_hash_links(ptr);
      hosttable[i] = NULL;

      ptr = domaintable[i];
      free_hash_links(ptr);
      domaintable[i] = NULL;

#ifdef VIRTUAL
      ptr = iptable[i];
      free_hash_links(ptr);
      iptable[i] = NULL;
#endif
    }
  /* XXX should not be here ! */
  free_bothunt();
}


/*
 * find_nick
 *
 * Returns a hashrec for the given nick, or NULL if not found
 *
 */

struct hashrec *
find_nick(const char * nick)
{
  int i;
  struct hashrec * userptr;
  if (nick == NULL)
    return (NULL);

  for (i=0;i<HASHTABLESIZE;++i)
    {
      for(userptr = domaintable[i]; userptr; userptr = userptr->collision)
	{
	  if (!wldcmp((char *)nick, userptr->info->nick))
	    return userptr;
	}
    }
  return (NULL);
}

/*
 * find_host
 *
 * Returns first hashrec for the given host, or NULL if not found
 *
 */

struct hashrec *
find_host(const char * host)
{
  int i;
  struct hashrec * userptr;

  if (host == NULL)
    return (NULL);

  for (i=0; i<HASHTABLESIZE; ++i)
    {
      for(userptr = domaintable[i]; userptr; userptr = userptr->collision)
	{
	  if (!wldcmp((char *)host, userptr->info->host))
	    return userptr;
	}
    }
  return (NULL);
}

/*
 * addtohash
 * 
 * inputs	- pointer to hashtable to add to
 *		- pointer to key being used for hash
 *		- pointer to item being added to hash
 * output	- NONE
 * side effects	- adds an entry to given hash table
 */
void
addtohash(struct hashrec *table[],char *key,struct userentry *item)
{
  int ind;
  struct hashrec *newhashrec;

  ind = hash_func(key);
  newhashrec = (struct hashrec *)xmalloc(sizeof(struct hashrec));

  newhashrec->info = item;
  newhashrec->collision = table[ind];
  table[ind] = newhashrec;
}


/*
 * removefromhash()
 *
 * inputs	- pointer to hashtable to remove entry from
 *		- pointer to key being used for hash
 *		- pointer to hostname to match before removal
 *		- pointer to username to match before removal
 *		- pointer to nickname to match before removal
 * output	- NONE
 * side effects	- adds an entry to given hash table
 */

int
removefromhash(struct hashrec *table[],
		    char *key,
		    char *hostmatch,
		    char *usermatch,
		    char *nickmatch)
{
  int ind;
  struct hashrec *find, *prev;

  ind = hash_func(key);
  find = table[ind];
  prev = NULL;

  while (find)
  {
    if ((!hostmatch || !strcmp(find->info->host,hostmatch)) &&
	(!usermatch || !strcmp(find->info->user,usermatch)) &&
	(!nickmatch || !strcmp(find->info->nick,nickmatch)))
    {
      if (prev)
	prev->collision = find->collision;
      else
	table[ind] = find->collision;

      if (find->info->link_count > 0)
      {
	find->info->link_count--;
	if (find->info->link_count == 0)
	  {
            xfree(find->info);
	  }
      }

      xfree(find);
      return 1;		/* Found the item */
    }
    prev = find;
    find = find->collision;
  }
  return (0);
}

/*
 * adduserhost()
 * 
 * inputs	- pointer to struct plus_c_info
 * 		- from a trace YES or NO
 * 		- is this user an oper YES or NO
 * output	- NONE
 * side effects	-
 * 
 * These days, its better to show host IP's as class C
 */

void
adduserhost(struct plus_c_info *userinfo, int fromtrace, int is_oper)
{
  struct userentry *newuser;
  char *domain;
#ifdef VIRTUAL
  int  found_dots;
  char *p;
#endif

#if defined(DETECT_WINGATE) || defined(DETECT_SOCKS) || defined(DETECT_SQUID)
  if (!doingtrace)
    user_signon(userinfo);
#endif

  newuser = (struct userentry *)xmalloc(sizeof(struct userentry));

  strlcpy(newuser->nick, userinfo->nick, MAX_NICK);
  strlcpy(newuser->user,userinfo->user,MAX_NICK);
  strlcpy(newuser->host,userinfo->host,MAX_HOST);
  if (userinfo->ip[0])
    strlcpy(newuser->ip_host,userinfo->ip,MAX_IP);
  else
    strcpy(newuser->ip_host,"0.0.0.0");

#ifdef VIRTUAL
  /* well, no such thing as a class c , but it will do */
  if (userinfo->ip)
    strcpy(newuser->ip_class_c,userinfo->ip);
  else
    newuser->ip_class_c[0] = '\0';

  p = newuser->ip_class_c;

  found_dots = 0;
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
#endif

  newuser->connecttime = (fromtrace ? 0 : time(NULL));
  newuser->reporttime = 0;

#ifdef VIRTUAL
  if (newuser->ip_class_c[0])
    newuser->link_count = 4;
  else
    newuser->link_count = 3;
#else
  newuser->link_count = 3;
#endif

  newuser->isoper = is_oper;
  strcpy(newuser->class, userinfo->class);

  /* Determine the domain name */
  domain = find_domain(userinfo->host);

  strncpy(newuser->domain, domain, MAX_HOST);
  newuser->domain[MAX_HOST-1] = '\0';

  /* Add it to the hash tables */
  addtohash(usertable, userinfo->user, newuser);
  addtohash(hosttable, userinfo->host, newuser);
  addtohash(domaintable, domain, newuser);

#ifdef VIRTUAL
  if (newuser->ip_class_c[0])
    addtohash(iptable, newuser->ip_class_c, newuser);
#endif

  /* Clonebot check */
  if (!fromtrace)
  {
    check_host_clones(userinfo->host);
#ifdef VIRTUAL
    check_virtual_host_clones(newuser->ip_class_c);
#endif
    check_reconnect_clones(userinfo->host);
  }
}

/*
 * updatehash
 *
 * inputs	- has table to update
 *		- key to use
 *		- nick1, nick2 nick changes
 * output	- NONE
 * side effects	- user entry nick is updated if found
 */

void
updatehash(struct hashrec *table[],
		       char *key,char *nick1,char *nick2)
{
  struct hashrec *find;

  for (find = table[hash_func(key)]; find; find = find->collision)
  {
    if (strcmp(find->info->nick,nick1) == 0)
    {
      strncpy(find->info->nick,nick2,MAX_NICK);
    }
  }
}

/*
 * removeuserhost()
 * 
 * inputs	- nick
 * 		- pointer to struct plus_c_info
 * output	- NONE
 * side effects	- 
 */

void
removeuserhost(char *nick, struct plus_c_info *userinfo)
{
#ifdef VIRTUAL
  int  found_dots;
  char ip_class_c[MAX_IP];
  char *p;
#endif
  char *domain;

  /* Determine the domain name */
  domain = find_domain(userinfo->host);

  if (!removefromhash(hosttable,
		      userinfo->host,
		      userinfo->host,
		      userinfo->user,
		      nick))
    if (!removefromhash(hosttable,
			userinfo->host,
			userinfo->host,
			userinfo->user,NULL))
    {
      if (config_entries.debug && outfile)
      {
	fprintf(outfile,"*** Error removing %s!%s@%s from host table!\n",
		nick,
		userinfo->user,
		userinfo->host);
      }
    }

  if (!removefromhash(domaintable,
		      domain,
		      userinfo->host,
		      userinfo->user,
		      nick))

    if (!removefromhash(domaintable,
			domain,
			userinfo->host,
			userinfo->user,
			NULL))
    {
      if (config_entries.debug && outfile)
      {
	fprintf(outfile,"*** Error removing %s!%s@%s from domain table!\n",
		nick,
		userinfo->user,
		userinfo->host);
      }
    }

  if (!removefromhash(usertable,
		      userinfo->user,
		      userinfo->host,
		      userinfo->user,
		      nick))
    if (!removefromhash(usertable,
			userinfo->user,
			userinfo->host,
			userinfo->user,
			NULL))
    {
      if (config_entries.debug && outfile)
      {
	fprintf(outfile,"*** Error removing %s!%s@%s from user table!\n",
		nick,
		userinfo->user,
		userinfo->host);
      }
    }

#ifdef VIRTUAL
  /* well, no such thing as a class c , but it will do */
  if (userinfo->ip)
    strcpy(ip_class_c,userinfo->ip);
  else
    ip_class_c[0] = '\0';

  p = ip_class_c;
  found_dots = 0;
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

  if (config_entries.debug && outfile)
  {
    fprintf(outfile,
	    "about to removefromhash ip_class_c = [%s]\n", ip_class_c);
    fprintf(outfile,
	    "userinfo->host [%s] userinfo->user [%s] nick [%s]\n",
	    userinfo->host,userinfo->user,nick);
  }

  if (!removefromhash(iptable,
		      ip_class_c,
		      userinfo->host,
		      userinfo->user,
		      nick))
    if (!removefromhash(iptable,
			ip_class_c,
			userinfo->host,
			userinfo->user,
			NULL))
    {
      if (config_entries.debug && outfile)
      {
	fprintf(outfile,
		"*** Error removing %s!%s@%s [%s] from iptable table!\n",
		nick,
		userinfo->user,
		userinfo->host,
		ip_class_c);
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

int
hash_func(char *string)
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
  int is_legal_ip = YES;
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

      if ( i > (MAX_IP-2))
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

  for (find = hosttable[ind]; find; find = find->collision)
  {
    if ((strcmp(find->info->host,host) == 0)&&
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
    report(SEND_WARN,
	   CHANNEL_REPORT_CLONES,
	   "%d more possible clones (%d total) from %s:\n",
	   clonecount, clonecount+reportedclones, host);

    tcm_log(L_NORM, "%d more possible clones (%d total) from %s:\n",
	clonecount, clonecount+reportedclones, host);
  }
  else
  {
    report(SEND_WARN,
	   CHANNEL_REPORT_CLONES,
	   "Possible clones from %s detected: %d connects in %d seconds\n",
	   host, clonecount, now - oldest);

    tcm_log(L_NORM, 
	    "Possible clones from %s detected: %d connects in %d seconds\n",
	    host, clonecount, now - oldest);
  }

  for(find = hosttable[ind],clonecount = 0; find; find = find->collision)
  {
    if ((strcmp(find->info->host,host) == 0) &&
	(now - find->info->connecttime < CLONECONNECTFREQ + 1) &&
	find->info->reporttime == 0)
    {
      ++clonecount;
      tmrec = localtime(&find->info->connecttime);

      if (clonecount == 1)
      {
	(void)snprintf(notice1, MAX_BUFF-1,
		       "  %s is %s@%s (%2.2d:%2.2d:%2.2d)\n",
		       find->info->nick, 
		       find->info->user,
		       find->info->host,
		       tmrec->tm_hour, tmrec->tm_min, tmrec->tm_sec);
      }
      else
      {
        memset((char *)&notice0, 0, sizeof(notice0));
	(void)snprintf(notice0, MAX_BUFF-1,
		       "  %s is %s@%s (%2.2d:%2.2d:%2.2d)\n",
		       find->info->nick,
		       find->info->user,
		       find->info->host,
		       tmrec->tm_hour, tmrec->tm_min, tmrec->tm_sec);
      }

      current_identd = YES;
      different = NO;

      if (clonecount == 1)
	last_user = find->info->user;
      else if (clonecount == 2)
      {
	char *current_user;
	
	if ( *last_user == '~' )
	{
	  last_user++;
	}

	current_user = find->info->user;
	if ( *current_user != '~' )
	  current_identd = YES;
	else
	  ++current_user;

	if (strcmp(last_user,current_user) && current_identd)
	  different = YES;

	handle_action(act_clone, current_identd, 
		      find->info->nick, find->info->user,
		      find->info->host, find->info->ip_host, 0);
      }

      find->info->reporttime = now;
      if (clonecount == 2)
      {
        if (notice1[0])
        {
  	  report(SEND_WARN, CHANNEL_REPORT_CLONES, "%s", notice1);
	  tcm_log(L_NORM, "%s", notice1);
        }
	/* I haven't figured out why all these are nessecary, but I know they are */
	if (notice0[0])
        {
          report(SEND_WARN, CHANNEL_REPORT_CLONES, "%s", notice0);
  	  tcm_log(L_NORM, "%s", notice0);
        }
      }
      else if (clonecount < 5)
      {
        if (notice0[0])
        {
	  report(SEND_WARN, CHANNEL_REPORT_CLONES, "%s", notice0);
	  tcm_log(L_NORM, "%s", notice0);
        }
      }
      else if (clonecount == 5)
      {
        if (notice0[0])
        {
	  send_to_all( SEND_WARN, "%s", notice0);
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

  for (find = iptable[ind]; find; find = find->collision)
    {
      if (!strcmp(find->info->ip_class_c,ip_class_c) &&
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
      report(SEND_WARN,
	     CHANNEL_REPORT_VCLONES,
	     "%d more possible virtual host clones (%d total) from %s.*:\n",
	     clonecount, clonecount+reportedclones, ip_class_c);

      tcm_log(L_NORM, 
	      "%d more possible virtual host clones (%d total) from %s.*:\n",
	      clonecount, clonecount+reportedclones, ip_class_c);
    }
  else
    {
      report(SEND_WARN,
	     CHANNEL_REPORT_VCLONES,
	     "Possible virtual host clones from %s.* detected: %d connects in %d seconds\n",
	     ip_class_c, clonecount, now - oldest);

      tcm_log(L_NORM,
"Possible virtual host clones from %s.* detected: %d connects in %d seconds\n",
	      ip_class_c, clonecount, now - oldest);
    }

  clonecount = 0;

  memset(&user, 0, sizeof(user));
  for (find = iptable[ind]; find; find = find->collision)
    {
      if (!strcmp(find->info->ip_class_c,ip_class_c) &&
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
			    find->info->nick,
			    find->info->user,
			    find->info->host,
			    find->info->ip_host,
			    tmrec->tm_hour,
			    tmrec->tm_min,
			    tmrec->tm_sec);
	    }
          else
	    {
	      (void)snprintf(notice0,MAX_BUFF - 1,
                            "  %s is %s@%s [%s] (%2.2d:%2.2d:%2.2d)\n",
			    find->info->nick,
			    find->info->user,
			    find->info->host,
			    find->info->ip_host,
			    tmrec->tm_hour,
			    tmrec->tm_min,
			    tmrec->tm_sec);
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
	      report(SEND_WARN, CHANNEL_REPORT_VCLONES, "%s", notice1);
	      tcm_log(L_NORM, "%s", notice1);

	      report(SEND_WARN, CHANNEL_REPORT_VCLONES, "%s", notice0);
	      tcm_log(L_NORM, "%s", notice0);
	    }
	  else if (clonecount < 5)
	    {
	      report(SEND_WARN, CHANNEL_REPORT_VCLONES, "%s", notice0);
	      tcm_log(L_NORM, "%s", notice0);
	    }
	  else if (clonecount == 5)
	    {
	      send_to_all(SEND_WARN, "%s", notice0);
	      tcm_log(L_NORM, "  [etc.]\n");
	    }
	}

    }
}
#endif



/*
 * updateuserhost()
 * 
 * inputs -	- original nick
 *		- new nick
 * 		- user@host of nick
 * output	- NONE
 * side effects - A user has changed nicks. update the nick
 *	          as seen by the hosttable. This way, list command
 *	          will show the updated nick.
 */

void
updateuserhost(char *nick1,char *nick2,char *userhost)
{
  char *host;

  if ((host = strchr(userhost,'@')) == NULL)
    return;

  *host = '\0';
  host++;
  
  updatehash(hosttable,host,nick1,nick2);
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
    for (userptr = domaintable[i]; userptr; userptr = userptr->collision)
    {
      if (!strcasecmp(nick, userptr->info->nick))
      {
        i = -1;
        break;
      }
    }
    if (i == -1)
      break;
  }
  if (i != -1)
    return;
  snprintf(buff, sizeof(buff), "%s killed by %s: %s", nick, by, reason);
  kline_report(buff);
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

          send_to_all(SEND_WARN,
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

#ifdef VIRTUAL
void
report_vbots(int sock,int nclones)
{
  struct hashrec *userptr,*top,*temp;
  int numfound,i;
  int foundany = NO;

  nclones-=2;  /* ::sigh:: I have no idea */
  for (i=0;i<HASHTABLESIZE;++i)
    {
      for(top = userptr = iptable[i]; userptr;
	  userptr = userptr->collision)
        {
          /* Ensure we haven't already checked this user & domain */
          for(temp = top, numfound = 0; temp != userptr;
	      temp = temp->collision)
            {
              if (!strcmp(temp->info->user,userptr->info->user) &&
                  !strcmp(temp->info->ip_class_c,userptr->info->ip_class_c))
                break;
            }

          if (temp == userptr)
            {
              for (temp = temp->collision; temp; temp = temp->collision)
                {
                  if (!strcmp(temp->info->user,userptr->info->user) &&
                      !strcmp(temp->info->ip_class_c,userptr->info->ip_class_c))
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
                  numfound++;   /* - zaph and next line*/
                  print_to_socket(sock,
                       " %s %2d connections -- %s@%s.* {%s}\n",
                       (numfound-nclones > 2) ? "==>" :
                       "   ",numfound,userptr->info->user,
                       userptr->info->ip_class_c,
                       userptr->info->class);
                }
            }
        }
    }
  if (!foundany)
    print_to_socket(sock, "No multiple logins found.\n");
}
#endif

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
      for( userptr = hosttable[i]; userptr; userptr = userptr->collision )
        {
          for (j=0;j<inuse;++j)
            {
              if (!strcasecmp(userptr->info->domain,sort[j].domainrec->domain))
                break;
            }

          if ((j == inuse) && (inuse < MAXDOMAINS))
            {
              sort[inuse].domainrec = userptr->info;
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
           sort[found].domainrec->domain,maxx);
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
      for(userptr = domaintable[i]; userptr; userptr = userptr->collision)
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
                  print_to_socket(sock,
                       "  %s (%s@%s)\n",
                       userptr->info->nick,
                       userptr->info->user,userptr->info->host);
                }
            }
        }
    }

  if (num_found)
    print_to_socket(sock,
         "%d are in class %s\n", num_found, class_to_find );
  else
    print_to_socket(sock,
         "Nothing found in class %s\n", class_to_find );
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
      for(userptr = domaintable[i]; userptr; userptr = userptr->collision)
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
                   userptr->info->nick,
                   userptr->info->user,userptr->info->host,
                   userptr->info->class);
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
    for (ipptr = iptable[i]; ipptr; ipptr = ipptr->collision)
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
               ipptr->info->user, ipptr->info->host, ipptr->info->ip_host,
               ipptr->info->class);
      }
    }
  }
  if (numfound > 0)
    print_to_socket(sock, "%d match%sfor %s found\n", numfound,
		    (numfound > 1 ? "es " : " "), userhost);
  else
    print_to_socket(sock, "No matches for %s found\n", userhost);
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
  struct hashrec *ipptr;
#ifdef HAVE_REGEX_H
  regex_t reg;
  regmatch_t m[1];
#endif
  char uhost[1024];
  int i,numfound = 0;

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
    for(ipptr = iptable[i]; ipptr; ipptr = ipptr->collision)
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
        if (!numfound++)
          print_to_socket(sock, "The following clients match %s:\n", userhost);

        print_to_socket(sock, "  %s (%s@%s) [%s] {%s}\n", ipptr->info->nick,
             ipptr->info->user, ipptr->info->host, ipptr->info->ip_host,
             ipptr->info->class);
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

  for (i=0;i<HASHTABLESIZE;++i)
  {
    for (userptr = domaintable[i]; userptr; userptr = userptr->collision)
    {
      snprintf(fulluh, sizeof(fulluh), "%s@%s", userptr->info->user,
               userptr->info->host);
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
  if (!foundany)
    print_to_socket(sock, "No multiple logins found.\n");
}

/*
 * report_multi()
 *
 * inputs       - socket to print out
 * output       - NONE
 * side effects -
 */

void report_multi(int sock,int nclones)
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

void report_multi_user(int sock,int nclones)
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

  if (!foundany)
    {
      print_to_socket(sock, "No multiple logins found.\n");
    }
}

/*
 * report_multi_virtuals()
 *
 * inputs       - socket to print out
 *              - number to consider as clone
 * output       - NONE
 * side effects -
 */

#ifdef VIRTUAL
void report_multi_virtuals(int sock,int nclones)
{
  struct hashrec *userptr;
  struct hashrec *top;
  struct hashrec *temp;
  int numfound;
  int i;
  int foundany = 0;

  if(!nclones)
    nclones = 5;

  nclones-=1;
  for (i=0;i<HASHTABLESIZE;++i)
    {
      for (top = userptr = iptable[i]; userptr; userptr = userptr->collision)
        {
          numfound = 0;

          for (temp = top; temp != userptr; temp = temp->collision)
            {
              if (!strcmp(temp->info->ip_class_c,userptr->info->ip_class_c))
                break;
            }

          if (temp == userptr)
            {
              numfound=1;
              for(temp = temp->collision; temp; temp = temp->collision)
                {
                  if (!strcmp(temp->info->ip_class_c,
                              userptr->info->ip_class_c))
                    numfound++; /* - zaph & Dianora :-) */
                }

              if (numfound > nclones)
                {
                  if (!foundany)
                    {
                      print_to_socket(sock,
                           "Multiple clients from the following ip blocks:\n");
                      foundany = YES;
                    }

                  print_to_socket(sock,
                       " %s %2d connections -- %s.*\n",
                       (numfound-nclones > 3) ? "==>" : "   ",
                       numfound,
                       userptr->info->ip_class_c);
                }
            }
        }
    }

  if (!foundany)
    print_to_socket(sock, "No multiple virtual logins found.\n");
}
#endif

/*
 * report_mem()
 * inputs       - socket to report to
 * output       - none
 * side effects - rough memory usage is reported
 */
void report_mem(int sock)
{
  struct hashrec *current;
  int i;
  unsigned long total_hosttable=0L;
  int count_hosttable=0;
  unsigned long total_domaintable=0L;
  int count_domaintable=0;
  unsigned long total_iptable=0L;
  int count_iptable=0;
  unsigned long total_usertable=0L;
  int count_usertable=0;
  unsigned long total_userentry=0L;
  int count_userentry=0;

  /*  hosttable,domaintable,iptable */

  for(i = 0; i < HASHTABLESIZE; i++)
    {
      for(current = hosttable[i]; current; current = current->collision)
        {
          total_hosttable += sizeof(struct hashrec);
          count_hosttable++;

          total_userentry += sizeof(struct userentry);
          count_userentry++;
        }
    }

  for(i = 0; i < HASHTABLESIZE; i++)
    {
      for(current = domaintable[i]; current; current = current->collision)
        {
          total_domaintable += sizeof(struct hashrec);
          count_domaintable++;
        }
    }

#ifdef VIRTUAL
  for(i = 0; i < HASHTABLESIZE; i++)
    {
      for(current = iptable[i]; current; current = current->collision)
        {
          total_iptable += sizeof(struct hashrec);
          count_iptable++;
        }
    }
#endif

  for(i = 0; i < HASHTABLESIZE; i++)
    {
      for(current = usertable[i]; current; current = current->collision)
        {
          total_usertable += sizeof(struct hashrec);
          count_usertable++;
        }
    }

  print_to_socket(sock,"Total hosttable memory %lu/%d entries\n",
       total_hosttable,count_hosttable);

  print_to_socket(sock,"Total usertable memory %lu/%d entries\n",
       total_usertable,count_usertable);

  print_to_socket(sock,"Total domaintable memory %lu/%d entries\n",
       total_domaintable,count_domaintable);

  print_to_socket(sock,"Total iptable memory %lu/%d entries\n",
       total_iptable, count_iptable);

  print_to_socket(sock,"Total user entry memory %lu/%d entries\n",
       total_userentry, count_userentry);

  print_to_socket(sock,"Total memory in use %lu\n",
       total_hosttable + total_domaintable + total_iptable + total_userentry);

  print_to_socket(sock,"Total memory allocated over time %lu\n", totalmem);
  print_to_socket(sock,"Average memory allocated in %lu allocations %lu\n",
	numalloc, totalmem/numalloc);
  print_to_socket(sock,"Average allocated memory not freed %lu in %lu frees\n",
	(totalmem/numalloc)*(numalloc-numfree), numfree);
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

  if (!foundany)
    {
        print_to_socket(sock, "No potential clonebots found.\n");
    }
}

void
init_hash(void)
{
  memset(&usertable,0,sizeof(usertable));
  memset(&hosttable,0,sizeof(usertable));
  memset(&domaintable,0,sizeof(usertable));
#ifdef VIRTUAL
  memset(&iptable,0,sizeof(iptable));
#endif
}
