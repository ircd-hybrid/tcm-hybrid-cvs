/*
 *  tcm-hybrid: an advanced irc connection monitor
 *  conf.c: config file loading and sanity checking
 *
 *  Copyright (C) 2004 by William Bierman and the Hybrid Development Team
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307
 *  USA
 *
 *    $Id: conf.c,v 1.3 2004/06/10 23:20:23 bill Exp $
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include "tcm.h"
#include "conf.h"
#include "userlist.h"
#include "tcm_io.h"
#include "logging.h"

extern int lineno;
extern char linebuf[];
extern char conffilebuf[BUFFERSIZE];

extern int yyparse();

static char *
strip_tabs(char *dest, const unsigned char *src, size_t len)
{
  char *d = dest;

  /* Sanity check; we don't want anything nasty... */
  assert(dest != NULL);
  assert(src  != NULL);

  if (dest == NULL || src == NULL)
    return(NULL);

  while (*src && (len > 0))
  {
    if (*src == '\t')
      *d++ = ' ';  /* Translate the tab into a space */
    else
      *d++ = *src; /* Copy src to dst */

    ++src;
    --len;
  }

  *d = '\0'; /* Null terminate, thanks and goodbye */
  return(dest);
}

static void
read_conf(FILE *file)
{
  lineno = 0;
  yyparse();
}

int
conf_fgets(char *lbuf, unsigned int max_size, FILE *in)
{
  char *buff;

  if ((buff = fgets(lbuf, max_size, in)) == NULL)
    return 0;

  return strlen(lbuf);
}

int
conf_fatal_error(const char *msg)
{
  return 0;
}

void
yyerror(const char *msg)
{
  char newlinebuf[BUFFERSIZE];

  strip_tabs(newlinebuf, (const unsigned char *)linebuf, strlen(linebuf));

  send_to_all(NULL, FLAGS_ADMIN, "\"%s\", line %d: %s: %s",
              conffilebuf, lineno + 1, msg, newlinebuf);
  tcm_log(L_ERR, "\"%s\", line %d: %s: %s",
          conffilebuf, lineno + 1, msg, newlinebuf);
}

void
read_conf_files(int cold)
{
  const char *filename = CONFIG_FILE;

  conf_file_in = NULL;
  strlcpy(conffilebuf, filename, sizeof(conffilebuf));

  if ((conf_file_in = fopen(filename, "r")) == NULL)
  {
    if (cold)
    { 
      fprintf(stderr, "Failed in reading configuration file %s\n", filename);
      exit(-1);
    }
    else
    {
      send_to_all(NULL, FLAGS_ADMIN, "Can't open '%s' - aborting rehash!",
                  filename);
      return;
    }
  }

  read_conf(conf_file_in);
  fclose(conf_file_in);
}
