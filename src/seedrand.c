/*
 * seedrand 0.1
 *
 * Copyright (c) 2002-2003 Bill Jonus
 *
 * $Id: seedrand.c,v 1.7 2003/08/13 02:43:31 joshk Exp $
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "tcm.h"
#include "tcm_io.h"
#include "tools.h"
#include "handler.h"
#include "hash.h"
#include "modules.h"
#include "match.h"
#include "seedrand.h"

#define THRESHOLD 2500

int score(char *);

static int IsConsonant(char);
static int IsLeftBracket(char);
static int IsRightBracket(char);
static int IsLower(char);
static int IsUpper(char);
static int IsSylableEnd(char);
static int IsNumeric(char);

static int find_max_score(int[], int, int);
static void m_seedrand(struct connection *connection_p, int argc, char *argv[]);
struct dcc_command seedrand_msgtab = {
  "seedrand", NULL, {m_unregistered, m_seedrand, m_seedrand}
};

int uses[72]; /* the size of this must be updated as s_all is changed! */
char *s_all		= "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890\\|^_-{[}]`";
char *s_consonants	= "bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ";
char *s_left_brackets	= "{[";
char *s_lower		= "abcdefghijklmnopqrstuvwxyz";
char *s_numerics	= "0123456789";
char *s_right_brackets	= "}]";
char *s_sylable_end	= "bdgjkpqxzBDGJKPQXZ";
char *s_upper		= "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
char *s_vowels		= "aeiouAEIOU";

struct node {
  char string[100];
  int score;
};

static int
IsConsonant(char asc)
{
  if (strchr(s_consonants, asc) != NULL)
    return YES;
  else
    return NO;
}

static int
IsLeftBracket(char asc)
{
  if (strchr(s_left_brackets, asc) != NULL)
    return YES;
  else
    return NO;
}

static int
IsLower(char asc)
{
  if (strchr(s_lower, asc) != NULL)
    return YES;
  else
    return NO;
}

static int
IsNumeric(char asc)
{
  if (strchr(s_numerics, asc) != NULL)
    return YES;
  else
    return NO;
}

static int
IsRightBracket(char asc)
{
  if (strchr(s_right_brackets, asc) != NULL)
    return YES;
  else
    return NO;
}

static int
IsSylableEnd(char asc)
{
  if (strchr(s_sylable_end, asc) != NULL)
    return YES;
  else
    return NO;
}

static int
IsUpper(char asc)
{
  if (strchr(s_upper, asc) != NULL)
    return YES;
  else
    return NO;
}

static int
find_max_score(int scores[], int size, int start)
{
  int a, idx=start;

  for (a=start; a < size; ++a)
  {
    if (scores[a] > scores[idx])
      idx = a;
  }

  return idx;
}

void
init_seedrand()
{
  add_dcc_handler(&seedrand_msgtab);
}

static void
m_seedrand(struct connection *connection_p, int argc, char *argv[])
{
  struct hash_rec *find;
  struct user_entry *results[HASHTABLESIZE], *temp_u;
  int scores[HASHTABLESIZE], temp_s;
  int numfound = 0, score_t, temp, threshold;
  char *match_s = NULL;

  if (argc == 1)
  {
    match_s = "*";
    threshold = THRESHOLD;
  }
  else if (argc == 2)
  {
    if ((threshold = atoi(argv[1])) == 0)
    match_s = argv[1];
    threshold = THRESHOLD;
  }
  else if (argc == 3)
  {
    match_s = argv[1];
    if ((threshold = atoi(argv[2])) == 0)
    {
      send_to_connection(connection_p, "Usage: %s [wildcard nick] [score threshold]",
                         argv[0]);
      return;
    }
  }
  else
  {
    send_to_connection(connection_p, "Usage: %s [wildcard nick] [score threshold]",
                       argv[0]);
    return;
  }

  send_to_connection(connection_p, "Searching %s.  Threshold is %d",
                     match_s, threshold);
  for (temp = 0; temp < HASHTABLESIZE; ++temp)
  {
    for (find = user_table[temp]; find; find = find->next)
    {
      if ((match(match_s, find->info->nick) == 0) && ((score_t = score(find->info->nick)) >= threshold))
      {
        results[numfound] = find->info;
        scores[numfound++] = score_t;
      }
    }
  }

  for (score_t = 0; score_t < numfound; ++score_t)
  {
    temp = find_max_score(scores, numfound, score_t);
    temp_u = results[temp];
    temp_s = scores[temp];

    results[temp] = results[score_t];
    scores[temp] = scores[score_t];
    results[score_t] = temp_u;
    scores[score_t] = temp_s;
  }

  for (score_t = 0; score_t < numfound; ++score_t)
  {
    if (scores[score_t] >= threshold && (results[score_t] != NULL))
    {
      send_to_connection(connection_p, "  %4d -- %s (%s@%s) [%s]", scores[score_t], results[score_t]->nick,
                         results[score_t]->username, results[score_t]->host, results[score_t]->ip_host);
    }
  }
  if (numfound == 0)
    send_to_connection(connection_p, "No matches for %s found.", match_s);
  else if (numfound == 1)
    send_to_connection(connection_p, "1 match for %s found.", match_s);
  else
    send_to_connection(connection_p, "%d matches for %s found.", numfound, match_s);
}

int
score(char *string)
{
  int consonants;
  int hyphens;
  int left_brackets;
  int length;
  int lower;
  int numerics;
  int offset;
  int retval;
  int right_brackets;
  int unique;
  int upper; 
  int vowels;
  char *w, *x;

  assert (string != NULL);

  for (offset = 0; offset < sizeof(uses); ++offset)
    uses[offset] = 0;

  consonants = hyphens = left_brackets = length = lower = numerics = offset = retval = right_brackets = unique = upper = vowels = 0;
  w = x = NULL;

  length = strlen(string);

  if (length <= 3)
  {
#ifdef DEBUGMODE
    printf("Cannot perform seeding on such short strings.  Skipping...\n");
#endif
    return 0;
  }

#ifdef DEBUGMODE
  printf("Computing score for %s ...\n", string);
#endif
  for (w = string; *w != '\0'; ++w)
  {
    if ((x = strchr(s_all, *w)) == NULL)
    {
#ifdef DEBUGMODE
      printf("Invalid character '%c' (asc:%d) in '%s'.  Skipping...\n",
             *w, *w, string);
#endif
      return 0;
    }

    offset = x - s_all;
    if (++uses[offset] == 1)
      ++unique;

    if (IsConsonant(*w))
    {
      ++consonants;
      if (IsConsonant(*(w+1)) && *(w+1) && IsSylableEnd(*w) && *w != *(w+1))
      {
#ifdef DEBUGMODE
        printf("%c and then %c!\n", *w, *(w+1));
#endif
        if (IsLower(*w) && IsUpper(*(w+1)))
        {
#ifdef DEBUGMODE
          printf("+400\tsylable ended followed by uppercase consonant\n");
#endif
          retval += 400;
        }
        else
        {
#ifdef DEBUGMODE
          printf("+800\tsylable ended followed by lowercase consonant\n");
#endif
          retval += 800;
        }
      }
    }

    if (IsLeftBracket(*w))
      ++left_brackets;
    if (IsNumeric(*w))
      ++numerics;
    if (IsRightBracket(*w))
      ++right_brackets;
    if (IsUpper(*w))
      ++upper;
    if (*w == '-')
      ++hyphens;
    if ((*w == 'Q' || *w == 'q') && (*(w+1) != 'u' && *(w+1) != 'U'))
    {
#ifdef DEBUGMODE
      printf("+400\tq without proceeding u\n");
#endif
      retval += 400;
    }
  }

#ifdef HAVE_STRCASESTR
  if (strcasestr(string, "DCC") != NULL)
#else
  if (strstr(string, "DCC") != NULL)
#endif
  {
#ifdef DEBUGMODE
    printf("-1300\tdcc bot\n");
#endif
    retval -= 1300;
  }

  if ((float) unique/length <= 0.5)
  {
#ifdef DEBUGMODE
    printf("-750\tsmall range of characters\n");
#endif
    retval -= 750;
  }

  if (consonants == length)
  {
#ifdef DEBUGMODE
    printf("+1000\tall chars consonants\n");
#endif
    retval += 1000;
  }

  if (upper + numerics == length)
  {
#ifdef DEBUGMODE
    printf("+900\tall uppercase and numerics\n");
#endif
    retval += 900;
  }

  if (numerics >= length - 2)
  {
#ifdef DEBUGMODE
    printf("+750\tall but 1 or 2 numerics\n");
#endif
    retval += 750;
  }

  if (hyphens > 0 && numerics >= 2)
  {
#ifdef DEBUGMODE
    printf("+700\t1 or more hyphens and 2 or more numerics\n");
#endif
    retval += 700;
  }

  if (upper > lower)
  {
#ifdef DEBUGMODE
    printf("+600\tmore upper than lower case\n");
#endif
    retval += 600;
  }

  if (numerics * 2 >= length)
  {
#ifdef DEBUGMODE
    printf("+600\tmostly numerics\n");
#endif
    retval += 600;
  }

  if (vowels * 3 < consonants)
  {
#ifdef DEBUGMODE
    printf("+550\t3 times as many consonants as vowels\n");
#endif
    retval += 550;
  }

  if (left_brackets != right_brackets)
  {
#ifdef DEBUGMODE
    printf("+500\tunmatched brackets\n");
#endif
    retval += 500;
  }

  return retval;
}
