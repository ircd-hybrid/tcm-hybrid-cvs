/************************************************************
* MrsBot by Hendrix <jimi@texas.net>                        *
* wild.c                                                    *
*   Contains my wildcard matching routines for *'s and ?'s  *
* Includes routines:                                        *
*   int wldcmp                                              *
*   int wldwld                                              *
*                                                           *
* removed unneeded match code                               *
************************************************************/

#include <ctype.h>
#include <string.h>
#include "wild.h"

static char *version="$Id: wild.c,v 1.1 2000/09/02 04:30:50 bill Exp $";

/*
** wldcmp()
**   My very own wildcard matching routine for one wildcarded string
**    and one non-wildcarded string.  Wildcards ? and * recognized.
**   Parameters:
**     wildexp - A string possibly containing wildcard expressions
**     regstr - A string DEFINITELY containing NO wildcard expressions
**   Returns:
**     Like strcmp()... Returns 1 on no match and 0 if they do match.
**   PDL:
**     Go thru each character.  Match is still intact if a * is found,
**     a ? is found, or both characters in the two strings match (excluding
**     case).  If a * is encountered, recursively call wldcmp() with the
**     remainder of the wildcarded string and all possible remaining pieces
**     of the regular string.  If any of those match, then the whole compare
**     is a match.  If the character encountered is a null, then we have
**     reached end of string and the match is a success.  However, an effort
**     to match a ? with the end of the string is a failure.
*/
int wldcmp (char *wildexp, char *regstr)
{
  while (*wildexp == '*' || tolower(*wildexp) == tolower(*regstr) ||
	 *wildexp == '?')
    if (*wildexp == '*')
      {
	/* This will stop idiots who ban *?*?*?*?*?*?* from crashing the bot */
	while (*(++wildexp) == '*' ||
	       (*wildexp == '?' && *(wildexp+1) == '*'));
      if (*wildexp)
	{
	  while (*regstr)
	    if (!wldcmp(wildexp,regstr++))
	      return 0;
	  return 1;
        }
      else
        return 0;
      }
    else if (!*wildexp)
      return 0;
    else if (!*regstr) /* Only true if nothing to match ? with */
      return 1;
    else
      {
	++wildexp;
	++regstr;
      }
  return 1;
}

/*
** wldwld()
**   My very own wildcard matching routine for TWO wildcarded strings.
**    Wildcards ? and * recognized.  Note: this is MUCH less efficient
**    than wldcmp(), so use it only where necessary.  There are very few
**    cases that you should truly need to compare 2 wildcarded strings.
**   Parameters:
**     wild1 - A string hopefully containing wildcard expressions
**     wild2 - A string hopefully containing wildcard expressions
**   Returns:
**     Like strcmp()... Returns 1 on no match and 0 if they do match.
**   PDL:
**     As in wldcmp() but check for *'s and ?'s in both strings.  If a
**     * is found in EITHER string, recursively call wldwld() with the
**     remainder of the other string.  You can see how this can get into
**     deep recursion, so use wldcmp() when you can.
*/
int wldwld (wild1,wild2)
char *wild1,*wild2;
{
  while (tolower(*wild1) == tolower(*wild2) || *wild1 == '*' || *wild2 == '*' ||
         *wild1 == '?' || *wild2 == '?') {
    if (*wild1 == '*') {
      /* This will stop idiots who ban *?*?*?*?*?*?* from crashing the bot */
      while (*(++wild1) == '*' || (*wild1 == '?' && *(wild1+1) == '*'));
      if (*wild1) {
        while (*wild2)
          if (!wldwld(wild1,wild2++))
            return 0;
        return 1;
        }
      else
        return 0;
      }
    else if (*wild2 == '*') {
      /* This will stop idiots who ban *?*?*?*?*?*?* from crashing the bot */
      while (*(++wild2) == '*' || (*wild2 == '?' && *(wild2+1) == '*'));
      if (*wild2) {
        while (*wild1)
          if (!wldwld(wild1++,wild2))
            return 0;
        return 1;
        }
      else
        return 0;
      }
    else if (!*wild1)
      return (*wild2 == '?');
    else if (!*wild2)   /* wild1 must be a ? in this case */
      return 1;
    else {
      ++wild1;
      ++wild2;
      }
    }
    return 1;
}
