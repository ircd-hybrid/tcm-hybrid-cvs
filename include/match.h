/* Stats - IRC Statistical Services for Hybrid, csircd, and IRCnet 2.10
** match.c - IRCnet derived match() and family
**
** Copyright W. Campbell and others.  See README for more details
** Some code Copyright: Jonathan George, Kai Seidler, ircd-hybrid Team,
**                      IRCnet IRCD developers.
**
** $Id: match.h,v 1.2 2002/12/29 09:41:18 bill Exp $
*/

#ifndef MATCH_H
#define MATCH_H

/*
 * character macros
 */
extern const unsigned char ToLowerTab[];
#define ToLower(c) (ToLowerTab[(unsigned char)(c)])

extern const unsigned char ToUpperTab[];
#define ToUpper(c) (ToUpperTab[(unsigned char)(c)])

int match(char *, char *);
char *collapse(char *);
int mycmp(char *, char *);
int myncmp(char *, char *, int);

#ifdef HAVE_REGEX_H
#define REGCOMP_FLAGS REG_EXTENDED
#define REGEXEC_FLAGS 0
#else
#undef REGEX_SIZE
#endif

#endif
