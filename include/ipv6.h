/* ipv6.h: ipv6 function declarations go here.
 *
 *    $Id: ipv6.h,v 1.1 2003/01/19 01:18:38 wiz Exp $
 */

const char *	inet_ntop6	(const unsigned char *, char *, unsigned int);
int		inet_pton6	(const char *, u_char *);
