/*
 * conf.h
 *
 *  $Id: conf.h,v 1.1 2004/06/02 02:00:41 bill Exp $
 */

#ifndef __CONF_H_
#define __CONF_H_

int conf_fgets(char *, unsigned int, FILE *);
int conf_fatal_error(const char *);
void yyerror(const char *);
void read_conf_files(int);

extern int yylex(void);

FILE *conf_file_in;

#endif /* !__CONF_H_ */
