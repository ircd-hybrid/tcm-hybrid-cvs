/* strdup, hacked by gustaf neumann, Oct 90 */

#include <strings.h>
#include <stdio.h>

extern char * malloc();

char * 
strdup ( string ) 
char * string;
{
char *newstring;
unsigned size;

	if (string == (char *)NULL)	/* If the original is NULL	*/
		return (char *)NULL;	/* so is the result.		*/

	size = (unsigned)strlen(string)+1;
	if ( (newstring = malloc((strlen(string)+1) * sizeof(char))) )
		strcpy(newstring,string);

	return newstring;
}
