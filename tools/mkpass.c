#include <stdio.h>
#include <pwd.h>
#include <string.h>

char* getpass(char *);

int main()
{
  char pass[100];
  static char saltChars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./";
  char salt[3];
  char * plaintext;

  srandom(time(0));           /* may not be the BEST salt, but its close */
  salt[0] = saltChars[random() % 64];
  salt[1] = saltChars[random() % 64];
  salt[2] = 0;

  strcpy(pass,getpass("plaintext: "));
  printf("%s\n", crypt(pass,salt));
  return 1;
}
