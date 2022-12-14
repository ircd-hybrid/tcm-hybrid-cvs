/*
 *  tcm-hybrid: an advanced irc connection monitor
 *  respond.c: issues response to ircd-hybrid CHALLENGE/RESPONSE system
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
 *    $Id: respond.c,v 1.4 2004/06/10 23:20:23 bill Exp $
 */

#include "setup.h"

#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/md5.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "tcm.h"
#include "userlist.h"
#include "tcm_io.h"
#include "respond.h"

static void
binary_to_hex( unsigned char * bin, char * hex, int length )
{
  char * trans = "0123456789ABCDEF";
  int i;

  for (i = 0; i < length; i++)
  {
    hex[i<<1]     = trans[bin[i] >> 4];
    hex[(i<<1)+1] = trans[bin[i] & 0xf];
  }
  hex[i<<1] = '\0';
}       

static int
hex_to_binary(const char *from, char *to, int len)
{
  char a, b=1;
  int p=0;
  const char *ptr = from;

  while (-1)
  {
    a = *ptr++;
    if (!a)
      break;
    b = *ptr++;

    /* If this happens, we got bad input. */
    if (!b)
      break;
    if (p >= len)
      break;
    if (!((a >= '0' && a <= '9') || (a >= 'A' && a <= 'F')))
      break;
    if (!((b >= '0' && b <= '9') || (b >= 'A' && b <= 'F')))
      break;

    to[p++] = ((a <= '9') ? (a - '0') : (a - 'A' + 0xA))<<4 |
              ((b <= '9') ? (b - '0') : (b - 'A' + 0xA));
  }
  return p;
}

static int
pass_cb(char *buf, int size, int rwflag, void *u)
{
  int len;

  len = strlen(config_entries.oper_pass_config);
  if (len <= 0)
    return 0;
  if (len > size)
    len = size;
  memcpy(buf, config_entries.oper_pass_config, len);
  return len;
}

/*
 * do_challenge()
 *
 * inputs	- challenge string
 * outputs	- -1 for failure, 0 for success
 * side effects	- writes challenge response to server FD
 */
int do_challenge(char *challenge_string)
{
  FILE *kfile;
  RSA *rsa = NULL;
  char ndata[257], ddata[257];

  if ((kfile = fopen(config_entries.oper_keyfile, "r")) == NULL)
  {
    send_to_all(NULL, FLAGS_ADMIN, "*** Error opening %s: %s",
                config_entries.oper_keyfile, strerror(errno));
    return -1;
  }

  SSLeay_add_all_ciphers();
  rsa = PEM_read_RSAPrivateKey(kfile, NULL, pass_cb, NULL);

  if (rsa == NULL)
  {
    send_to_all(NULL, FLAGS_ADMIN,
                "*** Unable to read private keyfile.  Incorrect passphrase?");
    return -1;
  }

  fclose(kfile);

  if (hex_to_binary(challenge_string, ndata, 128) != 128)
  {
    send_to_all(NULL, FLAGS_ADMIN,
               "*** Unable to process challenge string.");
    return -1;
  }

  if (RSA_private_decrypt(128, (unsigned char *)ndata,
      (unsigned char *)ddata, rsa, RSA_PKCS1_PADDING) == -1)
  {
    send_to_all(NULL, FLAGS_ADMIN,
                "*** Decryption error in CHALLENGE response attempt");
    return -1;
  }

  binary_to_hex((unsigned char *)ddata, ndata, 32);
  send_to_server("CHALLENGE +%s", ndata);
  return 0;
}
