/*
   +----------------------------------------------------------------------+
   | Copyright © The PHP Group and Contributors.                          |
   +----------------------------------------------------------------------+
   | This source file is subject to the Modified BSD License that is      |
   | bundled with this package in the file LICENSE, and is available      |
   | through the World Wide Web at <https://www.php.net/license/>.        |
   |                                                                      |
   | SPDX-License-Identifier: BSD-3-Clause                                |
   +----------------------------------------------------------------------+
   | Authors: Georg Richter <georg@mariadb.com>                           |
   +----------------------------------------------------------------------+
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "ext/mysqlnd/mysqlnd.h"
#include "ext/mysqlnd/mysqlnd_auth.h"
#include "ext/mysqlnd/mysqlnd_plugin.h"
#include "ext/mysqlnd/mysqlnd_wireprotocol.h"
#include "php_ini.h"
#include "php_mysqlnd_parsec.h"
#include <sodium.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

struct Passwd_in_memory
{
  char algorithm;
  zend_uchar iterations;
  zend_uchar salt[CHALLENGE_SALT_LENGTH];
  zend_uchar pub_key[ED25519_KEY_LENGTH];
};

#ifdef _MSC_VER
# define _Static_assert static_assert
#endif

_Static_assert(sizeof(struct Passwd_in_memory) == 2 + CHALLENGE_SALT_LENGTH
                                                   + ED25519_KEY_LENGTH,
              "Passwd_in_memory should be packed.");

struct Client_signed_response
{
  union {
    struct {
      zend_uchar client_scramble[CHALLENGE_SCRAMBLE_LENGTH];
      zend_uchar signature[ED25519_SIG_LENGTH];
    };
    zend_uchar start[1];
  };
};

_Static_assert(sizeof(struct Client_signed_response) == CLIENT_RESPONSE_LENGTH,
              "Client_signed_response should be packed.");


static int compute_derived_key(const char* password, size_t pass_len,
                               const struct Passwd_in_memory *params,
                               zend_uchar *derived_key)
{
  return !PKCS5_PBKDF2_HMAC(password, (int)pass_len, params->salt,
                            CHALLENGE_SALT_LENGTH,
                            1 << (params->iterations + 10),
                            EVP_sha512(), PBKDF2_HASH_LENGTH, derived_key);
}

int ed25519_sign(const zend_uchar *response, size_t response_len,
                 const zend_uchar *private_key, zend_uchar *signature,
                 zend_uchar *public_key)
{

  int res= 1;
  size_t sig_len= ED25519_SIG_LENGTH, pklen= ED25519_KEY_LENGTH;
  EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL,
                                                private_key,
                                                ED25519_KEY_LENGTH);
  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  if (!ctx || !pkey)
    goto cleanup;

  if (EVP_DigestSignInit(ctx, NULL, NULL, NULL, pkey) != 1 ||
      EVP_DigestSign(ctx, signature, &sig_len, response, response_len) != 1)
    goto cleanup;

  EVP_PKEY_get_raw_public_key(pkey, public_key, &pklen);

  res= 0;
cleanup:
  EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(pkey);
  return res;
}


static zend_uchar* mariadb_parsec_auth(struct st_mysqlnd_authentication_plugin* self, size_t* auth_data_len,
	MYSQLND_CONN_DATA* conn, const char* const user, const char* const passwd, const size_t passwd_len,
	zend_uchar* auth_plugin_data, const size_t auth_plugin_data_len,
	const MYSQLND_SESSION_OPTIONS* const session_options, const MYSQLND_PFC_DATA* const pfc_data,
	const zend_ulong mysql_flags) {

	union
	{
		struct
		{
			zend_uchar server_scramble[CHALLENGE_SCRAMBLE_LENGTH];
			struct Client_signed_response response;
		};
		zend_uchar start[1];
	} signed_msg;
	_Static_assert(sizeof signed_msg == CHALLENGE_SCRAMBLE_LENGTH
                                     + sizeof(struct Client_signed_response),
                "signed_msg should be packed.");

	zend_uchar *ret;
	zend_uchar buffer[128];
	size_t pkt_len;
	struct Passwd_in_memory params;
	MYSQLND_PFC * pfc = conn->protocol_frame_codec;
	zend_uchar priv_key[ED25519_KEY_LENGTH];
    zend_uchar *packet_no= &pfc->data->packet_no;
    zend_uchar offset = 0;

    *auth_data_len= 0;

	if (auth_plugin_data_len != CHALLENGE_SCRAMBLE_LENGTH)
    {
	    php_error_docref(NULL, E_WARNING, "received scramble with invalid length");
		return NULL;
    }

    if (!(pfc->data->m.send(pfc, conn->vio, buffer, 0, conn->stats, conn->error_info)))
      return NULL;


    if (FAIL == pfc->data->m.receive(pfc, conn->vio, buffer, NET_HEADER_SIZE, conn->stats, conn->error_info))
      return NULL;
    pkt_len= uint3korr(buffer);

    if (pkt_len > sizeof(buffer))
    {
	    php_error_docref(NULL, E_WARNING, "received extended salt with invalid length");
		return NULL;
    }

    if (FAIL == pfc->data->m.receive(pfc, conn->vio, buffer, pkt_len, conn->stats, conn->error_info))
      return NULL;

    /*
    the server sends \1\255 or \1\254 instead of just \255 or \254 -
    for us to not confuse it with an error or "change plugin" packets.
    We remove this escaping \1 here. */

    if (pkt_len && buffer[offset] == 1)
    {
      pkt_len--;
      offset++;
    }
    if (pkt_len != CHALLENGE_SALT_LENGTH + 2)
    {
	    php_error_docref(NULL, E_WARNING, "received extended salt with invalid length");
		return NULL;
    }

	memcpy(signed_msg.server_scramble, auth_plugin_data, auth_plugin_data_len);
    memcpy(&params, buffer + offset, pkt_len);

	if (params.algorithm != 'P')
    {
	    php_error_docref(NULL, E_WARNING, "Invalid/unknown algorithm for extended salt");
		return NULL;
    }
	if (params.iterations > 3)
    {
	    php_error_docref(NULL, E_WARNING, "Invalid iteration factor for extended salt");
		return NULL;
    }

	RAND_bytes(signed_msg.response.client_scramble, CHALLENGE_SCRAMBLE_LENGTH);

	if (compute_derived_key(passwd, passwd_len, &params, priv_key))
    {
	    php_error_docref(NULL, E_WARNING, "Unable to create derived key");
		return NULL;
    }

	if ((ret= calloc(sizeof signed_msg.response, 1)))
	{
        if (ed25519_sign(signed_msg.start, CHALLENGE_SCRAMBLE_LENGTH * 2,
                          priv_key, signed_msg.response.signature, params.pub_key))
        {
          free(ret);
          return NULL;
        }
		memcpy(ret, signed_msg.response.start, sizeof signed_msg.response);
	    *auth_data_len = sizeof signed_msg.response;

        /* Increment the packet number, to avoid packet order errors */
        (*packet_no)++;

        return ret;
	}
	return NULL;
}

static struct st_mysqlnd_authentication_plugin mariadb_parsec_auth_plugin =
{
	.plugin_header = {
		MYSQLND_PLUGIN_API_VERSION,
		"auth_plugin_parsec",
		PHP_VERSION_ID,
		PHP_MARIADB_AUTH_PLUGIN_VERSION,
		"3-clause BSD License",
		"Georg Richter <georg@mariadb.com>",
		{ NULL, NULL },
		{ NULL },
	},
	.methods = {
		mariadb_parsec_auth,
		NULL
	},
};

PHP_MINIT_FUNCTION(mysqlnd_parsec)
{
	if (mysqlnd_plugin_register_ex((struct st_mysqlnd_plugin_header*)&mariadb_parsec_auth_plugin) == FAIL) {
	  php_error_docref(NULL, E_WARNING, "mysqlnd_plugin_register_ex failed");
	  return FAILURE;
	}
	return SUCCESS;
}

PHP_MSHUTDOWN_FUNCTION(mysqlnd_parsec)
{
	return SUCCESS;
}

static const zend_module_dep mysqlnd_parsec_deps[] = {
	ZEND_MOD_REQUIRED("mysqlnd")
	ZEND_MOD_END
};

zend_module_entry mysqlnd_parsec_module_entry = {
	STANDARD_MODULE_HEADER_EX, NULL,
	mysqlnd_parsec_deps,
	"mysqlnd_parsec",
	NULL,
	PHP_MINIT(mysqlnd_parsec),
	PHP_MSHUTDOWN(mysqlnd_parsec),
	NULL,
	NULL,
	NULL,
	PHP_MARIADB_AUTH_PLUGIN_VERSION,
	STANDARD_MODULE_PROPERTIES
};

#ifdef COMPILE_DL_MYSQLND_PARSEC
ZEND_GET_MODULE(mysqlnd_parsec)
#endif

/* vim: set noexpandtab tabstop=4 shiftwidth=4: */
