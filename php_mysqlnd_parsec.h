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

#ifndef PHP_MARIADB_PARSEC_PLUGIN_H
#define PHP_MARIADB_PARSEC_PLUGIN_H

#define SHA512_LENGTH 64
#define NONCE_LENGTH 32

#define CHALLENGE_SCRAMBLE_LENGTH 32
#define CHALLENGE_SALT_LENGTH     18
#define ED25519_SIG_LENGTH        64
#define ED25519_KEY_LENGTH        32
#define PBKDF2_HASH_LENGTH        ED25519_KEY_LENGTH
#define CLIENT_RESPONSE_LENGTH    (CHALLENGE_SCRAMBLE_LENGTH + ED25519_SIG_LENGTH)

#define NET_HEADER_SIZE  4


#define PHP_MARIADB_AUTH_PLUGIN_VERSION "1.0.2"

extern zend_module_entry mariadb_auth_plugin_module_entry;
#define phpext_mariadb_auth_plugin_ptr &mariadb_auth_plugin_module_entry

#endif
