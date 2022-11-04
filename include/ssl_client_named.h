/* Provide SSL/TLS functions to ESP32 with Arduino IDE
 * by Evandro Copercini - 2017 - Apache 2.0 License
 */

#pragma once
#include "ssl_client.h"

int start_ssl_client_named(sslclient_context *ssl_client, const char *host, const char *hostname, uint32_t port, int timeout, const char *rootCABuff, bool useRootCABundle, const char *cli_cert, const char *cli_key, const char *pskIdent, const char *psKey, bool insecure, const char **alpn_protos);

