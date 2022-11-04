/* Provide SSL/TLS functions to ESP32 with Arduino IDE
*
* Adapted from the ssl_client1 example of mbedtls.
*
* Original Copyright (C) 2006-2015, ARM Limited, All Rights Reserved, Apache 2.0 License.
* Additions Copyright (C) 2017 Evandro Luis Copercini, Apache 2.0 License.
*/

#include "Arduino.h"
#include <esp32-hal-log.h>
#include <lwip/err.h>
#include <lwip/sockets.h>
#include <lwip/sys.h>
#include <lwip/netdb.h>
#include <mbedtls/sha256.h>
#include <mbedtls/oid.h>
#include <algorithm>
#include <string>
#include "ssl_client.h"
#include "esp_crt_bundle.h"
#include "WiFi.h"
#include "ssl_client_named.h"

#if !defined(MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED) && !defined(MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED)
#  warning "Please call `idf.py menuconfig` then go to Component config -> mbedTLS -> TLS Key Exchange Methods -> Enable pre-shared-key ciphersuites and then check `Enable PSK based cyphersuite modes`. Save and Quit."
#else

const char *pers_named = "esp32-tls";

static int _handle_error(int err, const char * function, int line)
{
    if(err == -30848){
        return err;
    }
#ifdef MBEDTLS_ERROR_C
    char error_buf[100];
    mbedtls_strerror(err, error_buf, 100);
    log_e("[%s():%d]: (%d) %s", function, line, err, error_buf);
#else
    log_e("[%s():%d]: code %d", function, line, err);
#endif
    return err;
}

#define handle_error(e) _handle_error(e, __FUNCTION__, __LINE__)

int start_ssl_client_named(sslclient_context *ssl_client, const char *host, const char *hostname, uint32_t port, int timeout, const char *rootCABuff, bool useRootCABundle, const char *cli_cert, const char *cli_key, const char *pskIdent, const char *psKey, bool insecure, const char **alpn_protos)
{
    char buf[512];
    int ret, flags;
    int enable = 1;
    log_v("Free internal heap before TLS %u", ESP.getFreeHeap());

    if (rootCABuff == NULL && pskIdent == NULL && psKey == NULL && !insecure && !useRootCABundle) {
        return -1;
    }

    log_v("Starting socket");
    ssl_client->socket = -1;

    ssl_client->socket = lwip_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (ssl_client->socket < 0) {
        log_e("ERROR opening socket");
        return ssl_client->socket;
    }

    IPAddress srv((uint32_t)0);
    if(!WiFiGenericClass::hostByName(host, srv)){
        return -1;
    }

    fcntl( ssl_client->socket, F_SETFL, fcntl( ssl_client->socket, F_GETFL, 0 ) | O_NONBLOCK );
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = srv;
    serv_addr.sin_port = htons(port);

    if(timeout <= 0){
        timeout = 30000; // Milli seconds.
    }

    fd_set fdset;
    struct timeval tv;
    FD_ZERO(&fdset);
    FD_SET(ssl_client->socket, &fdset);
    tv.tv_sec = timeout / 1000;
    tv.tv_usec = (timeout % 1000) * 1000;

    int res = lwip_connect(ssl_client->socket, (struct sockaddr*)&serv_addr, sizeof(serv_addr));
    if (res < 0 && errno != EINPROGRESS) {
        log_e("connect on fd %d, errno: %d, \"%s\"", ssl_client->socket, errno, strerror(errno));
        lwip_close(ssl_client->socket);
        ssl_client->socket = -1;
        return -1;
    }

    res = select(ssl_client->socket + 1, nullptr, &fdset, nullptr, timeout<0 ? nullptr : &tv);
    if (res < 0) {
        log_e("select on fd %d, errno: %d, \"%s\"", ssl_client->socket, errno, strerror(errno));
        lwip_close(ssl_client->socket);
        ssl_client->socket = -1;
        return -1;
    } else if (res == 0) {
        log_i("select returned due to timeout %d ms for fd %d", timeout, ssl_client->socket);
        lwip_close(ssl_client->socket);
        ssl_client->socket = -1;
        return -1;
    } else {
        int sockerr;
        socklen_t len = (socklen_t)sizeof(int);
        res = getsockopt(ssl_client->socket, SOL_SOCKET, SO_ERROR, &sockerr, &len);

        if (res < 0) {
            log_e("getsockopt on fd %d, errno: %d, \"%s\"", ssl_client->socket, errno, strerror(errno));
            lwip_close(ssl_client->socket);
            ssl_client->socket = -1;
            return -1;
        }

        if (sockerr != 0) {
            log_e("socket error on fd %d, errno: %d, \"%s\"", ssl_client->socket, sockerr, strerror(sockerr));
            lwip_close(ssl_client->socket);
            ssl_client->socket = -1;
            return -1;
        }
    }


#define ROE(x,msg) { if (((x)<0)) { log_e("LWIP Socket config of " msg " failed."); return -1; }}
     ROE(lwip_setsockopt(ssl_client->socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)),"SO_RCVTIMEO");
     ROE(lwip_setsockopt(ssl_client->socket, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)),"SO_SNDTIMEO");

     ROE(lwip_setsockopt(ssl_client->socket, IPPROTO_TCP, TCP_NODELAY, &enable, sizeof(enable)),"TCP_NODELAY");
     ROE(lwip_setsockopt(ssl_client->socket, SOL_SOCKET, SO_KEEPALIVE, &enable, sizeof(enable)),"SO_KEEPALIVE");



    log_v("Seeding the random number generator");
    mbedtls_entropy_init(&ssl_client->entropy_ctx);

    ret = mbedtls_ctr_drbg_seed(&ssl_client->drbg_ctx, mbedtls_entropy_func,
                                &ssl_client->entropy_ctx, (const unsigned char *) pers_named, strlen(pers_named));
    if (ret < 0) {
        return handle_error(ret);
    }

    log_v("Setting up the SSL/TLS structure...");

    if ((ret = mbedtls_ssl_config_defaults(&ssl_client->ssl_conf,
                                           MBEDTLS_SSL_IS_CLIENT,
                                           MBEDTLS_SSL_TRANSPORT_STREAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        return handle_error(ret);
    }

    if (alpn_protos != NULL) {
        log_v("Setting ALPN protocols");
        if ((ret = mbedtls_ssl_conf_alpn_protocols(&ssl_client->ssl_conf, alpn_protos) ) != 0) {
            return handle_error(ret);
        }
    }

    // MBEDTLS_SSL_VERIFY_REQUIRED if a CA certificate is defined on Arduino IDE and
    // MBEDTLS_SSL_VERIFY_NONE if not.

    if (insecure) {
        mbedtls_ssl_conf_authmode(&ssl_client->ssl_conf, MBEDTLS_SSL_VERIFY_NONE);
        log_d("WARNING: Skipping SSL Verification. INSECURE!");
    } else if (rootCABuff != NULL) {
        log_v("Loading CA cert");
        mbedtls_x509_crt_init(&ssl_client->ca_cert);
        mbedtls_ssl_conf_authmode(&ssl_client->ssl_conf, MBEDTLS_SSL_VERIFY_REQUIRED);
        ret = mbedtls_x509_crt_parse(&ssl_client->ca_cert, (const unsigned char *)rootCABuff, strlen(rootCABuff) + 1);
        mbedtls_ssl_conf_ca_chain(&ssl_client->ssl_conf, &ssl_client->ca_cert, NULL);
        //mbedtls_ssl_conf_verify(&ssl_client->ssl_ctx, my_verify, NULL );
        if (ret < 0) {
            // free the ca_cert in the case parse failed, otherwise, the old ca_cert still in the heap memory, that lead to "out of memory" crash.
            mbedtls_x509_crt_free(&ssl_client->ca_cert);
            return handle_error(ret);
        }
    } else if (useRootCABundle) {
        log_v("Attaching root CA cert bundle");
        ret = esp_crt_bundle_attach(&ssl_client->ssl_conf);

        if (ret < 0) {
            return handle_error(ret);
        }
    } else if (pskIdent != NULL && psKey != NULL) {
        log_v("Setting up PSK");
        // convert PSK from hex to binary
        if ((strlen(psKey) & 1) != 0 || strlen(psKey) > 2*MBEDTLS_PSK_MAX_LEN) {
            log_e("pre-shared key not valid hex or too long");
            return -1;
        }
        unsigned char psk[MBEDTLS_PSK_MAX_LEN];
        size_t psk_len = strlen(psKey)/2;
        for (int j=0; j<strlen(psKey); j+= 2) {
            char c = psKey[j];
            if (c >= '0' && c <= '9') c -= '0';
            else if (c >= 'A' && c <= 'F') c -= 'A' - 10;
            else if (c >= 'a' && c <= 'f') c -= 'a' - 10;
            else return -1;
            psk[j/2] = c<<4;
            c = psKey[j+1];
            if (c >= '0' && c <= '9') c -= '0';
            else if (c >= 'A' && c <= 'F') c -= 'A' - 10;
            else if (c >= 'a' && c <= 'f') c -= 'a' - 10;
            else return -1;
            psk[j/2] |= c;
        }
        // set mbedtls config
        ret = mbedtls_ssl_conf_psk(&ssl_client->ssl_conf, psk, psk_len,
                 (const unsigned char *)pskIdent, strlen(pskIdent));
        if (ret != 0) {
            log_e("mbedtls_ssl_conf_psk returned %d", ret);
            return handle_error(ret);
        }
    } else {
        return -1;
    }

    if (!insecure && cli_cert != NULL && cli_key != NULL) {
        mbedtls_x509_crt_init(&ssl_client->client_cert);
        mbedtls_pk_init(&ssl_client->client_key);

        log_v("Loading CRT cert");

        ret = mbedtls_x509_crt_parse(&ssl_client->client_cert, (const unsigned char *)cli_cert, strlen(cli_cert) + 1);
        if (ret < 0) {
        // free the client_cert in the case parse failed, otherwise, the old client_cert still in the heap memory, that lead to "out of memory" crash.
        mbedtls_x509_crt_free(&ssl_client->client_cert);
            return handle_error(ret);
        }

        log_v("Loading private key");
        ret = mbedtls_pk_parse_key(&ssl_client->client_key, (const unsigned char *)cli_key, strlen(cli_key) + 1, NULL, 0);

        if (ret != 0) {
            mbedtls_x509_crt_free(&ssl_client->client_cert); // cert+key are free'd in pair
            return handle_error(ret);
        }

        mbedtls_ssl_conf_own_cert(&ssl_client->ssl_conf, &ssl_client->client_cert, &ssl_client->client_key);
    }

    log_v("Setting hostname for TLS session...");

    // Hostname set here should match CN in server certificate
    if((ret = mbedtls_ssl_set_hostname(&ssl_client->ssl_ctx, hostname)) != 0){
        return handle_error(ret);
    }

    mbedtls_ssl_conf_rng(&ssl_client->ssl_conf, mbedtls_ctr_drbg_random, &ssl_client->drbg_ctx);

    if ((ret = mbedtls_ssl_setup(&ssl_client->ssl_ctx, &ssl_client->ssl_conf)) != 0) {
        return handle_error(ret);
    }

    mbedtls_ssl_set_bio(&ssl_client->ssl_ctx, &ssl_client->socket, mbedtls_net_send, mbedtls_net_recv, NULL );

    log_v("Performing the SSL/TLS handshake...");
    unsigned long handshake_start_time=millis();
    while ((ret = mbedtls_ssl_handshake(&ssl_client->ssl_ctx)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            return handle_error(ret);
        }
        if((millis()-handshake_start_time)>ssl_client->handshake_timeout)
            return -1;
        vTaskDelay(2);//2 ticks
    }


    if (cli_cert != NULL && cli_key != NULL) {
        log_d("Protocol is %s Ciphersuite is %s", mbedtls_ssl_get_version(&ssl_client->ssl_ctx), mbedtls_ssl_get_ciphersuite(&ssl_client->ssl_ctx));
        if ((ret = mbedtls_ssl_get_record_expansion(&ssl_client->ssl_ctx)) >= 0) {
            log_d("Record expansion is %d", ret);
        } else {
            log_w("Record expansion is unknown (compression)");
        }
    }

    log_v("Verifying peer X.509 certificate...");

    if ((flags = mbedtls_ssl_get_verify_result(&ssl_client->ssl_ctx)) != 0) {
        memset(buf, 0, sizeof(buf));
        mbedtls_x509_crt_verify_info(buf, sizeof(buf), "  ! ", flags);
        log_e("Failed to verify peer certificate! verification info: %s", buf);
        return handle_error(ret);
    } else {
        log_v("Certificate verified.");
    }
    
    if (rootCABuff != NULL) {
        mbedtls_x509_crt_free(&ssl_client->ca_cert);
    }

    if (cli_cert != NULL) {
        mbedtls_x509_crt_free(&ssl_client->client_cert);
    }

    if (cli_key != NULL) {
        mbedtls_pk_free(&ssl_client->client_key);
    }    

    log_v("Free internal heap after TLS %u", ESP.getFreeHeap());

    return ssl_client->socket;
}

#endif