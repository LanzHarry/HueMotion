#include "WifiClientSecureExt.hpp"
#include "ssl_client_named.h"

WifiClientSecureExt::WifiClientSecureExt() : WiFiClientSecure()
{
    // do nothing, super class constructor called
}

int WifiClientSecureExt::connectNamedHost(const char *host, const char *hostname, uint16_t port)
{
    return connectNamedHost(host, hostname, port, _CA_cert, _cert, _private_key);
}

int WifiClientSecureExt::connectNamedHost(const char *host, const char *hostname, uint16_t port, const char *CA_cert, const char *cert, const char *private_key)
{
    int ret = start_ssl_client_named(sslclient, host, hostname, port, _timeout, CA_cert, _use_ca_bundle, cert, private_key, NULL, NULL, _use_insecure, _alpn_protos);
    _lastError = ret;
    if (ret < 0) {
        log_e("start_ssl_client: %d", ret);
        stop();
        return 0;
    }
    _connected = true;
    return 1;
}


WifiClientSecureExt::~WifiClientSecureExt()
{

}