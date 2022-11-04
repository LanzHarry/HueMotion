#pragma once
#include <WiFiClientSecure.h>

class WifiClientSecureExt : public WiFiClientSecure
{
    public:
        // constructor
        WifiClientSecureExt();

        int connectNamedHost(const char *host, const char *hostname, uint16_t port);
        int connectNamedHost(const char *host, const char *hostname, uint16_t port, const char *CA_cert, const char *cert, const char *private_key);

        // destructor
        ~WifiClientSecureExt();

};