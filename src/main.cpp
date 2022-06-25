#include <Arduino.h>
#include <IRremote.hpp>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <ArduinoJson.h>

#include "config.hpp"
#include "sensitiveInfo.hpp" // TODO: change this to be part of config, this makes for easier development right now though
#include "processRecv.hpp"

// start client to communicate with hue bridge server
WiFiClientSecure client; 

const char *server_cert = "-----BEGIN CERTIFICATE-----\n"
"MIICMjCCAdigAwIBAgIUO7FSLbaxikuXAljzVaurLXWmFw4wCgYIKoZIzj0EAwIw\n"
"OTELMAkGA1UEBhMCTkwxFDASBgNVBAoMC1BoaWxpcHMgSHVlMRQwEgYDVQQDDAty\n"
"b290LWJyaWRnZTAiGA8yMDE3MDEwMTAwMDAwMFoYDzIwMzgwMTE5MDMxNDA3WjA5\n"
"MQswCQYDVQQGEwJOTDEUMBIGA1UECgwLUGhpbGlwcyBIdWUxFDASBgNVBAMMC3Jv\n"
"b3QtYnJpZGdlMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEjNw2tx2AplOf9x86\n"
"aTdvEcL1FU65QDxziKvBpW9XXSIcibAeQiKxegpq8Exbr9v6LBnYbna2VcaK0G22\n"
"jOKkTqOBuTCBtjAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBhjAdBgNV\n"
"HQ4EFgQUZ2ONTFrDT6o8ItRnKfqWKnHFGmQwdAYDVR0jBG0wa4AUZ2ONTFrDT6o8\n"
"ItRnKfqWKnHFGmShPaQ7MDkxCzAJBgNVBAYTAk5MMRQwEgYDVQQKDAtQaGlsaXBz\n"
"IEh1ZTEUMBIGA1UEAwwLcm9vdC1icmlkZ2WCFDuxUi22sYpLlwJY81Wrqy11phcO\n"
"MAoGCCqGSM49BAMCA0gAMEUCIEBYYEOsa07TH7E5MJnGw557lVkORgit2Rm1h3B2\n"
"sFgDAiEA1Fj/C3AN5psFMjo0//mrQebo0eKd3aWRx+pQY08mk48=\n"
"-----END CERTIFICATE-----\n";

void setup()
{
  // when finalising project, set debug to 0 in config.h and no serial output will be generated
  if (DEBUG)
  {
    delay(2000); // give some time to start terminal
    Serial.begin(115200);
    debugln("Serial open...");
  }

  // connect to wifi
  debug("Connecting to ");
  debugln(ssid);

  WiFi.mode(WIFI_STA);
  WiFi.begin(ssid, password);

  while (WiFi.status() != WL_CONNECTED)
  {
    delay(500);
    debugln(".");
  }

  debugln("");
  debugln("WiFi connected.");
  debugln("IP address: ");
  debugln(WiFi.localIP());

  // to create secure connection to the server
  client.setCACert(server_cert);

  // Start the IR receiver and test led
  IrReceiver.begin(IR_RECV_PIN); 
  pinMode(POWER_LED_PIN, OUTPUT);
  digitalWrite(POWER_LED_PIN, LOW);

  // make initial http request to get light ids
}

void loop()
{
  // detect IR signal and react to button presses
  if (IrReceiver.decode())
  {
    processSignal(IrReceiver.decodedIRData.decodedRawData); // deal with button press event

    IrReceiver.resume(); // Enable receiving of the next value
  }
}