#include <Arduino.h>
#include <IRremote.hpp>
#include <WiFi.h>
#include "WifiClientSecureExt.hpp"
#include <ArduinoJson.h>

#include "config.hpp"
#include "sensitiveInfo.hpp" // TODO: change this to be part of config, this makes for easier development right now though
#include "processRecv.hpp"

// start client to communicate with hue bridge server
WifiClientSecureExt client;

void makeHTTPRequest();

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

  // Start the IR receiver and test led
  IrReceiver.begin(IR_RECV_PIN);
  // pinMode(POWER_LED_PIN, OUTPUT);
  // digitalWrite(POWER_LED_PIN, LOW);

  // make initial http request to get light ids
  client.setCACert(server_cert);

  // button test
  pinMode(BUTTON_PIN, INPUT_PULLUP);
}

void loop()
{
  // detect IR signal and react to button presses
  if (IrReceiver.decode())
  {
    processSignal(IrReceiver.decodedIRData.decodedRawData); // deal with button press event
    IrReceiver.resume(); // Enable receiving of the next value
  }

  if (digitalRead(BUTTON_PIN) == LOW){
    makeHTTPRequest();
    delay(200);
  }

}

void makeHTTPRequest()
{
  if (!client.connectNamedHost(HUE_HOST, hostname, 443))
  {
    debugln(F("Connection failed"));
    return;
  }


  // give the esp a breather
  yield();
  

  // define message type and address and HTTP spec: https://www.rfc-editor.org/rfc/rfc7230.html
  client.print(F("PUT "));
  client.print("/clip/v2/resource/light/c8dc9e82-f247-4527-9757-3e325ae70c21");
  client.println(F(" HTTP/1.1"));

    // Headers, terminate with CRLF
  client.print(F("hue-application-key:"));
  client.println(F(APP_KEY));
  client.print(F("Host:"));
  client.println(F(BRIDGE_ID));
  client.println(F("Content-Type:text/plain"));
  client.print("Content-Length:18\r\n\r\n"); // need \r and \n as end of line marker as HTTP/1.1 expects CRLF here, and another one for rigour (could use println although this is more accurate to the spec)
  
  // message body
  client.println("{\"on\":{\"on\":true}}");

  if (client.println() == 0)
  {
    debugln(F("Failed to send request"));
    return;
  }

  // Check HTTP status
  char status[32] = {0};
  client.readBytesUntil('\r', status, sizeof(status));
  if (strcmp(status, "HTTP/1.1 200 OK") != 0)
  {
    debug(F("Unexpected response: "));
    debugln(status);
    return;
  }

  while (client.available() && client.peek() != '{')
  {
    char c = 0;
    client.readBytes(&c, 1);
    // debug(c);
  }

  DynamicJsonDocument doc(6144);
  DeserializationError error = deserializeJson(doc, client);

  // if (!error)
  // {
  //   bool json_id = doc["data"][0]["on"]["on"];
  //   debugln(json_id);
  // }
  // else
  // {
  //   debug(F("deserializeJson() failed: "));
  //   debugln(error.f_str());
  //   return;
  // }

  client.stop();
}