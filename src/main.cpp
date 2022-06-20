#include <Arduino.h>
#include <IRremote.hpp>
#include <WiFi.h>

#include "config.hpp"
#include "sensitive_info.hpp" // TODO: change this to be part of config, this makes for easier development right now though
#include "process_recv.hpp"

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

  IrReceiver.begin(IR_RECV_PIN); // Start the IR receiver
  pinMode(POWER_LED_PIN, OUTPUT);
  digitalWrite(POWER_LED_PIN, LOW);
}

void loop()
{
  // detect IR signal and react to button presses
  if (IrReceiver.decode())
  {
    process_signal(IrReceiver.decodedIRData.decodedRawData); // deal with button press event

    IrReceiver.resume(); // Enable receiving of the next value
  }
}