#include <Arduino.h>
#include <IRremote.hpp>
#include "config.hpp"
#include "process_recv.hpp"

bool led_status = false;

void setup()
{
  if (DEBUG)
  {
    Serial.begin(115200);
    debugln("Serial open...");
  }
  IrReceiver.begin(IR_RECV_PIN); // Start the receiver
  pinMode(POWER_LED_PIN, OUTPUT);
  digitalWrite(POWER_LED_PIN, led_status);
}

void loop()
{
  if (IrReceiver.decode())
  {

    process_signal(IrReceiver.decodedIRData.decodedRawData);

    IrReceiver.resume(); // Enable receiving of the next value
  }
}