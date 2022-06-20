#include <Arduino.h>
#include "config.hpp"
#include "remote_enum.hpp"

void process_signal(uint32_t hex_recv)
{
  // power button pressed
  if (hex_recv == Button_pressed::POWER)
  {
    debugln("Power button pressed");
    
    // testing LED, remove when hue control added
    bool led_status = digitalRead(POWER_LED_PIN); 

    digitalWrite(POWER_LED_PIN, !led_status);
  }
}