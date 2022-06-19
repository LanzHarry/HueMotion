#include <Arduino.h>
#include "config.hpp"
#include "remote_enum.hpp"

void process_signal(double hex_recv){
    // power button pressed
    if (hex_recv == POWER) {
        Serial.println("Power button pressed");
        
        bool led_status = digitalRead(POWER_LED_PIN);

        digitalWrite(POWER_LED_PIN, !led_status);
      }
}