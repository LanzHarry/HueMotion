#pragma once

// debug settings, set to 0 to disable any serial output
#define DEBUG 1

#if DEBUG
#define debug(x) Serial.print(x)
#define debugln(x) Serial.println(x)
#else
#define debug(x)
#define debugln(x)
#endif

// pin configurations
#define IR_RECV_PIN 4
#define POWER_LED_PIN 21
#define BUTTON_PIN 5

// API config
#define HUE_HOST "192.168.0.34"