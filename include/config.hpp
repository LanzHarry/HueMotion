#pragma once

#define DEBUG 0

#if DEBUG
#define debug(x) Serial.print(x)
#define debugln(x) Serial.println(x)
#else
#define debug(x)
#define debugln(x)
#endif

#define IR_RECV_PIN 4
#define POWER_LED_PIN 21