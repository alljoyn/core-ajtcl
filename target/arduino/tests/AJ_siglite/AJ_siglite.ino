/**
 * @file
 */
/******************************************************************************
 *  * 
 *    Copyright (c) 2016 Open Connectivity Foundation and AllJoyn Open
 *    Source Project Contributors and others.
 *    
 *    All rights reserved. This program and the accompanying materials are
 *    made available under the terms of the Apache License, Version 2.0
 *    which accompanies this distribution, and is available at
 *    http://www.apache.org/licenses/LICENSE-2.0

 ******************************************************************************/

#include <stdint.h>
#include <stdarg.h>

#include <alljoyn.h>

#include <SPI.h>
#ifdef WIFI_UDP_WORKING
#include <WiFi.h>
#else
#include <Ethernet.h>
#endif

int AJ_Main(void);

void setup() {
    //Initialize serial and wait for port to open:
    Serial.begin(115200);
    while (!Serial) {
        ; // wait for serial port to connect. Needed for Leonardo only
    }

    AJ_Printf("setup");

#ifdef WIFI_UDP_WORKING
    char ssid[] = "eric-wifi";
    int status = WL_IDLE_STATUS;     // the Wifi radio's status

    if (WiFi.status() == WL_NO_SHIELD) {
        Serial.println("WiFi shield not present");
        // don't continue:
        while (true) ;
    }

    while (status != WL_CONNECTED) {
        Serial.print("Attempting to connect to open SSID: ");
        Serial.println(ssid);
        WiFi.begin(ssid);

        // wait 10 seconds for connection:
        delay(10000);
    }
#else
    byte mac[] = { 0x90, 0xA2, 0xDA, 0x0D, 0xA7, 0xCA };
    // start the Ethernet connection:
    if (Ethernet.begin(mac) == 0) {
        AJ_Printf("Failed to configure Ethernet using DHCP\n");
        // no point in carrying on, so do nothing forevermore:
        for (;;)
            ;
    }
#endif

}


void loop() {
    AJ_Main();
}
