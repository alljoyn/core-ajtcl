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
#include <stdio.h>

#undef WIFI_UDP_WORKING

#include <SPI.h>
#ifdef WIFI_UDP_WORKING
#include <WiFi.h>
#else
#include <Ethernet.h>
#endif

#include <alljoyn.h>

#ifdef WIFI_UDP_WORKING
static char ssid[] = "pez-wifi";
static char pass[] = "71DF437B55"; // passphrase for the SSID
#endif

int AJ_Main();


void setup() {

    //Initialize serial and wait for port to open:
    Serial.begin(115200);
    while (!Serial) {
        ; // wait for serial port to connect. Needed for Leonardo only
    }

    AJ_Printf("hello, world.\n");

#ifdef WIFI_UDP_WORKING
    // check for the presence of the shield:
    unsigned int retries = 10;
    while (WiFi.status() == WL_NO_SHIELD) {
        if (retries == 0) {
            Serial.println("WiFi shield not present");
            // don't continue:
            while (true);
        }
        retries--;
        delay(500);
    }

    // attempt to connect to Wifi network:
    while (true) {
        Serial.print("Attempting to connect to open SSID: ");
        Serial.println(ssid);
        // Connect to WEP private network
        WiFi.begin(ssid, 0, pass);
        if (WiFi.status() == WL_CONNECTED) {
            break;
        }
        delay(10000);
    }
    IPAddress ip = WiFi.localIP();
    Serial.print("Connected: ");
    Serial.println(ip);
#else
    byte mac[] = { 0x00, 0xAA, 0xBB, 0xCC, 0xDE, 0x02 };
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
