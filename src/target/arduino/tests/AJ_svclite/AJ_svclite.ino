/**
 * @file
 */
/******************************************************************************
 * Copyright AllSeen Alliance. All rights reserved.
 *
 *    Permission to use, copy, modify, and/or distribute this software for any
 *    purpose with or without fee is hereby granted, provided that the above
 *    copyright notice and this permission notice appear in all copies.
 *
 *    THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 *    WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 *    MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 *    ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 *    WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 *    ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 *    OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 ******************************************************************************/

#include <stdint.h>
#include <stdarg.h>
//#include <stdio.h>

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
        WiFi.begin(ssid);
        if (WiFi.status() == WL_CONNECTED) {
            break;
        }
        delay(10000);
    }
    IPAddress ip = WiFi.localIP();
    Serial.print("Connected: ");
    Serial.println(ip);
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

