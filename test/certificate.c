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
#define AJ_MODULE TEST_CERTIFICATE

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <ajtcl/aj_debug.h>
#include <ajtcl/alljoyn.h>
#include <ajtcl/aj_cert.h>
#include <ajtcl/aj_crypto.h>
#include <ajtcl/aj_crypto_sha2.h>

uint8_t dbgTEST_CERTIFICATE = 1;

static const char pem_x509_self[] = {
    "-----BEGIN CERTIFICATE-----"
    "MIIBszCCAVmgAwIBAgIJAILNujb37gH2MAoGCCqGSM49BAMCMFYxKTAnBgNVBAsM"
    "IDdhNDhhYTI2YmM0MzQyZjZhNjYyMDBmNzdhODlkZDAyMSkwJwYDVQQDDCA3YTQ4"
    "YWEyNmJjNDM0MmY2YTY2MjAwZjc3YTg5ZGQwMjAeFw0xNTAyMjYyMTUxMjNaFw0x"
    "NjAyMjYyMTUxMjNaMFYxKTAnBgNVBAsMIDdhNDhhYTI2YmM0MzQyZjZhNjYyMDBm"
    "NzdhODlkZDAyMSkwJwYDVQQDDCA3YTQ4YWEyNmJjNDM0MmY2YTY2MjAwZjc3YTg5"
    "ZGQwMjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABGEkAUATvOE4uYmt/10vkTcU"
    "SA0C+YqHQ+fjzRASOHWIXBvpPiKgHcINtNFQsyX92L2tMT2Kn53zu+3S6UAwy6yj"
    "EDAOMAwGA1UdEwQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIgKit5yeq1uxTvdFmW"
    "LDeoxerqC1VqBrmyEvbp4oJfamsCIQDvMTmulW/Br/gY7GOP9H/4/BIEoR7UeAYS"
    "4xLyu+7OEA=="
    "-----END CERTIFICATE-----"
};

static const char pem_prv_1[] = {
    "-----BEGIN EC PRIVATE KEY-----"
    "MHcCAQEEIAqN6AtyOAPxY5k7eFNXAwzkbsGMl4uqvPrYkIj0LNZBoAoGCCqGSM49"
    "AwEHoUQDQgAEvnRd4fX9opwgXX4Em2UiCMsBbfaqhB1U5PJCDZacz9HumDEzYdrS"
    "MymSxR34lL0GJVgEECvBTvpaHP2bpTIl6g=="
    "-----END EC PRIVATE KEY-----"
};

static const char pem_x509_1[] = {
    "-----BEGIN CERTIFICATE-----"
    "MIIBtDCCAVmgAwIBAgIJAMlyFqk69v+OMAoGCCqGSM49BAMCMFYxKTAnBgNVBAsM"
    "IDdhNDhhYTI2YmM0MzQyZjZhNjYyMDBmNzdhODlkZDAyMSkwJwYDVQQDDCA3YTQ4"
    "YWEyNmJjNDM0MmY2YTY2MjAwZjc3YTg5ZGQwMjAeFw0xNTAyMjYyMTUxMjVaFw0x"
    "NjAyMjYyMTUxMjVaMFYxKTAnBgNVBAsMIDZkODVjMjkyMjYxM2IzNmUyZWVlZjUy"
    "NzgwNDJjYzU2MSkwJwYDVQQDDCA2ZDg1YzI5MjI2MTNiMzZlMmVlZWY1Mjc4MDQy"
    "Y2M1NjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABL50XeH1/aKcIF1+BJtlIgjL"
    "AW32qoQdVOTyQg2WnM/R7pgxM2Ha0jMpksUd+JS9BiVYBBArwU76Whz9m6UyJeqj"
    "EDAOMAwGA1UdEwQFMAMBAf8wCgYIKoZIzj0EAwIDSQAwRgIhAKfmglMgl67L5ALF"
    "Z63haubkItTMACY1k4ROC2q7cnVmAiEArvAmcVInOq/U5C1y2XrvJQnAdwSl/Ogr"
    "IizUeK0oI5c="
    "-----END CERTIFICATE-----"
};

static const char pem_prv_2[] = {
    "-----BEGIN EC PRIVATE KEY-----"
    "MHcCAQEEIIHvXKVlMAUG8NOeJ9SqQg3Op5kXIBRvoHowaLtySxhToAoGCCqGSM49"
    "AwEHoUQDQgAE79HKpErGIZVLzKvc1gPoCkKQtuc1JP9N9AGXGrvQWOQOSwzg3E82"
    "4DqEWkvOFEP1GHeagPFIINl6IUvcgISwLA=="
    "-----END EC PRIVATE KEY-----"
};

static const char pem_x509_2[] = {
    "-----BEGIN CERTIFICATE-----"
    "MIIBWzCCAQCgAwIBAgIJAN1+gCpX2RyfMAoGCCqGSM49BAMCMCsxKTAnBgNVBAMM"
    "IGE2NzgyNWUwZjZlYzZmZDlhMWVlYWJkNWMyNTg5Y2Q1MB4XDTE1MDMwMjE0NDYx"
    "N1oXDTE2MDMwMTE0NDYxN1owKzEpMCcGA1UEAwwgYTY3ODI1ZTBmNmVjNmZkOWEx"
    "ZWVhYmQ1YzI1ODljZDUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATv0cqkSsYh"
    "lUvMq9zWA+gKQpC25zUk/030AZcau9BY5A5LDODcTzbgOoRaS84UQ/UYd5qA8Ugg"
    "2XohS9yAhLAsow0wCzAJBgNVHRMEAjAAMAoGCCqGSM49BAMCA0kAMEYCIQCLChlN"
    "IoHhS7jbhbV96uyIthGEyJ62YvM+438VFMEHTwIhAOpxvefi7VFHQXhWpNE5KmG5"
    "zhXQwrpn6D0rMylIZ5/v"
    "-----END CERTIFICATE-----"
};

static const char pem_prv_3[] = {
    "-----BEGIN EC PRIVATE KEY-----"
    "MDECAQEEIICSqj3zTadctmGnwyC/SXLioO39pB1MlCbNEX04hjeioAoGCCqGSM49"
    "AwEH"
    "-----END EC PRIVATE KEY-----"
};

static const char pem_x509_3[] = {
    "-----BEGIN CERTIFICATE-----"
    "MIIBWjCCAQGgAwIBAgIHMTAxMDEwMTAKBggqhkjOPQQDAjArMSkwJwYDVQQDDCAw"
    "ZTE5YWZhNzlhMjliMjMwNDcyMGJkNGY2ZDVlMWIxOTAeFw0xNTAyMjYyMTU1MjVa"
    "Fw0xNjAyMjYyMTU1MjVaMCsxKTAnBgNVBAMMIDZhYWM5MjQwNDNjYjc5NmQ2ZGIy"
    "NmRlYmRkMGM5OWJkMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEP/HbYga30Afm"
    "0fB6g7KaB5Vr5CDyEkgmlif/PTsgwM2KKCMiAfcfto0+L1N0kvyAUgff6sLtTHU3"
    "IdHzyBmKP6MQMA4wDAYDVR0TBAUwAwEB/zAKBggqhkjOPQQDAgNHADBEAiAZmNVA"
    "m/H5EtJl/O9x0P4zt/UdrqiPg+gA+wm0yRY6KgIgetWANAE2otcrsj3ARZTY/aTI"
    "0GOQizWlQm8mpKaQ3uE="
    "-----END CERTIFICATE-----"
};

static const char pem_x509_4[] = {
    "-----BEGIN CERTIFICATE-----"
    "MIIBOjCB4aADAgECAgECMAoGCCqGSM49BAMCMCIxDjAMBgNVBAsMBUFkbWluMRAw"
    "DgYDVQQDDAdNYW5hZ2VyMB4XDTE1MDQyNzAyMTk1OFoXDTE2MDQyNjAyMTk1OFow"
    "HTEOMAwGA1UECwwFTWVkaWExCzAJBgNVBAMMAlRWMFkwEwYHKoZIzj0CAQYIKoZI"
    "zj0DAQcDQgAEXhpO6l5w9lARVZklVvYCnqvUnK1sQg+SFKERW9IOae0yUQJAoV5B"
    "L4YkaN3zQirDZzZefX4gIxIYXeLNLwYr8qMNMAswCQYDVR0TBAIwADAKBggqhkjO"
    "PQQDAgNIADBFAiA7aDL+XYAmfosrwINWWtwGcFDm1kSb7mw3N7tnXFwBHAIhAKeW"
    "LfgmobFgXu++LwVFg02BSLuL0IrFAysDcF8w9lxj"
    "-----END CERTIFICATE-----"
};

static const char pem_x509_5[] = {
    "-----BEGIN CERTIFICATE-----"
    "MIIBPTCB5KADAgECAgECMAoGCCqGSM49BAMCMCIxDjAMBgNVBAsMBUFkbWluMRAw"
    "DgYDVQQDDAdNYW5hZ2VyMB4XDTE1MDQyNzAyMjIyOFoXDTE2MDQyNjAyMjIyOFow"
    "HTEOMAwGA1UECwwFTWVkaWExCzAJBgNVBAMMAlRWMFkwEwYHKoZIzj0CAQYIKoZI"
    "zj0DAQcDQgAEXhpO6l5w9lARVZklVvYCnqvUnK1sQg+SFKERW9IOae0yUQJAoV5B"
    "L4YkaN3zQirDZzZefX4gIxIYXeLNLwYr8qMQMA4wDAYDVR0TBAUwAwEB/zAKBggq"
    "hkjOPQQDAgNIADBFAiEAoT1gFCwUONyeLaiyv4LZFxqMsCnGOYlDejfPBjfdlccC"
    "ICgI/7pny9QjuqKcX+FKUwqnq6IsOIaodvKNo3GlPe5O"
    "-----END CERTIFICATE-----"
};

static const char pem_x509_6[] = {
    "-----BEGIN CERTIFICATE-----"
    "MIIBPjCB5KADAgECAgECMAoGCCqGSM49BAMCMCIxDjAMBgNVBAsMBUFkbWluMRAw"
    "DgYDVQQDDAdNYW5hZ2VyMB4XDTE1MDQyNzAyMjM1NFoXDTE2MDQyNjAyMjM1NFow"
    "HTEOMAwGA1UECwwFTWVkaWExCzAJBgNVBAMMAlRWMFkwEwYHKoZIzj0CAQYIKoZI"
    "zj0DAQcDQgAEXhpO6l5w9lARVZklVvYCnqvUnK1sQg+SFKERW9IOae0yUQJAoV5B"
    "L4YkaN3zQirDZzZefX4gIxIYXeLNLwYr8qMQMA4wDAYDVR0TBAUwAwIBATAKBggq"
    "hkjOPQQDAgNJADBGAiEA4Laxe8SunKOjqohe5lFzSUQh3m9O2OdzV3ZKKcclMtEC"
    "IQCOVhnC7/PLFGXCY1uaJ/4cJvlLtUmLkMZVeYJRN3NSRA=="
    "-----END CERTIFICATE-----"
};

static const char pem_x509_7[] = {
    "-----BEGIN CERTIFICATE-----"
    "MIIBQjCB6qADAgECAgECMAoGCCqGSM49BAMCMCIxDjAMBgNVBAsMBUFkbWluMRAw"
    "DgYDVQQDDAdNYW5hZ2VyMB4XDTE1MDQyNzAyMjQwMloXDTE2MDQyNjAyMjQwMlow"
    "HTEOMAwGA1UECwwFTWVkaWExCzAJBgNVBAMMAlRWMFkwEwYHKoZIzj0CAQYIKoZI"
    "zj0DAQcDQgAEXhpO6l5w9lARVZklVvYCnqvUnK1sQg+SFKERW9IOae0yUQJAoV5B"
    "L4YkaN3zQirDZzZefX4gIxIYXeLNLwYr8qMWMBQwEgYDVR0TAQH/BAgwBgEB/wIB"
    "ATAKBggqhkjOPQQDAgNHADBEAiB4qUTMHJZMHtSvi9AKPRvG9JwkgFewBYpxvQad"
    "VbinnAIgWw4KgERCMAqSUbCVsQXGff87OPHrL1M1xsHpomG8Qhs="
    "-----END CERTIFICATE-----"
};

static const char pem_x509_8[] = {
    "-----BEGIN CERTIFICATE-----"
    "MIIBPjCB5KADAgECAgECMAoGCCqGSM49BAMCMCIxDjAMBgNVBAsMBUFkbWluMRAw"
    "DgYDVQQDDAdNYW5hZ2VyMB4XDTE1MDQyNzAyMjQyMVoXDTE2MDQyNjAyMjQyMVow"
    "HTEOMAwGA1UECwwFTWVkaWExCzAJBgNVBAMMAlRWMFkwEwYHKoZIzj0CAQYIKoZI"
    "zj0DAQcDQgAEXhpO6l5w9lARVZklVvYCnqvUnK1sQg+SFKERW9IOae0yUQJAoV5B"
    "L4YkaN3zQirDZzZefX4gIxIYXeLNLwYr8qMQMA4wDAYDVR0TAQH/BAIwADAKBggq"
    "hkjOPQQDAgNJADBGAiEA7lU0PJ5/TZgTj8EKiMUGIGsafxqZZVpjeeuC9yGskSwC"
    "IQCTgDOBsgKA74gf0pKipF7fA0+UDLpwMLQlw8P6YVidHQ=="
    "-----END CERTIFICATE-----"
};

static const char pem_x509_9[] = {
    "-----BEGIN CERTIFICATE-----"
    "MIIBiDCCAS+gAwIBAgIBATAKBggqhkjOPQQDAjAiMQ4wDAYDVQQLDAVBZG1pbjEQ"
    "MA4GA1UEAwwHTWFuYWdlcjAeFw0xNTA0MjcwMjM1MDFaFw0xNjA0MjYwMjM1MDFa"
    "MCIxDjAMBgNVBAsMBUFkbWluMRAwDgYDVQQDDAdNYW5hZ2VyMFkwEwYHKoZIzj0C"
    "AQYIKoZIzj0DAQcDQgAEPEPcAowvgJcSAVbZgJp1TjZ84VHtgITq/Ex3ayLMGrJ1"
    "aqA6+s9eOEYNGqvrZfQHRFcaM7m5MmRDn4J8PT+1oaNWMFQwDAYDVR0TAQH/BAIw"
    "ADAgBgNVHQ4BAf8EFgQU1Fg51CWrJVEvK0CmpqxH5cugqlgwIgYDVR0jAQH/BBgw"
    "FoAU1Fg51CWrJVEvK0CmpqxH5cugqlgwCgYIKoZIzj0EAwIDRwAwRAIgXzg72DWx"
    "EwY6xH6iVLvuqGW9cgBsgp/tPzkPwsmg0kcCIETALRqB6+bcIEgPLa6EG3/7rC44"
    "ZWyKXae3oh5W2t4k"
    "-----END CERTIFICATE-----"
};

// Identity certificate
static const char pem_x509_10[] = {
    "-----BEGIN CERTIFICATE-----"
    "MIIB8DCCAZagAwIBAgIBATAKBggqhkjOPQQDAjANMQswCQYDVQQDDAJjbjAeFw0x"
    "NTA1MjgwMDM3NTNaFw0xNjA1MjcwMDM3NTNaMA0xCzAJBgNVBAMMAmNuMFkwEwYH"
    "KoZIzj0CAQYIKoZIzj0DAQcDQgAEPEPcAowvgJcSAVbZgJp1TjZ84VHtgITq/Ex3"
    "ayLMGrJ1aqA6+s9eOEYNGqvrZfQHRFcaM7m5MmRDn4J8PT+1oaOB5jCB4zAMBgNV"
    "HRMBAf8EAjAAMCwGA1UdDgEB/wQiBCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAADAuBgNVHSMBAf8EJDAigCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAADARBgorBgEEAYLefAEBBAMCAQEwIwYDVR0RAQH/BBkwF6AVBgorBgEE"
    "AYLefAEEoAcEBWFsaWFzMD0GCisGAQQBgt58AQIELzAtBglghkgBZQMEAgEEIAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMAoGCCqGSM49BAMCA0gAMEUC"
    "IQDyo+zR+1Ba7Nud8X9I53ZF52tNn+ou4zSo9qIiEKmI5wIgTUO3+3HE0NN5uy8c"
    "aBmsqvqSzEvN/RQqsKXIyRUfQY8="
    "-----END CERTIFICATE-----"
};

// Security group certificate
static const char pem_x509_11[] = {
    "-----BEGIN CERTIFICATE-----"
    "MIIBuzCCAWKgAwIBAgIBATAKBggqhkjOPQQDAjANMQswCQYDVQQDDAJjbjAeFw0x"
    "NTA1MjcwNDAzMzhaFw0xNjA1MjYwNDAzMzhaMA0xCzAJBgNVBAMMAmNuMFkwEwYH"
    "KoZIzj0CAQYIKoZIzj0DAQcDQgAEPEPcAowvgJcSAVbZgJp1TjZ84VHtgITq/Ex3"
    "ayLMGrJ1aqA6+s9eOEYNGqvrZfQHRFcaM7m5MmRDn4J8PT+1oaOBsjCBrzAMBgNV"
    "HRMBAf8EAjAAMCwGA1UdDgEB/wQiBCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAADAuBgNVHSMBAf8EJDAigCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAADARBgorBgEEAYLefAEBBAMCAQIwLgYDVR0RAQH/BCQwIqAgBgorBgEE"
    "AYLefAEDoBIEEAAAAAAAAAAAAAAAAAAAAAAwCgYIKoZIzj0EAwIDRwAwRAIgaGVf"
    "HMKMdNPoBegHdikjI+tpNRWeh1rwg4xzKBnftWQCIFA6AK0Zm4cJfCvMw+Dx/rXa"
    "xqmf9RLcTk6jT96b0wGC"
    "-----END CERTIFICATE-----"
};

static const char pem_prv_12[] = {
    "-----BEGIN EC PRIVATE KEY-----"
    "MHcCAQEEINiXjrhr3NNV+NYcS9ZHuWGjOYVmK1l4S03QV+vn1mIIoAoGCCqGSM49"
    "AwEHoUQDQgAEZFf5jgxNc4wJ2qYcuBHcrWsxOXhMgtvyRMfH2ryM6aQPlioY/dnc"
    "XbWnsfO2FyE8wsdKLPeENJy+8g6p+RPEig=="
    "-----END EC PRIVATE KEY-----"
};

static const char pem_x509_12[] = {
    "-----BEGIN CERTIFICATE-----"
    "MIIB2jCCAYGgAwIBAgIBAjAKBggqhkjOPQQDAjANMQswCQYDVQQDDAJjbjAeFw0x"
    "NTA3MzEwNjUwMDhaFw0xNjA3MzAwNjUwMDhaMA0xCzAJBgNVBAMMAnR2MFkwEwYH"
    "KoZIzj0CAQYIKoZIzj0DAQcDQgAEZFf5jgxNc4wJ2qYcuBHcrWsxOXhMgtvyRMfH"
    "2ryM6aQPlioY/dncXbWnsfO2FyE8wsdKLPeENJy+8g6p+RPEiqOB0TCBzjAJBgNV"
    "HRMEAjAAMB0GA1UdDgQWBBQWI2DkX/AhybZBGOUP+LEJcNz2yjAfBgNVHSMEGDAW"
    "gBSqnBbXUz17dBCqTejIv0HoSS/xiTArBgNVHREEJDAioCAGCisGAQQBgt58AQSg"
    "EgQQAAAAAAAAAAAAAAAAAAAAADAVBgNVHSUEDjAMBgorBgEEAYLefAEBMD0GCisG"
    "AQQBgt58AQIELzAtBglghkgBZQMEAgEEIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAMAoGCCqGSM49BAMCA0cAMEQCIDjCZb6ALBxw+lc7i7oHDNwOQCIU"
    "BjYqtR4kr4LqdQktAiAfu5+EVXC1hDgK9bc91dy1cv21Pn9cL4FAVFX3xGm4hA=="
    "-----END CERTIFICATE-----"
    ""
    "-----BEGIN CERTIFICATE-----"
    "MIIBezCCASKgAwIBAgIBATAKBggqhkjOPQQDAjANMQswCQYDVQQDDAJjbjAeFw0x"
    "NTA3MzEwNjQ3NDlaFw0xNjA3MzAwNjQ3NDlaMA0xCzAJBgNVBAMMAmNuMFkwEwYH"
    "KoZIzj0CAQYIKoZIzj0DAQcDQgAE2+TD0C9O6nScng1lUl+s6pcrezUBySXVKadH"
    "7P8vAdvnnGtjSxSLdy/G1XDG/81cWf+W/sZcC+qCSbQg+EW/QqNzMHEwDAYDVR0T"
    "BAUwAwEB/zAdBgNVHQ4EFgQUqpwW11M9e3QQqk3oyL9B6Ekv8YkwHwYDVR0jBBgw"
    "FoAUqpwW11M9e3QQqk3oyL9B6Ekv8YkwIQYDVR0lBBowGAYKKwYBBAGC3nwBAQYK"
    "KwYBBAGC3nwBBTAKBggqhkjOPQQDAgNHADBEAiBVSPvp2t5Uct+Yrj43uC/eyKTb"
    "BQPY5bGS2yt8iReZ+AIgacrFYDzNnbUu39rtjn85kn3zWasFXmsa8R+mTmlJTFo="
    "-----END CERTIFICATE-----"
};

#define ASN_OCTETS           0x04
#define ASN_UTF8             0x0C
void PrintElement(const char* tag, DER_Element* der, uint8_t type)
{
    size_t i;

    if (0 == der->size) {
        return;
    }

    AJ_AlwaysPrintf(("%s: ", tag));
    for (i = 0; i < der->size; i++) {
        switch (type) {
        case ASN_OCTETS:
            AJ_AlwaysPrintf(("%02X", der->data[i]));
            break;

        case ASN_UTF8:
            AJ_AlwaysPrintf(("%c", (char) der->data[i]));
            break;
        }
    }
    AJ_AlwaysPrintf(("\n"));
}

void PrintCertificate(X509Certificate* certificate)
{
    AJ_AlwaysPrintf(("Certificate\n"));
    PrintElement("    Serial    ", &certificate->tbs.serial, ASN_OCTETS);
    PrintElement("    Issuer  OU", &certificate->tbs.issuer.ou, ASN_UTF8);
    PrintElement("    Issuer  CN", &certificate->tbs.issuer.cn, ASN_UTF8);
    PrintElement("    Subject OU", &certificate->tbs.subject.ou, ASN_UTF8);
    PrintElement("    Subject CN", &certificate->tbs.subject.cn, ASN_UTF8);
    AJ_AlwaysPrintf(("    Extensions\n"));
    PrintElement("        SKI   ", &certificate->tbs.extensions.ski, ASN_OCTETS);
    PrintElement("        AKI   ", &certificate->tbs.extensions.aki, ASN_OCTETS);
    PrintElement("        Alias ", &certificate->tbs.extensions.alias, ASN_UTF8);
    PrintElement("        Group ", &certificate->tbs.extensions.group, ASN_OCTETS);
    PrintElement("        Digest", &certificate->tbs.extensions.digest, ASN_OCTETS);
}

AJ_Status ParseCertificate(X509Certificate* certificate, const char* pem, uint8_t verify)
{
    AJ_Status status = AJ_OK;
    DER_Element der;

    status = AJ_X509DecodeCertificatePEM(certificate, pem);
    if (AJ_OK != status) {
        AJ_Printf("Parse: %s\n", AJ_StatusText(status));
        return status;
    }
    der.size = certificate->der.size;
    der.data = certificate->der.data;
    status = AJ_X509DecodeCertificateDER(certificate, &der);
    AJ_Printf("Parse: %s\n", AJ_StatusText(status));
    if (AJ_OK != status) {
        return status;
    }
    PrintCertificate(certificate);
    if (verify) {
        status = AJ_X509SelfVerify(certificate);
        AJ_Printf("Verify: %s\n", AJ_StatusText(status));
    }
    if (certificate->der.data) {
        AJ_Free(certificate->der.data);
    }
    return status;
}

int AJ_Main(int ac, char** av)
{
    AJ_Status status = AJ_OK;
    X509Certificate certificate;
    AJ_ECCPublicKey pub;
    AJ_ECCPrivateKey prv;
    AJ_ECCSignature sig;
    X509CertificateChain* head;
    X509CertificateChain* chain;
    uint8_t buffer[128];

    status = AJ_GenerateECCKeyPair(&pub, &prv);
    AJ_ASSERT(AJ_OK == status);
    status = AJ_ECDSASign(buffer, sizeof (buffer), &prv, &sig);
    AJ_ASSERT(AJ_OK == status);
    status = AJ_ECDSAVerify(buffer, sizeof (buffer), &sig, &pub);
    AJ_ASSERT(AJ_OK == status);

    status = ParseCertificate(&certificate, pem_x509_self, 1);

    status = ParseCertificate(&certificate, pem_x509_1, 0);
    status = AJ_DecodePrivateKeyPEM(&prv, pem_prv_1);
    AJ_ASSERT(AJ_OK == status);

    status = ParseCertificate(&certificate, pem_x509_2, 0);
    status = AJ_DecodePrivateKeyPEM(&prv, pem_prv_2);
    AJ_ASSERT(AJ_OK == status);

    status = ParseCertificate(&certificate, pem_x509_3, 0);
    status = AJ_DecodePrivateKeyPEM(&prv, pem_prv_3);
    AJ_ASSERT(AJ_OK == status);

    status = ParseCertificate(&certificate, pem_x509_4, 0);
    status = ParseCertificate(&certificate, pem_x509_5, 0);
    status = ParseCertificate(&certificate, pem_x509_6, 0);
    status = ParseCertificate(&certificate, pem_x509_7, 0);
    status = ParseCertificate(&certificate, pem_x509_8, 0);
    status = ParseCertificate(&certificate, pem_x509_9, 1);
    status = ParseCertificate(&certificate, pem_x509_10, 1);
    status = ParseCertificate(&certificate, pem_x509_11, 1);

    chain = AJ_X509DecodeCertificateChainPEM(pem_x509_12);
    head = chain;
    while (head) {
        PrintCertificate(&head->certificate);
        head = head->next;
    }
    AJ_X509FreeDecodedCertificateChain(chain);

    return 0;
}

#ifdef AJ_MAIN
int main(int ac, char** av)
{
    return AJ_Main(ac, av);
}
#endif
