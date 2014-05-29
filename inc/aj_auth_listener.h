#ifndef _AJ_AUTH_LISTENER_H
#define _AJ_AUTH_LISTENER_H
/**
 * @file aj_auth_listener.h
 * @defgroup aj_auth_listener Authentication Listener
 * @{
 */
/******************************************************************************
 * Copyright (c) 2014, AllSeen Alliance. All rights reserved.
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

#include "aj_target.h"
#include "aj_net.h"
#include "aj_status.h"
#include "aj_util.h"

/*
 * Command
 */
#define AJ_CRED_PRV_KEY    0x00000001
#define AJ_CRED_PUB_KEY    0x00000002
#define AJ_CRED_CERT_CHAIN 0x00000004

typedef struct _AJ_Credential {
    uint32_t mask;
    uint32_t expiration;
    uint8_t* data;
    size_t len;
} AJ_Credential;

#endif
