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

/**
 * Per-module definition of the current module for debug logging.  Must be defined
 * prior to first inclusion of aj_debug.h
 */
#define AJ_MODULE CONVERSATIONHASH

#include <ajtcl/aj_target.h>
#include <ajtcl/aj_debug.h>
#include <ajtcl/aj_conversationhash.h>
#include <ajtcl/aj_msg_priv.h>

/* SECURITY NOTE: Because the pre-shared key is hashed into the conversation hash
 * for the ECDHE_PSK method in conversation versions <= 3, to avoid unintentional
 * disclosure, the bytes of the PSK not traced in the log, but instead an entry stating
 * that secret data is hashed in at that point is added. To override this behavior and
 * include secret data in the log, define the CONVERSATION_HASH_TRACE_SECRETS constant.
 */
#undef CONVERSATION_HASH_LOG_SECRETS

/**
 * Turn on per-module debug printing by setting this variable to non-zero value
 * (usually in debugger).
 */
#ifndef NDEBUG
uint8_t dbgCONVERSATIONHASH = 0;
#endif

/* For purposes of debugging, try and keep the trace logging prints the same as they are
 * in standard client so diffing tools can be used.
 */

AJ_Status AJ_ConversationHash_Initialize(AJ_AuthenticationContext* ctx)
{
    AJ_InfoPrintf(("InitializeConversationHash ------------------------------------\n"));

    ctx->hash = AJ_SHA256_Init();

    if (ctx->hash) {
        return AJ_OK;
    } else {
        AJ_ErrPrintf(("AJ_ConversationHash_Initialize() failed\n"));
        return AJ_ERR_RESOURCES;
    }
}

uint8_t AJ_ConversationHash_IsInitialized(AJ_AuthenticationContext* ctx)
{
    if (ctx->hash) {
        return 1;
    }
    return 0;
}

static inline int ConversationVersionDoesNotApply(uint32_t conversationVersion, uint32_t currentAuthVersion)
{
    AJ_ASSERT((CONVERSATION_V1 == conversationVersion) || (CONVERSATION_V4 == conversationVersion));

    /* The conversation version itself is computed by taking (currentAuthVersion >> 16). We return true
     * if the current conversation version does NOT apply to the conversation version for the message being hashed.
     */
    if (CONVERSATION_V4 == conversationVersion) {
        return ((currentAuthVersion >> 16) != CONVERSATION_V4);
    } else {
        return ((currentAuthVersion >> 16) >= CONVERSATION_V4);
    }
}

void AJ_ConversationHash_Update_UInt8(AJ_AuthenticationContext* ctx, uint32_t conversationVersion, uint8_t byte)
{
    if (ConversationVersionDoesNotApply(conversationVersion, ctx->version)) {
        return;
    }
    AJ_SHA256_Update(ctx->hash, &byte, sizeof(byte));
    AJ_InfoPrintf(("Hashed byte: %02X\n", byte));
}

static void ConversationHash_Update_UInt32(AJ_AuthenticationContext* ctx, uint32_t u32)
{
    /* Make sure any functions calling this code are doing the appropriate trace logging! */
    uint8_t u32LE[sizeof(uint32_t)];
    HostU32ToLittleEndianU8(&u32, sizeof(u32), u32LE);
    AJ_SHA256_Update(ctx->hash, u32LE, sizeof(u32LE));
}

void AJ_ConversationHash_Update_UInt8Array(AJ_AuthenticationContext* ctx, uint32_t conversationVersion, const uint8_t* buf, size_t bufSize)
{
    if (ConversationVersionDoesNotApply(conversationVersion, ctx->version)) {
        return;
    }
    if (conversationVersion >= CONVERSATION_V4) {
        AJ_ASSERT(bufSize <= 0xFFFFFFFF);
        ConversationHash_Update_UInt32(ctx, (uint32_t)bufSize);
#if defined(_MSC_VER)
        AJ_InfoPrintf(("Hashed size: %Iu\n", bufSize));
#else
        AJ_InfoPrintf(("Hashed size: %zu\n", bufSize));
#endif
    }
    AJ_SHA256_Update(ctx->hash, buf, bufSize);
#ifndef CONVERSATION_HASH_LOG_SECRETS
    /* Compare != FALSE just in case a caller passes something nonzero but not TRUE (1) into
     * AJ_ConversationHash_SetSensitiveMode.
     */
    if (ctx->sensitiveMode != FALSE) {
        AJ_InfoPrintf(("Hashed byte array of secret data; data intentionally not logged\n"));
    } else {
#endif
    AJ_InfoPrintf(("Hashed byte array:\n"));
    AJ_DumpBytes(NULL, buf, bufSize);
#ifndef CONVERSATION_HASH_LOG_SECRETS
}
#endif
}

void AJ_ConversationHash_Update_String(AJ_AuthenticationContext* ctx, uint32_t conversationVersion, const char* str, size_t strSize)
{
    AJ_ConversationHash_Update_UInt8Array(ctx, conversationVersion, (const uint8_t*)str, strSize);
}

void AJ_ConversationHash_Update_Message(AJ_AuthenticationContext* ctx, uint32_t conversationVersion, AJ_Message* msg, uint8_t isMarshaledMessage)
{
    uint8_t* data;
    uint32_t size;
    AJ_MsgHeader hdr;

    if (ConversationVersionDoesNotApply(conversationVersion, ctx->version)) {
        return;
    }

    AJ_ASSERT((HASH_MSG_UNMARSHALED == isMarshaledMessage) || (HASH_MSG_MARSHALED == isMarshaledMessage));

    AJ_ASSERT(!(msg->hdr->flags & AJ_FLAG_ENCRYPTED));

    if (HASH_MSG_MARSHALED == isMarshaledMessage) {
        /* msg->hdr->bodyLen gets set by AJ_DeliverMsg when the message is sent out. We set it here as well
         * so that the buffer we hash equals what will actually go out on the wire.
         */
        AJ_ASSERT(0 == msg->hdr->bodyLen);
        msg->hdr->bodyLen = msg->bodyBytes;
        data = msg->bus->sock.tx.bufStart;
        size = sizeof(AJ_MsgHeader) + msg->hdr->headerLen + HEADERPAD(msg->hdr->headerLen) + msg->hdr->bodyLen;
        AJ_ConversationHash_Update_UInt8Array(ctx, conversationVersion, data, size);
    } else {
        /*
         * AJ_UnmarshalMsg ensures that the Peer.Authentication interface messages are loaded into the buffer.
         * The message header may have been endian swapped, so we use the raw header saved during AJ_UnmarshalMsg.
         */
        data = msg->bus->sock.rx.bufStart;
        size = sizeof(AJ_MsgHeader) + msg->hdr->headerLen + HEADERPAD(msg->hdr->headerLen) + msg->hdr->bodyLen;
        /* Save the current header */
        memcpy(&hdr, data, sizeof(AJ_MsgHeader));
        /* Replace with original header */
        memcpy(data, &msg->raw, sizeof(AJ_MsgHeader));
        AJ_ConversationHash_Update_UInt8Array(ctx, conversationVersion, data, size);
        /* Put the header back */
        memcpy(data, &hdr, sizeof(AJ_MsgHeader));
    }
}

AJ_Status AJ_ConversationHash_GetDigest(AJ_AuthenticationContext* ctx)
{
    AJ_Status status;
    status = AJ_SHA256_GetDigest(ctx->hash, ctx->digest);

    AJ_InfoPrintf(("Got conversation digest ------------------------------------\n"));
    AJ_InfoPrintf(("Digest is: \n"));
    AJ_DumpBytes(NULL, ctx->digest, AJ_SHA256_DIGEST_LENGTH);
    return status;
}

AJ_Status AJ_ConversationHash_Reset(AJ_AuthenticationContext* ctx)
{
    AJ_Status status;

    status = AJ_SHA256_Final(ctx->hash, NULL);

    if (status == AJ_OK) {
        /* Call to AJ_ConversationHash_Initialize will handle trace logging. */
        status = AJ_ConversationHash_Initialize(ctx);
    }

    return status;
}

void AJ_ConversationHash_SetSensitiveMode(AJ_AuthenticationContext* ctx, uint8_t mode)
{
    ctx->sensitiveMode = mode;
}
