#ifndef _AJ_CONVERSATIONHASH_H
#define _AJ_CONVERSATIONHASH_H

/**
 * @file aj_conversationhash.h
 * @defgroup aj_conversationhash Implementation of conversation hash mechanism
 * @{
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

#include <ajtcl/aj_config.h>
#include <ajtcl/aj_target.h>
#include <ajtcl/aj_authentication.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initialize/reset a conversation hash
 *
 * @param ctx          The authentication context
 *
 * @return
 *         - AJ_OK on success
 *         - An error status otherwise
 */
AJ_Status AJ_ConversationHash_Initialize(AJ_AuthenticationContext* ctx);

/**
 * Determine whether the conversation hash is initialized
 *
 * @param ctx          The authentication context
 *
 * @return
 *         - The value 1 if initialized
 *         - The value 0 if not initialized
 */
uint8_t AJ_ConversationHash_IsInitialized(AJ_AuthenticationContext* ctx);

/**
 * Update the conversation hash with a uint8_t
 *
 * @param ctx                   The authentication context
 * @param conversationVersion   The minimum authentication version which applies to this update
 * @param byte                  The byte to hash
 *
 */
void AJ_ConversationHash_Update_UInt8(AJ_AuthenticationContext* ctx, uint32_t conversationVersion, uint8_t byte);

/**
 * Update the conversation hash with a byte array
 *
 * @param ctx                   The authentication context
 * @param conversationVersion   The minimum authentication version which applies to this update
 * @param buf                   The input array to hash
 * @param bufSize               The size of buf
 *
 */
void AJ_ConversationHash_Update_UInt8Array(AJ_AuthenticationContext* ctx, uint32_t conversationVersion, const uint8_t* buf, size_t bufSize);

/**
 * Update the conversation hash with a string. This function does not assume a null-terminated
 * string; it will hash exactly the number of characters indicated by strSize.
 *
 * @param ctx                   The authentication context
 * @param conversationVersion   The minimum authentication version which applies to this update
 * @param str                   The string content to hash
 * @param strSize               The length of the string
 *
 */
void AJ_ConversationHash_Update_String(AJ_AuthenticationContext* ctx, uint32_t conversationVersion, const char* str, size_t strSize);

/**
 * Update the conversation hash with a message. If the message has been created locally with calls to AJ_Marshal*
 * functions, this function must be called BEFORE AJ_DeliverMsg or AJ_DeliverMsgPartial is called on it.
 *
 * If isMarshaledMessage is HASH_MSG_UNMARSHALED, the message will be reset to the beginning as a consequence
 * of calling this function. Any subsequent argument unmarshaling calls will start at the beginning of the message.
 * It is therefore recommended to call this function before or after all argument unmarshaling.
 *
 * @param ctx                   The authentication context
 * @param conversationVersion   The minimum authentication version which applies to this update
 * @param msg                   The pointer to a message that was unmarshaled by an earlier call to AJ_UnmarshalMsg
 *                              or created by calls to AJ_Marshal*
 * @param isMarshaledMessage    HASH_MSG_MARSHALED if msg was created locally through AJ_Marshal* calls,
 *                              or HASH_MSG_UNMARSHALED if received through a call to AJ_UnmarshalMsg
 *
 */
void AJ_ConversationHash_Update_Message(AJ_AuthenticationContext* ctx, uint32_t conversationVersion, AJ_Message* msg, uint8_t isMarshaledMessage);

/**
 * Get the conversation hash
 *
 * @param ctx           The authentication context
 *
 * @return
 *         - AJ_OK on success
 *         - An error status otherwise
 */
AJ_Status AJ_ConversationHash_GetDigest(AJ_AuthenticationContext* ctx);

/**
 * Reset the conversation hash
 *
 * @param ctx           The authentication context
 *
 * @return
 *         - AJ_OK on success
 *         - An error status otherwise
 */
AJ_Status AJ_ConversationHash_Reset(AJ_AuthenticationContext* ctx);

/**
 * Enable or disable "sensitive mode," where byte arrays that get hashed aren't
 * logged verbatim. When enabled, calling AJ_ConversationHash_Update_UInt8Array,
 * AJ_ConversationHash_Update_String, or AJ_ConversationHash_Update_Message will
 * log the size of the data, but then log that secret data was hashed without
 * showing the data.
 *
 * Other conversation hash functions, including AJ_ConversationHash_Update_UInt8, are
 * unaffected by this setting.
 * @param ctx           The authentication context
 * @param mode          TRUE to enable sensitive mode; FALSE to disable
 */
void AJ_ConversationHash_SetSensitiveMode(AJ_AuthenticationContext* ctx, uint8_t mode);

#ifdef __cplusplus
}
#endif
/**
 * @}
 */
#endif

