/**
 * @file
 */
/******************************************************************************
 * Copyright (c) 2012-2014, AllSeen Alliance. All rights reserved.
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
#define AJ_MODULE SASL

#include "aj_target.h"
#include "aj_status.h"
#include "aj_sasl.h"
#include "aj_util.h"
#include "aj_creds.h"
#include "aj_debug.h"

#include <stdlib.h>
#include <string.h>

#include "aj_config.h"

/**
 * Turn on per-module debug printing by setting this variable to non-zero value
 * (usually in debugger).
 */
#ifndef NDEBUG
uint8_t dbgSASL = 0;
#endif


/*
 * Sanity check value to prevent broken implementations from looping the state machine.
 */
#define MAX_AUTH_COUNT 8
#define PROTO_VERSION 8

#define STRING_FROM_VALUE(x) # x
#define VERSION_CMD(x) "INFORM_PROTO_VERSION " STRING_FROM_VALUE(x)
static const char CMD_PROTO_VER[] = VERSION_CMD(PROTO_VERSION);

static const char CMD_AUTH[]     = "AUTH";
static const char CMD_CANCEL[]   = "CANCEL";
static const char CMD_BEGIN[]    = "BEGIN";
static const char CMD_DATA[]     = "DATA";
static const char CMD_ERROR[]    = "ERROR";
static const char CMD_REJECTED[] = "REJECTED";
static const char CMD_OK[]       = "OK";
static const char CMD_PROTO[]    = "INFORM_PROTO_VERSION";

static const char* const CmdList[] = {
    CMD_AUTH,
    CMD_CANCEL,
    CMD_BEGIN,
    CMD_DATA,
    CMD_ERROR,
    CMD_REJECTED,
    CMD_OK,
    CMD_PROTO
};

AJ_Status AJ_SASL_InitContext(AJ_SASL_Context* context, const AJ_AuthMechanism* const* mechList, uint8_t role, AJ_AuthPwdFunc pwdFunc, uint8_t peer2peer)
{
    AJ_InfoPrintf(("AJ_SASL_InitContext(context=0x%p, mechList=0x%p, role=%d., pwdfunc=0x%p)\n", context, mechList, role, pwdFunc));

    if (!context || !mechList || !*mechList) {
        AJ_ErrPrintf(("AJ_SASL_InitContext(): AJ_ERR_NULL\n"));
        return AJ_ERR_NULL;
    }
    context->role = role;
    context->authCount = 0;
    context->state = (role == AJ_AUTH_RESPONDER) ? AJ_SASL_SEND_AUTH_REQ : AJ_SASL_WAIT_FOR_AUTH;
    context->pwdFunc = pwdFunc;
    context->mechList = mechList;
    context->mechanism = NULL;
    context->nextMech = -1;
    context->peer2peer = peer2peer;
    return AJ_OK;
}

/*
 * Check if the string matches any of the authentication mechanisms.
 */
static const AJ_AuthMechanism* MatchMechanism(AJ_SASL_Context* context, char** str)
{
    const AJ_AuthMechanism* const* mech = context->mechList;

    AJ_InfoPrintf(("MatchMechanism(context=0x%p, str=0x%p)\n", context, str));

    while (*mech) {
        size_t len = strlen(*str);
        size_t sz = strlen((*mech)->name);
        if ((len >= sz) && (memcmp((*mech)->name, *str, sz) == 0)) {
            *str += sz;
            /*
             * There might be initial response data following the auth mechanism name
             */
            if ((*str)[0] == ' ') {
                *str += 1;
            }
            AJ_InfoPrintf(("MatchMechanism(): mech=0x%p\n", mech));
            return *mech;
        }
        ++mech;
    }

    AJ_InfoPrintf(("MatchMechanism(): NULL\n"));
    return NULL;
}

/*
 * Inplace decode a hex encoded ascii string
 */
static AJ_Status HexDecode(char* str)
{
    AJ_Status status = AJ_OK;
    size_t sz = strlen(str);
    if (sz) {
        status = AJ_HexToRaw(str, sz, (uint8_t*)str, sz - 1);
    }
    /*
     * NUL terminate the result
     */
    str[sz / 2] = '\0';
    return status;
}

/*
 * Identify the command
 */
static const char* ParseCmd(char** str)
{
    uint32_t i;
    char* cmdString = *str;
    size_t sz = strlen(cmdString);

    AJ_InfoPrintf(("ParseCmd(str=0x%p)\n", str));

    if (sz < 4) {
        AJ_InfoPrintf(("ParseCmd(): NULL\n"));
        return NULL;
    }
    /*
     * Check for trailing CRLF and remove it
     */
    if (cmdString[sz - 2] != '\r' && cmdString[sz - 1] != '\n') {
        AJ_InfoPrintf(("ParseCmd(): NULL\n"));
        return NULL;
    }
    cmdString[sz - 1] = 0;
    cmdString[sz - 2] = 0;

    for (i = 0; i < ArraySize(CmdList); ++i) {
        const char* cmd = CmdList[i];
        size_t cmdLen = strlen(cmd);
        if ((sz >= cmdLen) && (memcmp(cmdString, cmd, cmdLen) == 0)) {
            /*
             * Command must be followed by NUL or space
             */
            if (cmdString[cmdLen]) {
                if (cmdString[cmdLen] != ' ') {
                    break;
                }
                /*
                 * Skip space
                 */
                ++cmdLen;
            }
            *str += cmdLen;
            AJ_InfoPrintf(("ParseCmd(): \"%s\"\n", cmd));
            return cmd;
        }
    }
    AJ_InfoPrintf(("ParseCmd(): NULL\n"));
    return NULL;
}

/**
 * Prepend a string followed by a space to the buffer
 *
 * If hexify == TRUE do an inplace ascii-hex encoding before prepending the string. The assumption
 * is that the input string is NUL terminated ascii string. This is true for all of the current
 * AllJoyn authentication mechanisms.
 */
static AJ_Status PrependStr(const char* str, char* buf, uint32_t bufLen, uint8_t hexify)
{
    size_t used = strlen(buf);
    size_t sz = strlen(str);

    if (hexify && (used > 0)) {
        AJ_Status status = AJ_RawToHex((uint8_t*) buf, used, buf, bufLen, FALSE);
        if (status != AJ_OK) {
            return status;
        }
        /* Conversion to hex doubles the size of the string */
        used *= 2;
    }
    if ((used + sz + 1) >= bufLen) {
        return AJ_ERR_RESOURCES;
    }
    if (used) {
        memmove(buf + sz + 1, buf, used + 1);
        memcpy(buf, str, sz);
        buf[sz] = ' ';
    } else {
        memcpy(buf, str, sz);
        buf[sz] = '\0';
    }
    return AJ_OK;
}

/**
 * Copy a string to a buffer
 */
static AJ_Status SetStr(const char* str, char* buf, uint32_t bufLen)
{
    size_t sz = strlen(str);
    if (sz >= bufLen) {
        return AJ_ERR_RESOURCES;
    } else {
        memcpy(buf, str, sz + 1);
        return AJ_OK;
    }
}

/**
 * Append the final CRLF to the buffer. NUL terminate so strlen works.
 */
static AJ_Status AppendCRLF(char* buf, uint32_t bufLen)
{
    size_t used = strlen(buf);
    if ((used + 3) > bufLen) {
        return AJ_ERR_RESOURCES;
    } else {
        buf[used] = '\r';
        buf[used + 1] = '\n';
        buf[used + 2] = '\0';
        return AJ_OK;
    }
}

/*
 * Compose a REJECTED response that lists the supported authentication mechanisms
 */
static AJ_Status Rejected(AJ_SASL_Context* context, char* outStr, uint32_t outLen)
{
    const AJ_AuthMechanism* const* mech = context->mechList;

    AJ_InfoPrintf(("Rejected(context=0x%p, outStr=0x%p, outLen=%d.)\n", context, outStr, outLen));

    SetStr(CMD_REJECTED, outStr, outLen);
    outLen -= (uint32_t)sizeof(CMD_REJECTED);
    while (*mech) {
        uint32_t len = strlen(outStr);
        outLen -= (uint32_t)(strlen((*mech)->name) + 1);
        if ((int32_t)outLen < 0) {
            return AJ_ERR_RESOURCES;
        }
        outStr[len++] = ' ';
        strcpy(outStr + len, (*mech)->name);
        ++mech;
    }
    return AJ_OK;
}

/*
 * Challenger side of the SASL conversation
 */
static AJ_Status Challenge(AJ_SASL_Context* context, char* inStr, char* outStr, uint32_t outLen)
{
    AJ_Status status = AJ_OK;
    AJ_AuthResult result;
    const char* rsp = outStr;
    const char* cmd;

    AJ_InfoPrintf(("Challenge(context=0x%p, inStr=\"%s\", outStr=0x%p, outLen=%d.)\n", context, inStr, outStr, outLen));

    cmd = ParseCmd(&inStr);

    /*
     * The ERROR command is handled the same in all states.
     */
    if (cmd == CMD_ERROR || ((cmd == CMD_CANCEL) && (context->state != AJ_SASL_WAIT_FOR_AUTH))) {
        status = Rejected(context, outStr, outLen);
        if (status == AJ_OK) {
            status = AppendCRLF(outStr, outLen);
        }
        context->state = AJ_SASL_WAIT_FOR_AUTH;
        return status;
    }
    switch (context->state) {
    case AJ_SASL_WAIT_FOR_AUTH:
        AJ_InfoPrintf(("Challenge(): AJ_SASL_WAIT_FOR_AUTH\n"));
        if (cmd == CMD_AUTH) {
            context->mechanism = MatchMechanism(context, &inStr);
            if (!context->mechanism) {
                result = AJ_AUTH_STATUS_RETRY;
                status = Rejected(context, outStr, outLen);
                break;
            } else {
                status = context->mechanism->Init(AJ_AUTH_CHALLENGER, context->pwdFunc);
                /*
                 * Initialization must succeed
                 */
                if (status != AJ_OK) {
                    break;
                }
            }
            /*
             * Data following an AUTH command is handled sames as DATA command
             */
            if ((*inStr) || (strcmp(context->mechanism->name, "ANONYMOUS") == 0)) {
                cmd = CMD_DATA;
            } else {
                break;
            }
        }
    /* Falling through */

    case AJ_SASL_WAIT_FOR_DATA:
        AJ_InfoPrintf(("Challenge(): AJ_SASL_WAIT_FOR_DATA\n"));
        if (cmd == CMD_DATA) {
            if (strcmp(context->mechanism->name, "ANONYMOUS") != 0) {
                status = HexDecode(inStr);
            }
            if (status == AJ_OK) {
                result = context->mechanism->Challenge(inStr, outStr, outLen);
                if (result == AJ_AUTH_STATUS_SUCCESS) {
                    AJ_GUID localGuid;
                    AJ_GetLocalGUID(&localGuid);
                    status = AJ_GUID_ToString(&localGuid, outStr, outLen);
                    if (status == AJ_OK) {
                        status = PrependStr(CMD_OK, outStr, outLen, FALSE);
                    }
                    context->state = AJ_SASL_WAIT_FOR_BEGIN;
                } else if (result == AJ_AUTH_STATUS_CONTINUE) {
                    status = PrependStr(CMD_DATA, outStr, outLen, TRUE);
                    context->state = AJ_SASL_WAIT_FOR_DATA;
                } else if (result == AJ_AUTH_STATUS_RETRY) {
                    status = Rejected(context, outStr, outLen);
                } else if (result == AJ_AUTH_STATUS_FAILURE) {
                    status = AJ_ERR_SECURITY;
                } else {
                    rsp = CMD_ERROR;
                }
            }
        } else if (cmd == CMD_BEGIN) {
            AJ_ErrPrintf(("Challenge(): AJ_ERR_SECURITY\n"));
            status = AJ_ERR_SECURITY;
        } else {
            rsp = CMD_ERROR;
        }
        break;

    case AJ_SASL_WAIT_FOR_BEGIN:
        AJ_InfoPrintf(("Challenge(): AJ_SASL_WAIT_FOR_BEGIN\n"));
        if (cmd == CMD_BEGIN) {
            context->state = AJ_SASL_AUTHENTICATED;
        } else {
            rsp = CMD_ERROR;
        }
        break;

    default:
        AJ_ErrPrintf(("Challenge(): AJ_ERR_UNEXPECTED\n"));
        status = AJ_ERR_UNEXPECTED;
    }

    if (status == AJ_OK) {
        if (rsp != outStr) {
            status = SetStr(rsp, outStr, outLen);
        }
    }

    /* The Challenger does not send out any SASL message once the state is AJ_SASL_AUTHENTICATED
       i.e after the BEGIN command is received. So we should not append the CRLF. This results
       in unwanted bytes being put in the tx buffer which gets sent out to the Responder. */
    if ((status == AJ_OK) && (context->state != AJ_SASL_AUTHENTICATED)) {
        status = AppendCRLF(outStr, outLen);
    }
    return status;
}

static const AJ_AuthMechanism* SelectAuth(AJ_SASL_Context* context, char* inStr)
{
    const AJ_AuthMechanism* mech = NULL;

    if (!*inStr) {
        return context->mechList[context->nextMech];
    }
    while (!mech && *inStr) {
        int32_t pos = AJ_StringFindFirstOf(inStr, " ");
        if (pos > 0) {
            inStr[pos] = '\0';
        }
        mech = MatchMechanism(context, &inStr);
        inStr += pos;
    }
    return mech;
}

/*
 * Responder side of the SASL conversation
 */
static AJ_Status Response(AJ_SASL_Context* context, char* inStr, char* outStr, uint32_t outLen)
{
    AJ_Status status = AJ_OK;
    AJ_AuthResult result;
    const char* cmd;
    const char* rsp = outStr;

    if (context->state == AJ_SASL_SEND_AUTH_REQ) {
        cmd = CMD_REJECTED;
    } else {
        cmd = ParseCmd(&inStr);
    }
    /*
     * The REJECTED command is handled the same in all states
     */
    if (cmd == CMD_REJECTED) {
        context->nextMech++;
        context->mechanism = SelectAuth(context, "");
        if (!context->mechanism) {
            /*
             * No mechanism in common so authentication fails.
             */
            return AJ_ERR_SECURITY;
        }
        status = context->mechanism->Init(AJ_AUTH_RESPONDER, context->pwdFunc);
        /*
         * Initialization must succeed
         */
        if (status != AJ_OK) {
            return status;
        }
        result = context->mechanism->Response(NULL, outStr, outLen);
        if ((result == AJ_AUTH_STATUS_SUCCESS) || (result == AJ_AUTH_STATUS_CONTINUE)) {
            status = PrependStr(context->mechanism->name, outStr, outLen, TRUE);
            if (status == AJ_OK) {
                status = PrependStr(CMD_AUTH, outStr, outLen, FALSE);
            }
            if (status == AJ_OK) {
                status = AppendCRLF(outStr, outLen);
            }
            AJ_InfoPrintf(("Response(): result = %u\n", result));
            context->state = (result == AJ_AUTH_STATUS_SUCCESS) ? AJ_SASL_WAIT_FOR_OK : AJ_SASL_WAIT_FOR_DATA;
        } else {
            status = AJ_ERR_SECURITY;
        }
        return status;
    }
    switch (context->state) {
    /*
     * Wait to receive the daemons protocol version
     */
    case AJ_SASL_WAIT_FOR_VERSION:
        AJ_InfoPrintf(("Response(): AJ_SASL_WAIT_FOR_VERSION\n"));
        if (cmd == CMD_PROTO || cmd == CMD_ERROR) {
            /* What's left in inStr should be the daemon's version number */
            unsigned int version = (cmd == CMD_PROTO) ? atoi(inStr) : 0;
            /* If the daemons version is valid... */
            if (version != 0) {
                AJ_InfoPrintf(("Response(): Version number = %u\n", version));
                /* Our version is higher so reject the connection */
                if (version < PROTO_VERSION) {
                    rsp = CMD_CANCEL;
                    context->state = AJ_SASL_WAIT_FOR_REJECT;
                    break;
                    /* Our version is either the same or lower so send BEGIN */
                } else {

                    AJ_GUID localGuid;
                    AJ_GetLocalGUID(&localGuid);
                    status = AJ_GUID_ToString(&localGuid, outStr, outLen);
                    if (status == AJ_OK) {
                        status = PrependStr(CMD_BEGIN, outStr, outLen, FALSE);
                    }

                    context->state = AJ_SASL_AUTHENTICATED;
                }
            } else {
                /* Daemons version was 0 (it was either never sent or the value it sent was invalid) */
                AJ_ErrPrintf(("Response(): Version number = invalid\n"));
                rsp = CMD_CANCEL;
                context->state = AJ_SASL_WAIT_FOR_REJECT;
                break;
            }
        }
        break;

    case AJ_SASL_BEGIN:
        if (cmd == CMD_OK) {
            AJ_GUID localGuid;
            AJ_GetLocalGUID(&localGuid);
            status = AJ_GUID_ToString(&localGuid, outStr, outLen);
            if (status == AJ_OK) {
                status = PrependStr(CMD_BEGIN, outStr, outLen, FALSE);
            }
            context->state = AJ_SASL_AUTHENTICATED;
        } else {
            context->state = AJ_SASL_WAIT_FOR_REJECT;
        }
        break;

    case AJ_SASL_WAIT_FOR_DATA:
        AJ_InfoPrintf(("Response(): AJ_SASL_WAIT_FOR_DATA\n"));
        if (cmd == CMD_DATA) {
            status = HexDecode(inStr);
            if (status == AJ_OK) {
                result = context->mechanism->Response(inStr, outStr, outLen);
                if (result == AJ_AUTH_STATUS_SUCCESS) {
                    status = PrependStr(CMD_DATA, outStr, outLen, TRUE);
                    if (context->peer2peer) {
                        context->state = AJ_SASL_BEGIN;
                        break;
                    }
                } else if (result == AJ_AUTH_STATUS_ERROR) {
                    status = context->mechanism->Init(AJ_AUTH_RESPONDER, context->pwdFunc);
                    /*
                     * Initialization must succeed
                     */
                    if (status != AJ_OK) {
                        return status;
                    }
                    context->state = AJ_SASL_WAIT_FOR_REJECT;
                    rsp = CMD_CANCEL;
                } else if (result != AJ_AUTH_STATUS_CONTINUE) {
                    if (result == AJ_AUTH_STATUS_RETRY &&
                        context->mechList[context->nextMech + 1] != NULL) {
                        // Notify the challenger to give up on the current authentication mechanism and to be in WAIT_FOR_AUTH state
                        rsp = CMD_ERROR;
                    } else {
                        status = AJ_ERR_SECURITY;
                    }
                }
            }
            if (!context->peer2peer) {
                break;
            }
        }

    /* Fallthrough */
    case AJ_SASL_WAIT_FOR_OK:
        AJ_InfoPrintf(("Response(): AJ_SASL_WAIT_FOR_OK\n"));
        /* Received 'OK' so we can send our protocol version */
        if (context->peer2peer) {
            AJ_GUID localGuid;
            AJ_GetLocalGUID(&localGuid);
            status = AJ_GUID_ToString(&localGuid, outStr, outLen);
            if (status == AJ_OK) {
                status = PrependStr(CMD_BEGIN, outStr, outLen, FALSE);
            }
        }
        if (cmd == CMD_OK) {
            AJ_InfoPrintf(("Response(): AJ_SASL_INFORM_VERSION\n"));
            status = PrependStr(CMD_PROTO_VER, outStr, outLen, FALSE);
            context->state = AJ_SASL_WAIT_FOR_VERSION;
            break;
        } else if (cmd == CMD_DATA) {
            rsp = CMD_CANCEL;
            context->state = AJ_SASL_WAIT_FOR_REJECT;
        } else if (cmd == CMD_ERROR) {
            rsp = CMD_CANCEL;
            context->state = AJ_SASL_WAIT_FOR_REJECT;
        } else {
            rsp = CMD_ERROR;
        }
        break;

    case AJ_SASL_WAIT_FOR_REJECT:
        AJ_ErrPrintf(("Response(): AJ_ERR_SECURITY\n"));
        status = AJ_ERR_SECURITY;
        break;

    default:
        AJ_ErrPrintf(("Response(): AJ_ERR_UNEXPECTED\n"));
        status = AJ_ERR_UNEXPECTED;
    }

    if (status == AJ_OK) {
        if (rsp != outStr) {
            status = SetStr(rsp, outStr, outLen);
        }
    }
    if (status == AJ_OK) {
        status = AppendCRLF(outStr, outLen);
    }
    return status;
}

AJ_Status AJ_SASL_Advance(AJ_SASL_Context* context, char* inStr, char* outStr, uint32_t outLen)
{
    AJ_Status status;

    AJ_InfoPrintf(("AJ_SASL_Advance(context=0x%p, inStr=\"%s\", outStr=0x%p, outlen=%d.)\n",
                   context, inStr, outStr, outLen));

    if (!outStr) {
        AJ_ErrPrintf(("AJ_SASL_Advance(): AJ_ERR_RESOURCES\n"));
        return AJ_ERR_RESOURCES;
    }
    if ((context->state == AJ_SASL_AUTHENTICATED) || (context->state == AJ_SASL_FAILED)) {
        AJ_ErrPrintf(("AJ_SASL_Advance(): AJ_ERR_UNEXPECTED\n"));
        return AJ_ERR_UNEXPECTED;
    }
    if (++context->authCount > AJ_MAX_AUTH_COUNT) {
        AJ_ErrPrintf(("AJ_SASL_Advance(): AJ_ERR_SECURITY\n"));
        return AJ_ERR_SECURITY;
    }
    AJ_InfoPrintf(("SASL->%s\n", inStr));
    *outStr = '\0';
    if (context->role == AJ_AUTH_CHALLENGER) {
        status = Challenge(context, inStr, outStr, outLen);
    } else {
        status = Response(context, inStr, outStr, outLen);
    }
    AJ_InfoPrintf(("AJ_SASL_Advance(): SASL<-%s\n", outStr));
    return status;
}
