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

#include <ajtcl/aj_target.h>
#include <ajtcl/aj_std.h>

const char AJ_DBusDestination[] = "org.freedesktop.DBus";
const char AJ_BusDestination[] = "org.alljoyn.Bus";

const char AJ_ErrServiceUnknown[] = "org.freedesktop.DBus.Error.ServiceUnknown";
const char AJ_ErrTimeout[] = "org.alljoyn.Bus.Timeout";
const char AJ_ErrRejected[] = "org.alljoyn.Bus.Rejected";
const char AJ_ErrResources[] = "org.alljoyn.Bus.Resources";
const char AJ_ErrUpdateNotAllowed[] = "org.alljoyn.Error.UpdateNotAllowed";
const char AJ_ErrInvalidValue[] = "org.alljoyn.Error.InvalidValue";
const char AJ_ErrFeatureNotAvailable[] = "org.alljoyn.Error.FeatureNotAvailable";
const char AJ_ErrMaxSizeExceeded[] = "org.alljoyn.Error.MaxSizeExceeded";
const char AJ_ErrLanguageNotSuppored[] = "org.alljoyn.Error.LanguageNotSupported";
const char AJ_ErrMethodNotAllowed[] = "org.alljoyn.Error.MethodNotAllowed";

/* Security specific errors */
const char AJ_ErrSecurityViolation[] = "org.alljoyn.Bus.SecurityViolation";
const char AJ_ErrPermissionDenied[] = "org.alljoyn.Bus.Security.Error.PermissionDenied";
const char AJ_ErrDigestMismatch[] = "org.alljoyn.Bus.Security.Error.DigestMismatch";
const char AJ_ErrInvalidCertificate[] = "org.alljoyn.Bus.Security.Error.InvalidCertificate";
const char AJ_ErrDuplicateCertificate[] = "org.alljoyn.Bus.Security.Error.DuplicateCertificate";
const char AJ_ErrCertificateNotFound[] = "org.alljoyn.Bus.Security.Error.CertificateNotFound";
const char AJ_ErrPolicyNotNewer[] = "org.alljoyn.Bus.Security.Error.PolicyNotNewer";

static const char DBusObjectPath[] = "/org/freedesktop/DBus";
static const char DBusInterface[] = "org.freedesktop.DBus";
const char DBusPeerInterface[] = "#org.freedesktop.DBus.Peer";
static const char DBusPropsInterface[] = "#org.freedesktop.DBus.Properties";
static const char DBusIntrospectableInterface[] = "#org.freedesktop.DBus.Introspectable";

static const char BusObjectPath[] = "/org/alljoyn/Bus";
static const char BusInterface[] = "org.alljoyn.Bus";

static const char DaemonObjectPath[] = "/";
static const char DaemonInterface[] = "org.alljoyn.Daemon";

static const char PeerObjectPath[] = "/org/alljoyn/Bus/Peer";
static const char PeerSessionInterface[] = "org.alljoyn.Bus.Peer.Session";
const char PeerAuthInterface[] = "org.alljoyn.Bus.Peer.Authentication";

static const char AboutObjectPath[] = "/About";
static const char AboutInterface[] = "org.alljoyn.About";

static const char AboutIconObjectPath[] = "/About/DeviceIcon";
static const char AboutIconInterface[] = "org.alljoyn.Icon";

const char AllSeenIntrospectableInterface[] = "#org.allseen.Introspectable";

static const char SecurityObjectPath[] = "/org/alljoyn/Bus/Security";
static const char ApplicationInterface[] = "org.alljoyn.Bus.Application";
static const char SecurityApplicationInterface[] = "$org.alljoyn.Bus.Security.Application";
static const char SecurityClaimableApplicationInterface[] = "$org.alljoyn.Bus.Security.ClaimableApplication";
static const char SecurityManagedApplicationInterface[] = "$org.alljoyn.Bus.Security.ManagedApplication";

const char* const AJ_PropertiesIface[] = {
    DBusPropsInterface,
    "?Get <s <s >v",
    "?Set <s <s <v",
    "?GetAll <s >a{sv}",
    "!PropertiesChanged >s >a{sv} >as",
    NULL
};

const char* const AJ_IntrospectionIface[] = {
    DBusIntrospectableInterface,
    "?Introspect >s",
    NULL
};

const char* const AJ_AllSeenIntrospectionIface[] = {
    AllSeenIntrospectableInterface,
    "?GetDescriptionLanguages >as",
    "?IntrospectWithDescription <s >s",
    NULL
};

static const char* const DBusIface[] = {
    DBusInterface,
    "?Hello >s",
    "!NameOwnerChanged >s >s >s",
    "!NameAcquired >s",
    "!NameLost >s",
    "?RequestName <s <u >u",
    "?AddMatch <s",
    "?RemoveMatch <s",
    "?ReleaseName <s >u",
    "?NameHasOwner <s >b",
    NULL

};

static const char* const DBusPeerIface[] = {
    DBusPeerInterface,
    "?Ping",
    "?GetMachineId >s",
    NULL

};

static const AJ_InterfaceDescription DBusIfaces[] = {
    DBusIface,
    NULL
};

static const char* const BusIface[] = {
    BusInterface,
    "!SessionLost >u",
    "!FoundAdvertisedName >s >q >s",
    "!LostAdvertisedName >s >q >s",
    "!MPSessionChanged >u >s >b",
    "?AdvertiseName <s <q >u",
    "?CancelAdvertiseName <s <q >u",
    "?FindAdvertisedName <s >u",
    "?CancelFindAdvertisedName <s >u",
    "?BindSessionPort <q <a{sv} >u >q",
    "?UnbindSessionPort <q >u",
    "?JoinSession <s <q <a{sv} >u >u >a{sv}",
    "?LeaveSession <u >u",
    "?CancelSessionlessMessage <u >u",
    "?FindAdvertisedNameByTransport <s <q >u",
    "?CancelFindAdvertisedNameByTransport <s <q >u",
    "?SetLinkTimeout <u <u >u >u",
    "?RemoveSessionMember <us >u",
    "!SessionLostWithReason >u >u",
    "?Ping <s <u >u",
    "?SetIdleTimeouts <u <u >u >u >u",
    "?SimpleHello <s <u >s >s >u",
    NULL
};

static const char* const DaemonIface[] = {
    DaemonInterface,
    "!ProbeReq",
    "!ProbeAck",
    NULL
};

static const char* const PeerSessionIface[] = {
    PeerSessionInterface,
    "?AcceptSession <q <u <s <a{sv} >b",
    "!SessionJoined >q >u >s",
    NULL
};

static const char* const PeerAuthIface[] = {
    PeerAuthInterface,
    "?ExchangeGuids <s <u >s >u",
    "?GenSessionKey <s <s <s >s >s",
    "?ExchangeGroupKeys <ay >ay",
    "?AuthChallenge <s >s",
    "?ExchangeSuites <au >au",
    "?KeyExchange <u <v >u >v",
    "?KeyAuthentication <v >v",
    "?SendManifests <a(ua(ssa(syy))saysay) >a(ua(ssa(syy))saysay)",
    "?SendMemberships <ya(yay) >ya(yay)",
    "@Mechanisms>s",
    "@Version>u",
    NULL
};

static const char* const AboutIface[] = {
    AboutInterface,
    "@Version>q",
    "?GetAboutData <s >a{sv}",
    "?GetObjectDescription >a(oas)",
    "!&Announce >q >q >a(oas) >a{sv}",
    NULL
};

static const char* const AboutIconIface[] = {
    AboutIconInterface,
    "@Version>q",
    "@MimeType>s",
    "@Size>u",
    "?GetUrl >s",
    "?GetContent >ay",
    NULL
};

static const char* const ApplicationIface[] = {
    ApplicationInterface,
    "@Version>q",
    "!&State >(yyayay) >q",
    NULL
};

static const char* const SecurityApplicationIface[] = {
    SecurityApplicationInterface,
    "@Version>q",
    "@ApplicationState>q",
    "@ManifestTemplateDigest>(yay)",
    "@EccPublicKey>(yyayay)",
    "@ManufacturerCertificate>a(yay)",
    "@ManifestTemplate>a(ssa(syy))",
    "@ClaimCapabilities>q",
    "@ClaimCapabilityAdditionalInfo>q",
    NULL
};

static const char* const SecurityClaimableApplicationIface[] = {
    SecurityClaimableApplicationInterface,
    "@Version>q",
    "?Claim <(yyayay) <ay <ay <(yyayay) <ay <a(yay) <a(ua(ssa(syy))saysay)",
    NULL
};

static const char* const SecurityManagedApplicationIface[] = {
    SecurityManagedApplicationInterface,
    "@Version>q",
    "@Identity>a(yay)",
    "@Manifests>a(ua(ssa(syy))saysay)",
    "@IdentityCertificateId>(ayay(yyayay))",
    "@PolicyVersion>u",
    "@Policy>(qua(a(ya(yyayayay)ay)a(ssa(syy))))",
    "@DefaultPolicy>(qua(a(ya(yyayayay)ay)a(ssa(syy))))",
    "@MembershipSummaries>a(ayay(yyayay))",
    "?Reset",
    "?UpdateIdentity <a(yay) <a(ua(ssa(syy))saysay)",
    "?UpdatePolicy <(qua(a(ya(yyayayay)ay)a(ssa(syy))))",
    "?ResetPolicy",
    "?InstallMembership <a(yay)",
    "?RemoveMembership <(ayay(yyayay))",
    "?StartManagement",
    "?EndManagement",
    "?InstallManifests <a(ua(ssa(syy))saysay)",
    NULL
};

static const AJ_InterfaceDescription PeerIfaces[] = {
    PeerSessionIface,
    PeerAuthIface,
    NULL
};

static const AJ_InterfaceDescription BusIfaces[] = {
    BusIface,
    NULL
};

static const AJ_InterfaceDescription SecurityIfaces[] = {
    AJ_PropertiesIface,
    ApplicationIface,
    SecurityApplicationIface,
    SecurityClaimableApplicationIface,
    SecurityManagedApplicationIface,
    NULL
};

/*
 * These are interfaces that all objects implement so use the wildcard in the object list
 */
static const AJ_InterfaceDescription CommonIfaces[] = {
    AJ_IntrospectionIface,
    DBusPeerIface,
    AJ_AllSeenIntrospectionIface,
    NULL
};

static const AJ_InterfaceDescription DaemonIfaces[] = {
    DaemonIface,
    NULL
};

static const AJ_InterfaceDescription AboutIfaces[] = {
    AJ_PropertiesIface,
    AboutIface,
    NULL
};

static const AJ_InterfaceDescription AboutIconIfaces[] = {
    AJ_PropertiesIface,
    AboutIconIface,
    NULL
};

/*
 * Ordering of these objects is important
 */
const AJ_Object AJ_StandardObjects[] = {
    { DBusObjectPath,        DBusIfaces,        AJ_OBJ_FLAG_IS_PROXY,  NULL },
    { BusObjectPath,         BusIfaces,         AJ_OBJ_FLAG_IS_PROXY,  NULL },
    { PeerObjectPath,        PeerIfaces,        0,                     NULL },
    { "?",                   CommonIfaces,      0,                     NULL },
    { DaemonObjectPath,      DaemonIfaces,      AJ_OBJ_FLAG_IS_PROXY,  NULL },
    { AboutObjectPath,       AboutIfaces,       AJ_OBJ_FLAG_ANNOUNCED, NULL },
    { AboutIconObjectPath,   AboutIconIfaces,   AJ_OBJ_FLAG_ANNOUNCED, NULL },
    { SecurityObjectPath,    SecurityIfaces,    0,                     NULL },
    { NULL,                  NULL,              0,                     NULL }
};
