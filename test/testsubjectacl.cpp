/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

/* Access decisions made on a peer certificate's subject rather than on its
 * common name alone.
 *
 * The subject arrives on ClientCredentials as a list of key and value pairs and
 * is offered to the access security library as a further identity.  These tests
 * build that credential directly instead of over a TLS connection, so that a
 * subject can be chosen freely; testtls covers the step that reads one out of a
 * real certificate.
 */

#include <string>

#include <asLib.h>

#include <asDbLib.h>
#include <dbAccess.h>
#include <epicsExit.h>
#include <epicsUnitTest.h>
#include <testMain.h>

#include <pvxs/unittest.h>

#include "testioc.h"
#include "utilpvt.h"

#ifdef EPICS_ASLIB_HAS_SUBJECT_UAG

#include <pvxs/credentials.h>
#include <pvxs/srvcommon.h>

extern "C" {
extern int testioc_registerRecordDeviceDriver(struct dbBase*);
}

using namespace pvxs;

namespace {

/* The chain testioc.tls.acf names as CMS_AUTH, written root first as
 * SSLContext::getPeerCredentials writes it. */
const char* const kTestAuthority = "EPICS Root Certificate Authority\nintermediateCA";

//! A TLS peer with the given common name and subject
server::ClientCredentials tlsPeer(const std::string& account, const std::string& subject) {
    server::ClientCredentials cred;
    cred.peer = "192.168.1.1:1234";
    cred.method = "x509";
    cred.authority = kTestAuthority;
    cred.account = account;
    cred.subject = subject;
    cred.isTLS = true;
    return cred;
}

//! Whether the identities that peer presents include the given one
bool offersIdentity(const server::ClientCredentials& peer, const std::string& identity) {
    const ioc::Credentials cred(peer);
    for (const auto& entry : cred.cred) {
        if (entry == identity) return true;
    }
    return false;
}

//! Whether that peer is allowed to write to the record, which is in ASG(SPECIAL)
bool canWrite(const server::ClientCredentials& peer) {
    ioc::Credentials cred(peer);
    ioc::SecurityClient client;

    dbChannel* channel = dbChannelCreate("test:spec");
    if (!channel) throw std::runtime_error("no channel to test:spec");
    if (dbChannelOpen(channel)) {
        dbChannelDelete(channel);
        throw std::runtime_error("could not open test:spec");
    }

    client.update(channel, cred);
    const auto allowed = client.canWrite();
    dbChannelDelete(channel);
    return allowed;
}

/**
 * @brief testIdentitiesOffered checks which credentials carry a keyed subject identity
 */
void testIdentitiesOffered() {
    testShow() << __func__;

    // A subject naming more than one field is offered alongside the bare common
    // name, which stays in place so that every entry already written goes on
    // meaning what it meant
    const auto full = tlsPeer("alice", "CN=alice,OU=staff,O=acme");
    testTrue(offersIdentity(full, "CN=alice,OU=staff,O=acme"));
    testTrue(offersIdentity(full, "alice"));

    // A subject naming only a common name matches the bare common name and adds nothing
    testFalse(offersIdentity(tlsPeer("alice", "CN=alice"), "CN=alice"));

    // Neither is a subject on a connection that is not authenticated by certificate
    auto not_x509 = tlsPeer("alice", "CN=alice,OU=staff,O=acme");
    not_x509.method = "ca";
    not_x509.isTLS = false;
    testFalse(offersIdentity(not_x509, "CN=alice,OU=staff,O=acme"));
}

/**
 * @brief testAccessDecision checks that a keyed entry in a user access group decides access
 */
void testAccessDecision() {
    testShow() << __func__;

    // testioc.tls.acf gives UAG(BAR) the plain name "michael" and the keyed
    // entry "OU=staff,OU=beamline,O=lbnl".  dave is named by neither, but his
    // subject satisfies every condition the keyed entry places.
    testTrue(canWrite(tlsPeer("dave", "CN=dave,OU=staff,OU=beamline,O=lbnl")));

    // The units the entry names need not be next to one another, only in the
    // same relative order, since each is an ancestor of the common name
    testTrue(canWrite(tlsPeer("dave", "CN=dave,OU=staff,OU=controls,OU=beamline,O=lbnl")));

    // eve is in neither unit, so she matches neither entry
    testFalse(canWrite(tlsPeer("eve", "CN=eve,OU=controls,O=lbnl")));

    // Naming the units the other way round asks a different question - beamline
    // within staff, which is the opposite, and is not satisfied.
    // This is why the string is built in one canonical order.
    testFalse(canWrite(tlsPeer("dave", "CN=dave,OU=beamline,OU=staff,O=lbnl")));

    // A different organization is refused even when both units match
    testFalse(canWrite(tlsPeer("dave", "CN=dave,OU=staff,OU=beamline,O=acme")));

    // A plain name entry still decides access on its own, as it always did
    testTrue(canWrite(tlsPeer("michael", "CN=michael,OU=controls,O=lbnl")));
    testTrue(canWrite(tlsPeer("client", "CN=client,OU=controls,O=lbnl")));

    // The subject below is what testtls sees a real test certificate produce.
    // Repeating it here is what proves the string the server builds is read
    // back as the pairs it was built from, quoted value and all.
    testTrue(canWrite(tlsPeer("client1", "CN=client1,OU='epics.org Certificate Authority',O=certs.epics.org,C=US")));

    // The same subject with the organization changed no longer satisfies the
    // entry, so the quoted value is being read as a condition and not skipped
    testFalse(canWrite(tlsPeer("client1", "CN=client1,OU='epics.org Certificate Authority',O=certs.example.com,C=US")));
}

}  // namespace

#endif  // EPICS_ASLIB_HAS_SUBJECT_UAG

MAIN(testsubjectacl) {
#ifndef EPICS_ASLIB_HAS_SUBJECT_UAG
    testPlan(1);
    testSkip(1, "EPICS Base does not read certificate subject fields in a user access group");
#else
    testPlan(14);
    testSetup();
    {
        pvxs::ioc::TestIOC ioc;
        asSetFilename("../testioc.tls.acf");
        testdbReadDatabase("testioc.dbd", nullptr, nullptr);
        testOk1(!testioc_registerRecordDeviceDriver(pdbbase));
        testdbReadDatabase("testioc.db", nullptr, "user=test");
        ioc.init();

        testIdentitiesOffered();
        testAccessDecision();
    }
    epicsExitCallAtExits();
    pvxs::cleanup_for_valgrind();
#endif
    return testDone();
}
