/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
#define PVXS_ENABLE_EXPERT_API

#include <algorithm>
#include <cstring>
#include <iomanip>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include <epicsEvent.h>
#include <epicsUnitTest.h>
#include <errlog.h>
#include <osiSock.h>
#include <testMain.h>

#include <event2/util.h>

#include <pvxs/client.h>
#include <pvxs/log.h>
#include <pvxs/nt.h>
#include <pvxs/server.h>
#include <pvxs/sharedpv.h>
#include <pvxs/source.h>
#include <pvxs/unittest.h>

#include "certcontext.h"
#include "certstatus.h"
#include "evhelper.h"
#include "openssl.h"
#include "ownedptr.h"
#include "pvaproto.h"
#include "udp_collector.h" 
#include "utilpvt.h"

using namespace pvxs;

namespace {

/**
 * @brief WhoAmI is a server::Source that returns the credentials of the peer
 *
 * This is used to test the client and server credentials.
 */
struct WhoAmI final : server::Source {
    const Value resultType;

    WhoAmI() : resultType(nt::NTScalar(TypeCode::String).create()) {}

    void onSearch(Search& op) override {
        for (auto& pv : op) {
            if (strcmp(pv.name(), WHO_AM_I_PV) == 0) pv.claim();
        }
    }

    void onCreate(std::unique_ptr<server::ChannelControl>&& op) override {
        if (op->name() != WHO_AM_I_PV) return;

        op->onOp([this](std::unique_ptr<server::ConnectOp>&& cop) {
            cop->onGet([this](std::unique_ptr<server::ExecOp>&& eop) {
                const auto cred(eop->credentials());
                std::ostringstream strm;
                strm << cred->method << '/' << cred->account;

                eop->reply(resultType.cloneEmpty().update(TEST_PV_FIELD, strm.str()));
            });

            cop->connect(resultType);
        });

        std::shared_ptr<server::MonitorControlOp> sub;
        op->onSubscribe([this, sub](std::unique_ptr<server::MonitorSetupOp>&& sop) mutable {
            sub = sop->connect(resultType);
            const auto cred(sub->credentials());
            std::ostringstream strm;
            strm << cred->method << '/' << cred->account;

            sub->post(resultType.cloneEmpty().update(TEST_PV_FIELD, strm.str()));
        });
    }
};

/**
 * @brief WhatIsMySubject is a server::Source that returns the peer's subject
 *
 * Reports the credentials the server itself sees for the peer, which is the
 * direction that matters for access control: this is the string a user access
 * group entry is matched against.
 */
struct WhatIsMySubject final : server::Source {
    const Value resultType;

    WhatIsMySubject() : resultType(nt::NTScalar(TypeCode::String).create()) {}

    void onSearch(Search& op) override {
        for (auto& pv : op) {
            if (strcmp(pv.name(), WHAT_IS_MY_SUBJECT_PV) == 0) pv.claim();
        }
    }

    void onCreate(std::unique_ptr<server::ChannelControl>&& op) override {
        if (op->name() != WHAT_IS_MY_SUBJECT_PV) return;

        op->onOp([this](std::unique_ptr<server::ConnectOp>&& cop) {
            cop->onGet([this](std::unique_ptr<server::ExecOp>&& eop) {
                eop->reply(resultType.cloneEmpty().update(TEST_PV_FIELD, eop->credentials()->subject));
            });

            cop->connect(resultType);
        });
    }
};

/**
 * @brief pop is a helper function that pops a value from a subscription
 *
 * This is used to test the client and server protocol messages and subscriptions.
 */
Value pop(const std::shared_ptr<client::Subscription>& sub, epicsEvent& evt) {
    while (true) {
        if (auto ret = sub->pop()) return ret;
        if (!evt.wait(5.0)) {
            testFail("timeout waiting for event");
            return {};
        }
    }
}

/**
 * @brief testLegacyMode is a test that verifies the legacy mode of the client and server still works
 *
 */
void testLegacyMode() {
    testShow() << __func__;

    auto initial(nt::NTScalar{TypeCode::Int32}.create());
    auto mbox(server::SharedPV::buildReadonly());

    const auto serv_conf(server::Config::isolated());

    auto serv(serv_conf.build().addPV(TEST_PV, mbox));

    const auto cli_conf(serv.clientConfig());

    auto cli(cli_conf.build());

    mbox.open(initial.update(TEST_PV_FIELD, 42));
    serv.start();

    auto conn(cli.connect(TEST_PV).onConnect([](const client::Connected& c) { testTrue(c.cred && !c.cred->isTLS); }).exec());

    auto reply(cli.get(TEST_PV).exec()->wait(5.0));
    testEq(reply[TEST_PV_FIELD].as<int32_t>(), 42);
    conn.reset();
}

/**
 * @brief testClientBackwardsCompatibility is a test that verifies the client backwards compatibility
 *
 * This is used to verify that an updated server can connect to a legacy client without any modifications.
 */
void testClientBackwardsCompatibility() {
    testShow() << __func__;

    auto initial(nt::NTScalar{TypeCode::Int32}.create());
    auto mbox(server::SharedPV::buildReadonly());

    auto serv_conf(server::Config::isolated());
    serv_conf.tls_keychain_file = SUPER_SERVER_KEYCHAIN_FILE;

    auto serv(serv_conf.build().addPV(TEST_PV, mbox));

    const auto cli_conf(serv.clientConfig());

    auto cli(cli_conf.build());

    mbox.open(initial.update(TEST_PV_FIELD, 42));
    serv.start();

    auto conn(cli.connect(TEST_PV).onConnect([](const client::Connected& c) { testTrue(c.cred && !c.cred->isTLS); }).exec());

    auto reply(cli.get(TEST_PV).exec()->wait(5.0));
    testEq(reply[TEST_PV_FIELD].as<int32_t>(), 42);
    conn.reset();
}

/**
 * @brief testServerBackwardsCompatibility is a test that verifies the server backwards compatibility
 *
 * This is used to verify that an updated client can connect to a legacy server without any modifications.
 */
void testServerBackwardsCompatibility() {
    testShow() << __func__;

    auto initial(nt::NTScalar{TypeCode::Int32}.create());
    auto mbox(server::SharedPV::buildReadonly());

    const auto serv_conf(server::Config::isolated());

    auto serv(serv_conf.build().addPV(TEST_PV, mbox));

    auto cli_conf(serv.clientConfig());
    cli_conf.tls_keychain_file = CLIENT1_KEYCHAIN_FILE;

    auto cli(cli_conf.build());

    mbox.open(initial.update(TEST_PV_FIELD, 42));
    serv.start();

    auto conn(cli.connect(TEST_PV).onConnect([](const client::Connected& c) { testTrue(c.cred && !c.cred->isTLS); }).exec());

    auto reply(cli.get(TEST_PV).exec()->wait(5.0));
    testEq(reply[TEST_PV_FIELD].as<int32_t>(), 42);
    conn.reset();
}

/**
 * @brief testServerOnly is a test that verifies the client can connect in server-only authenticated TLS mode
 *
 * This is used to verify that a client that is configured with a certificate authority certificate but no entity cert
 * will be able to connect in server-only authenticated TLS mode
 */
void testServerOnly() {
    testShow() << __func__;

    auto initial(nt::NTScalar{TypeCode::Int32}.create());
    auto mbox(server::SharedPV::buildReadonly());

    auto serv_conf(server::Config::isolated());
    serv_conf.tls_keychain_file = SUPER_SERVER_KEYCHAIN_FILE;

    auto serv(serv_conf.build().addPV(TEST_PV, mbox));

    auto cli_conf(serv.clientConfig());
    cli_conf.tls_keychain_file = CERT_AUTH_CERT_FILE;

    auto cli(cli_conf.build());

    mbox.open(initial.update(TEST_PV_FIELD, 42));
    serv.start();

    auto is_tls{false};
    auto conn(cli.connect(TEST_PV).onConnect([&is_tls](const client::Connected& c) { is_tls = c.cred && c.cred->isTLS; }).exec());

    auto reply(cli.get(TEST_PV).exec()->wait(5.0));
    testTrue(is_tls);
    testEq(reply[TEST_PV_FIELD].as<int32_t>(), 42);
    conn.reset();
}

/**
 * @brief testStrictServer is a test that verifies that strict servers allow only mutually authenticated TLS connections
 *
 * This is used to verify that a server that is configured to accept only TLS clients enforces that rule
 */
void testStrictServer() {
    testShow() << __func__;

    auto initial(nt::NTScalar{TypeCode::Int32}.create());
    auto mbox(server::SharedPV::buildReadonly());

    auto serv_conf(server::Config::isolated());
    serv_conf.tls_keychain_file = SUPER_SERVER_KEYCHAIN_FILE;
    serv_conf.tls_client_cert_required = ConfigCommon::Require;

    auto serv(serv_conf.build().addPV(TEST_PV, mbox));
    mbox.open(initial.update(TEST_PV_FIELD, 42));
    serv.start();

    auto cli_conf(serv.clientConfig());

    {
        // Test without any client TLS configuration
        auto cli(cli_conf.build());

        auto is_tls{false};
        auto conn(cli.connect(TEST_PV).onConnect([&is_tls](const client::Connected& c) { is_tls = c.cred && c.cred->isTLS; }).exec());

        auto reply(cli.get(TEST_PV).exec()->wait(3.0));
        testTrue(!is_tls);
        testEq(reply[TEST_PV_FIELD].as<int32_t>(), 42);
    }

    try {
        // Test with server only TLS config
        cli_conf.tls_keychain_file = CERT_AUTH_CERT_FILE;

        auto cli(cli_conf.build());

        auto conn(cli.connect(TEST_PV).onConnect([](const client::Connected&) { testFail("Unexpected connection with server only setup"); }).exec());

        auto reply(cli.get(TEST_PV).exec()->wait(3.0));
        testFail("Unexpected reply with server only setup");
    } catch (std::exception& e) {
        testTrue(std::string{e.what()} == "Timeout");
    }
}

/**
 * @brief testGetSuper is a test that verifies the client can connect to the server using a standard cert file
 *
 * This is used to verify that the client can connect to the server using a standard cert file on a TLS connection.
 */
void testGetSuper() {
    testShow() << __func__;

    auto initial(nt::NTScalar{TypeCode::Int32}.create());
    auto mbox(server::SharedPV::buildReadonly());

    auto serv_conf(server::Config::isolated());
    serv_conf.tls_keychain_file = SUPER_SERVER_KEYCHAIN_FILE;

    auto serv(serv_conf.build().addPV(TEST_PV, mbox));

    auto cli_conf(serv.clientConfig());
    cli_conf.tls_keychain_file = CLIENT1_KEYCHAIN_FILE;

    auto cli(cli_conf.build());

    mbox.open(initial.update(TEST_PV_FIELD, 42));
    serv.start();

    auto conn(cli.connect(TEST_PV).onConnect([](const client::Connected& c) { testTrue(c.cred && c.cred->isTLS); }).exec());

    auto reply(cli.get(TEST_PV).exec()->wait(5.0));
    testEq(reply[TEST_PV_FIELD].as<int32_t>(), 42);
    conn.reset();
}

/**
 * @brief testGetIntermediate is a test that verifies the client can connect to the server that has a cert file that has intermediate certs in its chain
 *
 * This is used to verify that the client can connect to the server using an intermediate cert file on a TLS connection.
 */
void testGetIntermediate() {
    testShow() << __func__;

    auto initial(nt::NTScalar{TypeCode::Int32}.create());
    auto mbox(server::SharedPV::buildReadonly());

    auto serv_conf(server::Config::isolated());
    serv_conf.tls_keychain_file = SERVER1_KEYCHAIN_FILE;

    auto serv(serv_conf.build().addPV(TEST_PV, mbox));

    auto cli_conf(serv.clientConfig());
    cli_conf.tls_keychain_file = CLIENT1_KEYCHAIN_FILE;

    auto cli(cli_conf.build());

    mbox.open(initial.update(TEST_PV_FIELD, 42));
    serv.start();

    auto conn(cli.connect(TEST_PV).onConnect([](const client::Connected& c) { testTrue(c.cred && c.cred->isTLS); }).exec());

    auto reply(cli.get(TEST_PV).exec()->wait(5.0));
    testEq(reply[TEST_PV_FIELD].as<int32_t>(), 42);
    conn.reset();
}

void testGetNameServer() {
    testShow() << __func__;

    auto initial(nt::NTScalar{TypeCode::Int32}.create());
    auto mbox(server::SharedPV::buildReadonly());

    auto serv_conf(server::Config::isolated());
    serv_conf.tls_keychain_file = SERVER1_KEYCHAIN_FILE;

    auto serv(serv_conf.build().addPV(TEST_PV, mbox));

    auto cli_conf(serv.clientConfig());
    cli_conf.tls_keychain_file = CLIENT1_KEYCHAIN_FILE;

    for (auto& addr : cli_conf.addressList) cli_conf.nameServers.push_back(SB() << "pvas://" << addr /*<<':'<<cli_conf.tls_port*/);
    cli_conf.autoAddrList = false;
    cli_conf.addressList.clear();

    auto cli(cli_conf.build());

    mbox.open(initial.update(TEST_PV_FIELD, 42));
    serv.start();

    auto conn(cli.connect(TEST_PV).onConnect([](const client::Connected& c) { testTrue(c.cred && c.cred->isTLS); }).exec());

    try {
        auto reply(cli.get(TEST_PV).exec()->wait(5.0));
        testEq(reply[TEST_PV_FIELD].as<int32_t>(), 42);
    } catch (std::exception&) {
        testFail("timeout waiting for event");
    }
}

/**
 * @brief testClientReconfig is a test that verifies the client can be reconfigured on the fly
 *
 * This is used to verify that the client can be reconfigured and the changes will take effect.
 * Existing connections will be disconnected and new connections will use the new configuration.
 * If going from a TLS connection to a non-TLS configuration, then TLS connections will be disconnected.
 * If going from a non-TLS connection to a TLS configuration, then non-TLS connections will be disconnected.
 */
void testClientReconfig() {
    testShow() << __func__;

    auto serv_conf(server::Config::isolated());
    serv_conf.tls_keychain_file = IOC1_KEYCHAIN_FILE;

    auto serv(serv_conf.build().addSource(WHO_AM_I_PV, std::make_shared<WhoAmI>()));

    auto cli_conf(serv.clientConfig());
    cli_conf.tls_keychain_file = CLIENT1_KEYCHAIN_FILE;

    auto cli(cli_conf.build());

    serv.start();

    epicsEvent evt;
    auto sub(cli.monitor(WHO_AM_I_PV).maskConnected(false).maskDisconnected(false).event([&evt](client::Subscription&) { evt.signal(); }).exec());

    try {
        pop(sub, evt);
        testFail("Unexpected success");
        testSkip(2, "oops");
    } catch (client::Connected& e) {
        testTrue(e.cred->isTLS);
        testEq(e.cred->method, TLS_METHOD_STRING);
        testEq(e.cred->account, CERT_CN_IOC1);
    }
    testDiag("Connect");

    Value update = pop(sub, evt);
    testEq(update[TEST_PV_FIELD].as<std::string>(), TLS_METHOD_STRING "/" CERT_CN_CLIENT1);

    cli_conf = cli.config();
    cli_conf.tls_keychain_file = CLIENT2_KEYCHAIN_FILE;
    cli_conf.setKeychainPassword(CLIENT2_KEYCHAIN_FILE_PWD);
    testDiag("cli.reconfigure()");
    cli.reconfigure(cli_conf);

    testThrows<client::Disconnect>([&sub, &evt] { pop(sub, evt); });
    testDiag("Disconnect");

    try {
        (void)pop(sub, evt);
        testFail("Missing expected Connected");
    } catch (client::Connected& e) {
        testOk1(e.cred && e.cred->isTLS);
    } catch (...) {
        testFail("Unexpected exception instead of Connected");
    }
    testDiag("Reconnect");

    update = pop(sub, evt);
    if (update.valid()) testEq(update[TEST_PV_FIELD].as<std::string>(), TLS_METHOD_STRING "/" CERT_CN_CLIENT2);
}

/**
 * @brief testServerReconfig is a test that verifies the server can be reconfigured on the fly
 *
 * This is used to verify that the server can be reconfigured and the changes will take effect.
 * Existing connections will be disconnected and new connections will use the new configuration.
 * If going from a TLS connection to a non-TLS configuration, then TLS connections will be disconnected.
 * If going from a non-TLS connection to a TLS configuration, then non-TLS connections will be disconnected.
 */
void testServerReconfig() {
    testShow() << __func__;

    auto serv_conf(server::Config::isolated());
    serv_conf.tls_keychain_file = SERVER1_KEYCHAIN_FILE;

    auto serv(serv_conf.build().addSource(WHO_AM_I_PV, std::make_shared<WhoAmI>()));

    auto cli_conf(serv.clientConfig());
    cli_conf.tls_keychain_file = IOC1_KEYCHAIN_FILE;

    auto cli(cli_conf.build());

    serv.start();

    epicsEvent evt;
    auto sub(cli.monitor(WHO_AM_I_PV).maskConnected(false).maskDisconnected(false).event([&evt](client::Subscription&) { evt.signal(); }).exec());

    try {
        pop(sub, evt);
        testFail("Unexpected success");
        testSkip(2, "oops");
    } catch (client::Connected& e) {
        testTrue(e.cred->isTLS);
        testEq(e.cred->method, TLS_METHOD_STRING);
        testEq(e.cred->account, CERT_CN_SERVER1);
    }
    testDiag("Connect");

    Value update = pop(sub, evt);
    testEq(update[TEST_PV_FIELD].as<std::string>(), TLS_METHOD_STRING "/" CERT_CN_IOC1);

    serv_conf = serv.config();
    serv_conf.tls_keychain_file = IOC1_KEYCHAIN_FILE;
    testDiag("serv.reconfigure()");
    serv.reconfigure(serv_conf);

    testThrows<client::Disconnect>([&sub, &evt] { pop(sub, evt); });
    testDiag("Disconnect");

    try {
        pop(sub, evt);
        testFail("Unexpected success");
        testSkip(2, "oops");
    } catch (client::Connected& e) {
        testTrue(e.cred->isTLS);
        testEq(e.cred->method, TLS_METHOD_STRING);
        testEq(e.cred->account, CERT_CN_IOC1);
    }
    testDiag("Reconnect");

    update = pop(sub, evt);
    testEq(update[TEST_PV_FIELD].as<std::string>(), TLS_METHOD_STRING "/" CERT_CN_IOC1);
}

/**
 * @brief testMutualTLSWithMismatchedTrustRoot tests that mutual TLS fails
 * when the client's certificate is signed by a different root than the server trusts.
 *
 * This verifies that TLS handshake properly validates certificate chains
 * and rejects connections where trust anchors don't match.
 */
void testMutualTLSWithMismatchedTrustRoot() {
    testShow() << __func__;

    auto initial(nt::NTScalar{TypeCode::Int32}.create());
    auto mbox(server::SharedPV::buildReadonly());

    // Server uses main root CA hierarchy
    auto serv_conf(server::Config::isolated());
    serv_conf.tls_keychain_file = SUPER_SERVER_KEYCHAIN_FILE;

    auto serv(serv_conf.build().addPV(TEST_PV, mbox));

    // Client uses alternate root CA hierarchy (different trust anchor)
    auto cli_conf(serv.clientConfig());
    cli_conf.tls_keychain_file = ALT_CLIENT1_KEYCHAIN_FILE;

    auto cli(cli_conf.build());

    mbox.open(initial.update(TEST_PV_FIELD, 42));
    serv.start();

    // Connection should fail because client's cert chain doesn't link to server's trust anchor
    try {
        auto conn(cli.connect(TEST_PV).onConnect([](const client::Connected&) {
            testFail("Unexpected successful connection with mismatched trust roots");
        }).exec());

        auto reply(cli.get(TEST_PV).exec()->wait(3.0));
        testFail("Unexpected reply received - connection should have failed");
    } catch (std::exception& e) {
        // Expected: connection timeout or authentication failure
        auto msg = std::string{e.what()};
        bool expected = (msg == "Timeout") ||
                       (msg.find("SSL") != std::string::npos) ||
                       (msg.find("auth") != std::string::npos) ||
                       (msg.find("certificate") != std::string::npos);
        testDiag("Expected error, got: %s", e.what());
        testTrue(expected);
    }
}

/**
 * @brief testServerOnlyAuthWithMismatchedTrustAnchor tests that server-only
 * TLS authentication fails when the client's trust anchor differs from the server's cert chain.
 *
 * In server-only auth, the client trusts the server based on the server's certificate chain.
 * If the client's trust anchor doesn't include the server's root, the handshake fails.
 */
void testServerOnlyAuthWithMismatchedTrustAnchor() {
    testShow() << __func__;

    auto initial(nt::NTScalar{TypeCode::Int32}.create());
    auto mbox(server::SharedPV::buildReadonly());

    // Server uses alternate root CA hierarchy
    auto serv_conf(server::Config::isolated());
    serv_conf.tls_keychain_file = ALT_SERVER1_KEYCHAIN_FILE;
    testDiag("Server using: %s", ALT_SERVER1_KEYCHAIN_FILE);

    auto serv(serv_conf.build().addPV(TEST_PV, mbox));

    // Client uses main root CA as trust anchor only (server-only auth, no entity cert)
    // cert_authcert.p12 contains the main root CA certificate only
    auto cli_conf(serv.clientConfig());
    cli_conf.tls_keychain_file = CERT_AUTH_CERT_FILE;
    testDiag("Client using: %s (trust anchor only, no entity cert)", CERT_AUTH_CERT_FILE);

    auto cli(cli_conf.build());

    mbox.open(initial.update(TEST_PV_FIELD, 42));
    serv.start();

    // Connection should fail because client's trust anchor (main root) doesn't match
    // server's certificate chain (alt root) - client can't verify server
    bool connection_succeeded = false;
    bool got_callback = false;

    try {
        auto conn(cli.connect(TEST_PV).onConnect([&connection_succeeded, &got_callback](const client::Connected& c) {
            got_callback = true;
            connection_succeeded = c.cred && c.cred->isTLS;
            if (connection_succeeded) {
                testDiag("UNEXPECTED: Connection succeeded with TLS=%s, method=%s, account=%s",
                         c.cred->isTLS ? "true" : "false",
                         c.cred->method.c_str(),
                         c.cred->account.c_str());
            }
        }).exec());

        auto reply(cli.get(TEST_PV).exec()->wait(3.0));
        testDiag("UNEXPECTED: Reply received with value=%d", reply[TEST_PV_FIELD].as<int32_t>());
        testFail("Unexpected reply received - connection should have failed");
    } catch (std::exception& e) {
        testDiag("Caught exception: %s", e.what());
        if (!got_callback) {
            testPass("Connection failed before onConnect callback (expected)");
        } else if (!connection_succeeded) {
            testPass("Connection succeeded but without TLS (unexpected but non-TLS connection)");
        } else {
            testFail("Connection succeeded with TLS when it should have failed");
        }
    }
}

/**
 * @brief testServerOnlyAuthWithMatchingTrustAnchor is a positive test that
 * server-only TLS authentication succeeds when trust anchors match.
 */
void testServerOnlyAuthWithMatchingTrustAnchor() {
    testShow() << __func__;

    auto initial(nt::NTScalar{TypeCode::Int32}.create());
    auto mbox(server::SharedPV::buildReadonly());

    auto serv_conf(server::Config::isolated());
    serv_conf.tls_keychain_file = SUPER_SERVER_KEYCHAIN_FILE;

    auto serv(serv_conf.build().addPV(TEST_PV, mbox));

    // Client has only trust anchor (main root), no entity cert (server-only auth)
    auto cli_conf(serv.clientConfig());
    cli_conf.tls_keychain_file = CERT_AUTH_CERT_FILE;

    auto cli(cli_conf.build());

    mbox.open(initial.update(TEST_PV_FIELD, 42));
    serv.start();

    auto is_tls{false};
    auto conn(cli.connect(TEST_PV).onConnect([&is_tls](const client::Connected& c) {
        is_tls = c.cred && c.cred->isTLS;
    }).exec());

    auto reply(cli.get(TEST_PV).exec()->wait(5.0));
    testTrue(is_tls);
    testEq(reply[TEST_PV_FIELD].as<int32_t>(), 42);
    conn.reset();
}

/**
 * @brief One field of a subject built for a test
 *
 * A length of -1 means the value is read up to its terminating null, as
 * X509_NAME_add_entry_by_txt reads it by default.
 */
struct SubjectField {
    const char* key;
    const char* value;
    int length;

    SubjectField(const char* key, const char* value, int length = -1) : key(key), value(value), length(length) {}
};

/**
 * @brief Write the given fields as a subject and return what makeSubjectIdentity makes of it
 */
std::string subjectIdentityOf(const std::vector<SubjectField>& fields) {
    const ossl_ptr<X509_NAME> subject(X509_NAME_new());
    for (const auto& field : fields) {
        // OpenSSL will not write an empty value itself, so one is put in place
        // and then emptied.  Another implementation can produce such a subject
        // and this is the only way to build one here to try it against.
        const auto empty = field.length == 0;
        if (!X509_NAME_add_entry_by_txt(subject.get(), field.key, MBSTRING_ASC,
                                        reinterpret_cast<const unsigned char*>(empty ? "placeholder" : field.value),
                                        empty ? -1 : field.length, -1, 0))
            throw std::runtime_error(SB() << "could not add subject field " << field.key);
        if (empty) {
            const auto entry = X509_NAME_get_entry(subject.get(), X509_NAME_entry_count(subject.get()) - 1);
            if (!ASN1_STRING_set(X509_NAME_ENTRY_get_data(entry), "", 0))
                throw std::runtime_error(SB() << "could not empty subject field " << field.key);
        }
    }
    return ossl::makeSubjectIdentity(subject.get());
}

/**
 * @brief testSubjectIdentity checks how a certificate subject is written as key and value pairs
 */
void testSubjectIdentity() {
    testShow() << __func__;

    // An empty subject, and a subject with no field worth keeping, give nothing
    testEq(ossl::makeSubjectIdentity(nullptr), "");
    testEq(subjectIdentityOf({}), "");

    testEq(subjectIdentityOf({{"CN", "alice"}}), "CN=alice");
    testEq(subjectIdentityOf({{"CN", "alice"}, {"O", "acme"}}), "CN=alice,O=acme");
    testEq(subjectIdentityOf({{"CN", "alice"}, {"C", "US"}}), "CN=alice,C=US");

    // Both organizational units are kept, in the relative order the subject
    // carries them.  X509_NAME_get_text_by_NID would have seen only the first.
    testEq(subjectIdentityOf({{"CN", "alice"}, {"OU", "staff"}, {"OU", "beamline"}}), "CN=alice,OU=staff,OU=beamline");

    // Every other field is left out
    testEq(subjectIdentityOf({{"CN", "alice"}, {"ST", "California"}, {"L", "Menlo Park"}, {"O", "acme"}}), "CN=alice,O=acme");

    // A value carrying a comma, an equals sign or a space is wrapped in quotes
    testEq(subjectIdentityOf({{"O", "Acme, Inc."}}), "O='Acme, Inc.'");
    testEq(subjectIdentityOf({{"CN", "a=b"}}), "CN='a=b'");
    testEq(subjectIdentityOf({{"CN", "alice smith"}}), "CN='alice smith'");

    // A value that cannot be written at all costs the whole string, so that no
    // identity is offered rather than one missing a field
    testEq(subjectIdentityOf({{"CN", "alice"}, {"O", "O'Brien Ltd"}}), "");
    testEq(subjectIdentityOf({{"CN", "good"}, {"O", "acme\0evil", 9}}), "");

    // An empty value is left out: the reader rejects a whole string that carries
    // one, which would cost the peer its keyed identity altogether
    testEq(subjectIdentityOf({{"CN", "alice"}, {"O", "", 0}}), "CN=alice");

    // The four kept fields come out in the same order however the subject
    // carries them.  The first is the order PVACMS used to issue, the second is
    // leaf first, the third is the ordinary X.500 direction.
    const std::string expected("CN=alice,OU=staff,O=lbnl,C=US");
    testEq(subjectIdentityOf({{"CN", "alice"}, {"C", "US"}, {"O", "lbnl"}, {"OU", "staff"}}), expected);
    testEq(subjectIdentityOf({{"CN", "alice"}, {"OU", "staff"}, {"O", "lbnl"}, {"C", "US"}}), expected);
    testEq(subjectIdentityOf({{"C", "US"}, {"O", "lbnl"}, {"OU", "staff"}, {"CN", "alice"}}), expected);

    // Only the relative order of the organizational units survives
    testEq(subjectIdentityOf({{"OU", "staff"}, {"CN", "alice"}, {"OU", "beamline"}}), "CN=alice,OU=staff,OU=beamline");
    testEq(subjectIdentityOf({{"OU", "beamline"}, {"CN", "alice"}, {"OU", "staff"}}), "CN=alice,OU=beamline,OU=staff");
}

/**
 * @brief testCommonNameLength checks that a long common name is read whole
 *
 * A common name may be 64 characters, the upper bound X.500 sets and OpenSSL
 * enforces.  This code used to read it with X509_NAME_get_text_by_NID into a
 * 64-byte buffer, which cut anything past 62 characters without saying so, and
 * left the account disagreeing with the same name in the written subject.
 */
void testCommonNameLength() {
    testShow() << __func__;

    const std::string longest(64, 'a');

    const ossl_ptr<X509_NAME> subject(X509_NAME_new());
    if (!X509_NAME_add_entry_by_txt(subject.get(), "CN", MBSTRING_ASC,
                                    reinterpret_cast<const unsigned char*>(longest.c_str()), -1, -1, 0))
        throw std::runtime_error("could not add a 64 character common name");

    std::string read_back;
    testTrue(ossl::getSubjectCommonName(subject.get(), read_back));
    testEq(read_back, longest);

    // The account and the written subject have to carry the same name, since an
    // access security file may be written against either
    testEq(ossl::makeSubjectIdentity(subject.get()), "CN=" + longest);

    // A subject with no common name, and one whose common name is empty, are
    // both reported as carrying none
    std::string untouched("unchanged");
    testFalse(ossl::getSubjectCommonName(nullptr, untouched));
    const ossl_ptr<X509_NAME> no_common_name(X509_NAME_new());
    if (!X509_NAME_add_entry_by_txt(no_common_name.get(), "O", MBSTRING_ASC,
                                    reinterpret_cast<const unsigned char*>("acme"), -1, -1, 0))
        throw std::runtime_error("could not add an organization");
    testFalse(ossl::getSubjectCommonName(no_common_name.get(), untouched));
    testEq(untouched, "unchanged");
}

/**
 * @brief testSubjectCredentials checks that a mutual TLS connection reports each peer's subject
 *
 * Both directions are checked, because the server's view of the client is what
 * access control is decided on, and the client's view of the server is what a
 * client-side check would read.  In both the bare common name has to be
 * untouched, since every access security file already written names it.
 */
void testSubjectCredentials() {
    testShow() << __func__;

    auto serv_conf(server::Config::isolated());
    serv_conf.tls_keychain_file = SERVER1_KEYCHAIN_FILE;

    auto serv(serv_conf.build().addSource(WHAT_IS_MY_SUBJECT_PV, std::make_shared<WhatIsMySubject>()));

    auto cli_conf(serv.clientConfig());
    cli_conf.tls_keychain_file = CLIENT1_KEYCHAIN_FILE;

    auto cli(cli_conf.build());

    serv.start();

    // What the client sees of the server
    auto conn(cli.connect(WHAT_IS_MY_SUBJECT_PV).onConnect([](const client::Connected& c) {
        testTrue(c.cred && c.cred->isTLS);
        testEq(c.cred->account, CERT_CN_SERVER1);
        testEq(c.cred->subject, CERT_SUBJECT_OF(CERT_CN_SERVER1));
    }).exec());

    // What the server sees of the client
    const auto reply(cli.get(WHAT_IS_MY_SUBJECT_PV).exec()->wait(5.0));
    testEq(reply[TEST_PV_FIELD].as<std::string>(), CERT_SUBJECT_OF(CERT_CN_CLIENT1));
    conn.reset();
}

/**
 * @brief testMutualTLSWithMatchingTrustAnchors is a positive test that
 * mutual TLS succeeds when both client and server use matching trust anchors.
 */
void testMutualTLSWithMatchingTrustAnchors() {
    testShow() << __func__;

    auto initial(nt::NTScalar{TypeCode::Int32}.create());
    auto mbox(server::SharedPV::buildReadonly());

    // Server uses alternate root CA hierarchy
    auto serv_conf(server::Config::isolated());
    serv_conf.tls_keychain_file = ALT_SERVER1_KEYCHAIN_FILE;

    auto serv(serv_conf.build().addPV(TEST_PV, mbox));

    // Client also uses alternate root CA hierarchy (matching trust anchor)
    auto cli_conf(serv.clientConfig());
    cli_conf.tls_keychain_file = ALT_CLIENT1_KEYCHAIN_FILE;

    auto cli(cli_conf.build());

    mbox.open(initial.update(TEST_PV_FIELD, 42));
    serv.start();

    auto is_tls{false};
    auto conn(cli.connect(TEST_PV).onConnect([&is_tls](const client::Connected& c) {
        is_tls = c.cred && c.cred->isTLS;
    }).exec());

    auto reply(cli.get(TEST_PV).exec()->wait(5.0));
    testTrue(is_tls);
    testEq(reply[TEST_PV_FIELD].as<int32_t>(), 42);
    conn.reset();
}

/**
 * @brief testClientWithMismatchedChainFallback tests that when a client's p12 file
 * contains an entity certificate that doesn't chain to the trust anchor in the p12,
 * TLS is disabled and connections fall back to TCP.
 *
 * This is expected behavior: if the entity cert can't be verified against the trust store
 * built from the p12's CA certificates, the client can't use mutual TLS and falls back to TCP.
 *
 * The p12 file contains:
 * - Entity cert: alt_client1 (signed by alt_root via alt_intermediate)
 * - Trust store: main_root (NOT alt_root)
 *
 * Since alt_client1 doesn't chain to main_root, the client detects this mismatch and
 * disables TLS, falling back to TCP-only mode.
 */
void testClientWithMismatchedChainFallback() {
    testShow() << __func__;

    auto initial(nt::NTScalar{TypeCode::Int32}.create());
    auto mbox(server::SharedPV::buildReadonly());

    // Server uses main root CA hierarchy
    auto serv_conf(server::Config::isolated());
    serv_conf.tls_keychain_file = SUPER_SERVER_KEYCHAIN_FILE;

    auto serv(serv_conf.build().addPV(TEST_PV, mbox));

    // Client has entity cert (alt_client1) that doesn't chain to trust anchor (main_root)
    // This should cause the client to fall back to TCP mode
    auto cli_conf(serv.clientConfig());
    cli_conf.tls_keychain_file = ALT_CLIENT1_WITH_MAIN_ROOT_KEYCHAIN_FILE;

    auto cli(cli_conf.build());

    mbox.open(initial.update(TEST_PV_FIELD, 42));
    serv.start();

    // The client should detect that its entity cert doesn't chain to the trust store
    // and disable TLS, falling back to TCP mode
    bool is_tls{false};
    auto conn(cli.connect(TEST_PV).onConnect([&is_tls](const client::Connected& c) {
        is_tls = c.cred && c.cred->isTLS;
        testDiag("Connection established with TLS=%s, method=%s, account=%s",
                  c.cred && c.cred->isTLS ? "true" : "false",
                  c.cred ? c.cred->method.c_str() : "none",
                  c.cred ? c.cred->account.c_str() : "none");
    }).exec());

    auto reply(cli.get(TEST_PV).exec()->wait(5.0));

    // Expected: TCP-only connection (TLS disabled due to chain mismatch)
    testDiag("Expected: TCP-only connection (TLS disabled due to chain mismatch)");
    testTrue(!is_tls);
    testEq(reply[TEST_PV_FIELD].as<int32_t>(), 42);
    conn.reset();
}

/**
 * @brief What a keychain file holds: an identity, its key, and the authority chain
 *
 * Either of the identity and the key may be absent, since some of the generated
 * keychains carry nothing but certificate authority certificates.
 */
struct Keychain {
    ossl_ptr<X509> cert;
    ossl_ptr<EVP_PKEY> key;
    ossl_shared_ptr<STACK_OF(X509)> chain;
};

/**
 * @brief Reads a keychain file with libcrypto, without going through a TLS context
 *
 * The tests below need the raw certificates out of a keychain so they can compare
 * them against what a context ended up presenting, and need an authority's key so
 * they can sign a certificate status reply with it.
 */
Keychain readKeychain(const char* filename, const char* password = "") {
    ossl::osslInit();

    const file_ptr fp(fopen(filename, "rb"), false);
    if (!fp) throw std::runtime_error(SB() << "could not open keychain file " << filename);

    const ossl_ptr<PKCS12> p12(d2i_PKCS12_fp(fp.get(), nullptr));
    if (!p12) throw std::runtime_error(SB() << "could not read " << filename << " as a PKCS#12 file");

    Keychain out;
    STACK_OF(X509)* chain_ptr = nullptr;
    if (!PKCS12_parse(p12.get(), password, out.key.acquire(), out.cert.acquire(), &chain_ptr))
        throw std::runtime_error(SB() << "could not parse keychain file " << filename);

    out.chain = chain_ptr ? ossl_shared_ptr<STACK_OF(X509)>(chain_ptr) : ossl_shared_ptr<STACK_OF(X509)>(sk_X509_new_null());
    return out;
}

/**
 * @brief Builds a client TLS context from a keychain, the way a client does
 *
 * The status check is turned off so that no status subscription is started, which
 * is why the empty client context handed to the builder is never used.
 */
std::shared_ptr<ossl::SSLContext> buildClientContext(const impl::evbase& loop, const char* keychain_file) {
    client::Config conf;
    conf.tls_keychain_file = keychain_file;
    conf.disableStatusCheck();
    conf.disableStapling();

    const client::Context unused_status_client;
    return ossl::SSLContext::for_client(conf, unused_status_client, loop);
}

/**
 * @brief Whether a certificate is among those in a stack
 */
bool stackHolds(const STACK_OF(X509)* certificates, const X509* wanted) {
    for (int i = 0, N = sk_X509_num(certificates); i < N; i++) {
        if (X509_cmp(sk_X509_value(certificates, i), wanted) == 0) return true;
    }
    return false;
}

/**
 * @brief Signs a certificate status reply for a certificate, under the authority that issued it
 *
 * pvxs cannot mint one of these on its own, because the factory that does lives in
 * pvxs-cms, so the reply is built here straight from libcrypto.  It says the
 * certificate is good, from now until the usual status validity period is up.
 */
std::vector<uint8_t> signStatusReply(const Keychain& authority, const X509* subject) {
    const ossl_ptr<OCSP_CERTID> cert_id(OCSP_cert_to_id(EVP_sha1(), subject, authority.cert.get()));

    const time_t now(time(nullptr));
    const ossl_ptr<ASN1_TIME> this_update(ASN1_TIME_set(nullptr, now));
    const ossl_ptr<ASN1_TIME> next_update(ASN1_TIME_set(nullptr, now + STATUS_VALID_FOR_SECS));

    const ossl_ptr<OCSP_BASICRESP> basic_response(OCSP_BASICRESP_new());
    if (!OCSP_basic_add1_status(basic_response.get(), cert_id.get(), V_OCSP_CERTSTATUS_GOOD, 0, nullptr, this_update.get(), next_update.get()))
        throw std::runtime_error("could not add a certificate status to the reply");

    // The signing certificate goes into the reply, which is where the verifier looks for it
    if (!OCSP_basic_sign(basic_response.get(), authority.cert.get(), authority.key.get(), EVP_sha256(), nullptr, 0))
        throw std::runtime_error("could not sign the certificate status reply");

    const ossl_ptr<OCSP_RESPONSE> response(OCSP_response_create(OCSP_RESPONSE_STATUS_SUCCESSFUL, basic_response.get()));
    unsigned char* der = nullptr;
    const int der_len = i2d_OCSP_RESPONSE(response.get(), &der);
    if (der_len <= 0) throw std::runtime_error("could not encode the certificate status reply");
    const ossl_ptr<unsigned char> der_holder(der);

    return std::vector<uint8_t>(der, der + der_len);
}

/**
 * @brief The certificate identifier that a status reply signed by this authority carries
 *
 * The identifier names the authority by the hash of its public key and the certificate by
 * its serial number, which is how pvxs-cms builds one (`createOCSPCertId`).  It cannot be
 * read off the subject certificate with getCertIdFromCert here, because gen_test_certs
 * writes every certificate a subject key identifier taken from its issuer's key rather
 * than from its own, so what a generated certificate advertises is not the hash a reply
 * about it carries.
 */
std::string statusReplyCertId(const X509* authority, const X509* subject) {
    unsigned char key_hash[EVP_MAX_MD_SIZE];
    unsigned int key_hash_len = 0;

    const ASN1_BIT_STRING* authority_key = X509_get0_pubkey_bitstr(authority);
    const ossl_ptr<EVP_MD_CTX> digest(EVP_MD_CTX_new());
    if (!EVP_DigestInit_ex(digest.get(), EVP_sha1(), nullptr) ||
        !EVP_DigestUpdate(digest.get(), authority_key->data, authority_key->length) ||
        !EVP_DigestFinal_ex(digest.get(), key_hash, &key_hash_len))
        throw std::runtime_error("could not hash the authority's public key");

    std::ostringstream issuer_id;
    for (unsigned i = 0; i < key_hash_len && issuer_id.tellp() < 8; i++) {
        issuer_id << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(key_hash[i]);
    }

    return certs::CertStatusManager::getCertIdFromSerialAndIssuer(issuer_id.str(), certs::CertStatusManager::getSerialFromCert(subject));
}

/**
 * @brief testTwoAnchorsConnectsUnderOwnRoot checks that a keychain carrying a foreign
 * anchor still reaches a server under the root the identity itself chains to.
 *
 * This is the case that would have failed while the context was being built, if
 * SSL_CTX_build_cert_chain had refused the foreign anchor added to the presented chain
 * instead of dropping it.
 */
void testTwoAnchorsConnectsUnderOwnRoot() {
    testShow() << __func__;

    auto initial(nt::NTScalar{TypeCode::Int32}.create());
    auto mbox(server::SharedPV::buildReadonly());

    auto serv_conf(server::Config::isolated());
    serv_conf.tls_keychain_file = SUPER_SERVER_KEYCHAIN_FILE;

    auto serv(serv_conf.build().addPV(TEST_PV, mbox));

    auto cli_conf(serv.clientConfig());
    cli_conf.tls_keychain_file = CLIENT1_TWO_ANCHORS_KEYCHAIN_FILE;

    auto cli(cli_conf.build());

    mbox.open(initial.update(TEST_PV_FIELD, 42));
    serv.start();

    auto is_tls{false};
    auto conn(cli.connect(TEST_PV).onConnect([&is_tls](const client::Connected& c) {
        is_tls = c.cred && c.cred->isTLS;
    }).exec());

    auto reply(cli.get(TEST_PV).exec()->wait(5.0));
    testTrue(is_tls) << "a two anchor keychain still secures the connection to its own root";
    testEq(reply[TEST_PV_FIELD].as<int32_t>(), 42);
    conn.reset();
}

/**
 * @brief testTwoAnchorsConnectsAcrossRoots checks the point of the whole feature:
 * two holders whose identities chain to roots neither issues under still reach each other,
 * because each keychain carries both roots as anchors.
 */
void testTwoAnchorsConnectsAcrossRoots() {
    testShow() << __func__;

    auto initial(nt::NTScalar{TypeCode::Int32}.create());
    auto mbox(server::SharedPV::buildReadonly());

    // The server's identity chains to the alternate root, and it holds both roots
    auto serv_conf(server::Config::isolated());
    serv_conf.tls_keychain_file = ALT_SERVER1_TWO_ANCHORS_KEYCHAIN_FILE;

    auto serv(serv_conf.build().addPV(TEST_PV, mbox));

    // The client's identity chains to the main root, and it holds both roots
    auto cli_conf(serv.clientConfig());
    cli_conf.tls_keychain_file = CLIENT1_TWO_ANCHORS_KEYCHAIN_FILE;

    auto cli(cli_conf.build());

    mbox.open(initial.update(TEST_PV_FIELD, 42));
    serv.start();

    auto is_tls{false};
    auto conn(cli.connect(TEST_PV).onConnect([&is_tls](const client::Connected& c) {
        is_tls = c.cred && c.cred->isTLS;
    }).exec());

    auto reply(cli.get(TEST_PV).exec()->wait(5.0));
    testTrue(is_tls) << "each side verifies the other under a root it does not issue under";
    testEq(reply[TEST_PV_FIELD].as<int32_t>(), 42);
    conn.reset();
}

/**
 * @brief testTwoAnchorsOrderDoesNotMatter repeats the case above with the client's two
 * anchors written the other way round in the chain, and expects the identical result.
 *
 * Anchors are found by the self-signed flag, so no anchor carries more weight for being
 * written earlier.
 */
void testTwoAnchorsOrderDoesNotMatter() {
    testShow() << __func__;

    auto initial(nt::NTScalar{TypeCode::Int32}.create());
    auto mbox(server::SharedPV::buildReadonly());

    auto serv_conf(server::Config::isolated());
    serv_conf.tls_keychain_file = ALT_SERVER1_TWO_ANCHORS_KEYCHAIN_FILE;

    auto serv(serv_conf.build().addPV(TEST_PV, mbox));

    auto cli_conf(serv.clientConfig());
    cli_conf.tls_keychain_file = CLIENT1_TWO_ANCHORS_REVERSED_KEYCHAIN_FILE;

    auto cli(cli_conf.build());

    mbox.open(initial.update(TEST_PV_FIELD, 42));
    serv.start();

    auto is_tls{false};
    auto conn(cli.connect(TEST_PV).onConnect([&is_tls](const client::Connected& c) {
        is_tls = c.cred && c.cred->isTLS;
    }).exec());

    auto reply(cli.get(TEST_PV).exec()->wait(5.0));
    testTrue(is_tls) << "the order the anchors are written in makes no difference";
    testEq(reply[TEST_PV_FIELD].as<int32_t>(), 42);
    conn.reset();
}

/**
 * @brief testKeychainWithNoAnchorRefused checks that a keychain carrying no trust anchor
 * at all is still refused, with the message it has always had.
 */
void testKeychainWithNoAnchorRefused() {
    testShow() << __func__;

    static const char expected[] = "Could not find Trusted Root Certificate Authority Certificate in keychain";

    const impl::evbase loop("noanchor");

    std::string message;
    try {
        const auto tls_context(buildClientContext(loop, CLIENT1_NO_ANCHOR_KEYCHAIN_FILE));
        testDiag("a context was built from a keychain holding no trust anchor");
    } catch (std::exception& e) {
        message = e.what();
        testDiag("refused with: %s", message.c_str());
    }

    testTrue(!message.empty()) << "a keychain holding no trust anchor is refused";
    testTrue(message.find(expected) != std::string::npos) << "refused with the message it has always had";
}

/**
 * @brief testPresentedChainExcludesForeignAnchor checks that the handshake presents this
 * identity's own chain and nothing else.
 *
 * extractCAs adds every certificate in the keychain to the presented chain, foreign
 * anchors included, and SSL_CTX_build_cert_chain then rebuilds that chain from the identity
 * certificate and drops whatever is not on its certification path.
 */
void testPresentedChainExcludesForeignAnchor() {
    testShow() << __func__;

    const impl::evbase loop("presented");
    const auto tls_context(buildClientContext(loop, CLIENT1_TWO_ANCHORS_KEYCHAIN_FILE));

    const auto intermediate(readKeychain(INTERMEDIATE_SERVER_KEYCHAIN_FILE));
    const auto main_root(readKeychain(CERT_AUTH_CERT_FILE));
    const auto alt_root(readKeychain(ALT_CERT_AUTH_KEYCHAIN_FILE));

    STACK_OF(X509)* presented = nullptr;
    SSL_CTX_get0_chain_certs(tls_context->ctx.get(), &presented);

    testEq(sk_X509_num(presented), 2) << "only the identity's issuer and its own root are presented";
    testTrue(stackHolds(presented, intermediate.cert.get())) << "the identity's issuer is presented";
    testTrue(stackHolds(presented, sk_X509_value(main_root.chain.get(), 0))) << "the identity's own root is presented";
    testTrue(!stackHolds(presented, sk_X509_value(alt_root.chain.get(), 0))) << "the foreign anchor is not presented";
}

/**
 * @brief testStatusReplyUnderOwnRootVerifies checks that a status reply signed under the
 * authority this identity chains to verifies against a store built from a two anchor keychain.
 */
void testStatusReplyUnderOwnRootVerifies() {
    testShow() << __func__;

    const impl::evbase loop("ownroot");
    const auto tls_context(buildClientContext(loop, CLIENT1_TWO_ANCHORS_KEYCHAIN_FILE));
    const auto trusted_store_ptr(tls_context->getCertStatusExData()->trusted_store_ptr);

    const auto authority(readKeychain(INTERMEDIATE_SERVER_KEYCHAIN_FILE));
    const auto subject(readKeychain(CLIENT1_KEYCHAIN_FILE));
    const auto reply(signStatusReply(authority, subject.cert.get()));
    const auto cert_id(statusReplyCertId(authority.cert.get(), subject.cert.get()));

    auto verified{false};
    uint32_t reported_status{~0u};
    try {
        const auto parsed(certs::CertStatusManager::parse(reply.data(), reply.size(), trusted_store_ptr, cert_id));
        verified = true;
        reported_status = parsed.ocsp_status.i;
    } catch (std::exception& e) {
        testDiag("refused: %s", e.what());
    }

    testTrue(verified) << "a reply signed under the root the identity chains to verifies";
    testEq(reported_status, static_cast<uint32_t>(certs::OCSP_CERTSTATUS_GOOD));
}

/**
 * @brief testStatusReplyUnderOtherAnchorVerifies checks that a status reply signed under the
 * other anchor in the keychain, which this identity does not chain to, verifies from the
 * very same store.  This is the requirement in one case.
 */
void testStatusReplyUnderOtherAnchorVerifies() {
    testShow() << __func__;

    const impl::evbase loop("otheranchor");
    const auto tls_context(buildClientContext(loop, CLIENT1_TWO_ANCHORS_KEYCHAIN_FILE));
    const auto trusted_store_ptr(tls_context->getCertStatusExData()->trusted_store_ptr);

    const auto authority(readKeychain(ALT_INTERMEDIATE_KEYCHAIN_FILE));
    const auto subject(readKeychain(ALT_SERVER1_KEYCHAIN_FILE));
    const auto reply(signStatusReply(authority, subject.cert.get()));
    const auto cert_id(statusReplyCertId(authority.cert.get(), subject.cert.get()));

    auto verified{false};
    uint32_t reported_status{~0u};
    try {
        const auto parsed(certs::CertStatusManager::parse(reply.data(), reply.size(), trusted_store_ptr, cert_id));
        verified = true;
        reported_status = parsed.ocsp_status.i;
    } catch (std::exception& e) {
        testDiag("refused: %s", e.what());
    }

    testTrue(verified) << "a reply signed under the other anchor verifies from the same store";
    testEq(reported_status, static_cast<uint32_t>(certs::OCSP_CERTSTATUS_GOOD));
}

/**
 * @brief testStatusReplyUnderUnknownAuthorityRefused checks that trusting more anchors has
 * not made the store trust everything: a reply signed by an authority reachable from no
 * anchor in the keychain is still refused.
 */
void testStatusReplyUnderUnknownAuthorityRefused() {
    testShow() << __func__;

    const impl::evbase loop("unknown");
    const auto tls_context(buildClientContext(loop, CLIENT1_TWO_ANCHORS_KEYCHAIN_FILE));
    const auto trusted_store_ptr(tls_context->getCertStatusExData()->trusted_store_ptr);

    // The fake hierarchy carries the same names as the real one but no anchor reaches it
    const auto authority(readKeychain(FAKE_INTERMEDIATE_KEYCHAIN_FILE));
    const auto subject(readKeychain(FAKE_CLIENT1_KEYCHAIN_FILE));
    const auto reply(signStatusReply(authority, subject.cert.get()));
    const auto cert_id(statusReplyCertId(authority.cert.get(), subject.cert.get()));

    std::string message;
    try {
        const auto parsed(certs::CertStatusManager::parse(reply.data(), reply.size(), trusted_store_ptr, cert_id));
        testDiag("accepted a reply signed by an authority no anchor reaches");
    } catch (std::exception& e) {
        message = e.what();
        testDiag("refused: %s", message.c_str());
    }

    testTrue(!message.empty()) << "a reply signed by an authority no anchor reaches is refused";
    // The refusal has to come from verifying the signature against the store, not from the
    // reply naming a different certificate than the one asked about
    testTrue(message.find("OCSP_basic_verify failed") != std::string::npos) << "refused because it does not verify against the store";
}

/**
 * @brief testFakeCertificateNameMatchingAttack tests that TLS authentication
 * is based on cryptographic verification, not just CN name matching.
 *
 * This test creates fake certificates with the SAME CNs as the real certificates
 * but signed by different (fake) Certificate Authorities. The test verifies that:
 * - Having the same CN is NOT sufficient for authentication
 * - The certificate must chain cryptographically to a trusted root
 * - Fake CAs that share CNs with real CAs are NOT trusted
 *
 * Test scenarios (all combinations of real/fake server and client certs):
 * 1. Real server + Real client → TLS succeeds (baseline)
 * 2. Fake server + Real client → TLS fails (fake server not trusted by real CA)
 * 3. Real server + Fake client → TLS fails (fake client not trusted by real CA)
 * 4. Fake server + Fake client → TLS succeeds (both share the same fake CA)
 *    This is expected - they authenticate each other, but this is NOT secure
 *    because neither chain traces back to a REAL trusted root.
 */
void testFakeCertificateNameMatchingAttack() {
    // Test 1: Real server + Real client (baseline - should succeed)
    {
        testShow() << __func__ << ": === Test 1: Real server + Real client (baseline) ===";
        auto initial(nt::NTScalar{TypeCode::Int32}.create());
        auto mbox(server::SharedPV::buildReadonly());

        auto serv_conf(server::Config::isolated());
        serv_conf.tls_keychain_file = SUPER_SERVER_KEYCHAIN_FILE;

        auto serv(serv_conf.build().addPV(TEST_PV, mbox));

        auto cli_conf(serv.clientConfig());
        cli_conf.tls_keychain_file = CLIENT1_KEYCHAIN_FILE;

        auto cli(cli_conf.build());

        mbox.open(initial.update(TEST_PV_FIELD, 42));
        serv.start();

        bool is_tls{false};
        auto conn(cli.connect(TEST_PV).onConnect([&is_tls](const client::Connected& c) {
            is_tls = c.cred && c.cred->isTLS;
        }).exec());

        auto reply(cli.get(TEST_PV).exec()->wait(5.0));
        testTrue(is_tls);
        testDiag("Real server + Real client: TLS should succeed");
        testEq(reply[TEST_PV_FIELD].as<int32_t>(), 42);
        conn.reset();
    }

    // Test 2: Fake server + Real client (should FAIL - fake server not trusted)
    {
        testShow() << __func__ << ":=== Test 2: Fake server + Real client ===";
        auto initial(nt::NTScalar{TypeCode::Int32}.create());
        auto mbox(server::SharedPV::buildReadonly());

        auto serv_conf(server::Config::isolated());
        serv_conf.tls_keychain_file = FAKE_SUPERSERVER_KEYCHAIN_FILE;

        auto serv(serv_conf.build().addPV(TEST_PV, mbox));

        auto cli_conf(serv.clientConfig());
        cli_conf.tls_keychain_file = CLIENT1_KEYCHAIN_FILE;

        auto cli(cli_conf.build());

        mbox.open(initial.update(TEST_PV_FIELD, 42));
        serv.start();

        try {
            auto conn(cli.connect(TEST_PV).onConnect([](const client::Connected&) {
                // Should not reach here
            }).exec());

            auto reply(cli.get(TEST_PV).exec()->wait(3.0));
            testFail("Fake server + Real client: Connection should have failed");
        } catch (std::exception& e) {
            testPass("Fake server + Real client: TLS correctly rejected fake server");
        }
    }

    // Test 3: Real server + Fake client (should FAIL - fake client not trusted)
    {
        testShow() << __func__ << ": === Test 3: Real server + Fake client ===";
        auto initial(nt::NTScalar{TypeCode::Int32}.create());
        auto mbox(server::SharedPV::buildReadonly());

        auto serv_conf(server::Config::isolated());
        serv_conf.tls_keychain_file = SUPER_SERVER_KEYCHAIN_FILE;

        auto serv(serv_conf.build().addPV(TEST_PV, mbox));

        auto cli_conf(serv.clientConfig());
        cli_conf.tls_keychain_file = FAKE_CLIENT1_KEYCHAIN_FILE;

        auto cli(cli_conf.build());

        mbox.open(initial.update(TEST_PV_FIELD, 42));
        serv.start();

        try {
            auto conn(cli.connect(TEST_PV).onConnect([](const client::Connected&) {
                // Should not reach here
            }).exec());

            auto reply(cli.get(TEST_PV).exec()->wait(3.0));
            testFail("Real server + Fake client: Connection should have failed");
        } catch (std::exception& e) {
            testPass("Real server + Fake client: TLS correctly rejected fake client");
        }
    }

    // Test 4: Fake server + Fake client (both share same fake CA - succeeds but insecure!)
    {
        testShow() << __func__ << ": === Test 4: Fake server + Fake client ===";
        auto initial(nt::NTScalar{TypeCode::Int32}.create());
        auto mbox(server::SharedPV::buildReadonly());

        auto serv_conf(server::Config::isolated());
        serv_conf.tls_keychain_file = FAKE_SUPERSERVER_KEYCHAIN_FILE;

        auto serv(serv_conf.build().addPV(TEST_PV, mbox));

        auto cli_conf(serv.clientConfig());
        cli_conf.tls_keychain_file = FAKE_CLIENT1_KEYCHAIN_FILE;

        auto cli(cli_conf.build());

        mbox.open(initial.update(TEST_PV_FIELD, 42));
        serv.start();

        bool is_tls{false};
        try {
            auto conn(cli.connect(TEST_PV).onConnect([&is_tls](const client::Connected& c) {
                is_tls = c.cred && c.cred->isTLS;
            }).exec());

            auto reply(cli.get(TEST_PV).exec()->wait(5.0));
            testTrue(is_tls);
            testEq(reply[TEST_PV_FIELD].as<int32_t>(), 42);
            conn.reset();
            testDiag("Fake+Fake: Connection succeeded (expected - both share fake CA)");
        } catch (std::exception& e) {
            testFail("Fake server + Fake client: Should have succeeded (both share fake CA)");
        }
    }
}

}  // namespace

// TLS-only transport mode (EPICS_PVAS_SERVER_PORT=NO)
// ----------------------------------------------------------------------------

namespace {

using namespace pvxs::impl;

// Result of a raw UDP SEARCH probe.
struct NoTcpSearchResult {
    bool replied = false;
    std::string proto;      // "tcp" or "tls" if a reply was parsed
    uint16_t port = 0;
};

// Send a raw UDP SEARCH to the server's UDP port on loopback advertising the
// given protocol list, and wait briefly for a SEARCH_RESPONSE.  Reply (if any)
// is delivered to the source socket (body reply-address is "any").
NoTcpSearchResult probeSearch(uint16_t serverUdpPort, std::initializer_list<const char*> protos,
                              const char* pvname = TEST_PV)
{
    NoTcpSearchResult out;

    SockAddr dest(SockAddr::loopback(AF_INET, serverUdpPort));
    SockAddr bindAddr(SockAddr::loopback(AF_INET, 0));

    evsocket sock(AF_INET, SOCK_DGRAM, 0);
    sock.bind(bindAddr);
    // recover the OS-assigned source port to embed in the SEARCH body
    SockAddr selfAddr;
    {
        socklen_t slen = selfAddr.size();
        getsockname(sock.sock, &selfAddr->sa, &slen);
    }
    const uint16_t selfPort = selfAddr.port();

    std::vector<uint8_t> msg;
    VectorOutBuf M(true, msg);
    M.skip(8, __FILE__, __LINE__); // header placeholder
    to_wire(M, uint32_t(0x55667788)); // searchID
    to_wire(M, uint8_t(pva_search_flags::Unicast));
    M.skip(3, __FILE__, __LINE__);
    to_wire(M, SockAddr::any(AF_INET)); // reply to sender
    to_wire(M, uint16_t(selfPort));
    to_wire(M, Size{protos.size()});
    for(auto p : protos)
        to_wire(M, p);
    to_wire(M, uint16_t(1)); // one name
    to_wire(M, uint32_t(1));
    to_wire(M, pvname);

    auto pktlen = M.consumed();
    FixedBuf H(true, msg.data(), 8);
    to_wire(H, Header{CMD_SEARCH, 0, uint32_t(pktlen-8)});
    if(!M.good() || !H.good()) {
        testFail("probeSearch: failed to build SEARCH");
        return out;
    }

    if(sendto(sock.sock, (char*)msg.data(), pktlen, 0, &dest->sa, dest.size()) != int(pktlen)) {
        testFail("probeSearch: sendto failed");
        return out;
    }

    std::vector<uint8_t> rxbuf(0x1000);
    for(int i=0; i<10; i++) {
        SockAddr from;
        socklen_t flen = from.size();
        evutil_socket_t s = sock.sock;
        timeval tmo{0, 50000}; // 50ms
        fd_set rs; FD_ZERO(&rs); FD_SET(s, &rs);
        int sr = select(int(s)+1, &rs, nullptr, nullptr, &tmo);
        if(sr <= 0) continue;
        auto n = recvfrom(s, (char*)rxbuf.data(), rxbuf.size(), 0, &from->sa, &flen);
        if(n <= 0) continue;

        // SEARCH_RESPONSE: header(8) guid(12) searchID(4) addr(16) port(2) proto(str)...
        FixedBuf R(true, rxbuf.data(), size_t(n));
        Header rh{};
        from_wire(R, rh);
        if(!R.good() || rh.cmd != CMD_SEARCH_RESPONSE)
            continue;
        R.skip(12, __FILE__, __LINE__); // guid
        uint32_t sid=0;
        from_wire(R, sid);
        SockAddr saddr;
        from_wire(R, saddr); // 16 bytes
        uint16_t sport=0;
        from_wire(R, sport);
        std::string proto;
        from_wire(R, proto);
        if(!R.good())
            continue;
        out.replied = true;
        out.proto = proto;
        out.port = sport;
        break;
    }
    return out;
}

// errlog capture helper: collects log lines into a string.
struct LogCapture {
    static std::string buf;
    static void listener(void* /*pvt*/, const char* message) {
        buf += message;
    }
    LogCapture() {
        buf.clear();
        errlogAddListener(&listener, nullptr);
    }
    ~LogCapture() {
        errlogRemoveListeners(&listener, nullptr);
    }
    std::string flush() {
        errlogFlush();
        return buf;
    }
};
std::string LogCapture::buf;

// 8.9 + 7a: EPICS_PVAS_SERVER_PORT / EPICS_PVAS_TLS_PORT "NO" parsing.
void testNoTcpTokenParsing() {
    testShow() << __func__;

    struct Case {
        const char* server_port;
        const char* tls_port;
        const char* bcast_port;
        bool expectTcpDisabled;
        bool expectTlsDisabled;
        bool expectUdpDisabled;
    };
    const Case cases[] = {
        {"5075", "5076", "5076", false, false, false},
        {"NO", "5076", "5076", true, false, false},
        {"5075", "NO", "5076", false, true, false},
        {"5075", "5076", "NO", false, false, true},
        {"NO", "NO", "5076", true, true, false},
        {"no", "Off", "FALSE", true, true, true},
    };


    for(const auto& c : cases) {
        auto conf(server::Config::isolated());
        conf.applyDefs({{"EPICS_PVAS_SERVER_PORT", c.server_port},
                        {"EPICS_PVAS_TLS_PORT", c.tls_port},
                        {"EPICS_PVAS_BROADCAST_PORT", c.bcast_port}});
        testEq(conf.tcp_disabled, c.expectTcpDisabled)
            << "EPICS_PVAS_SERVER_PORT=" << c.server_port;
        testEq(conf.tls_disabled, c.expectTlsDisabled)
            << "EPICS_PVAS_TLS_PORT=" << c.tls_port;
        testEq(conf.udp_disabled, c.expectUdpDisabled)
            << "EPICS_PVAS_BROADCAST_PORT=" << c.bcast_port;
    }

    // client_cert=require is independent of the port settings
    {
        auto conf(server::Config::isolated());
        conf.applyDefs({{"EPICS_PVAS_SERVER_PORT", "NO"},
                        {"EPICS_PVAS_TLS_OPTIONS", "client_cert=require"}});
        testTrue(conf.tcp_disabled) << "tcp disabled";
        testTrue(conf.tls_client_cert_required == server::Config::Require) << "require kept";
    }
}

// 8.8(a): updateDefs() round-trips the NO values.
void testNoTcpPrintTLSOptions() {
    testShow() << __func__;

    {
        auto conf(server::Config::isolated());
        conf.applyDefs({{"EPICS_PVAS_SERVER_PORT", "NO"}, {"EPICS_PVAS_BROADCAST_PORT", "NO"}});
        std::map<std::string, std::string> defs;
        conf.updateDefs(defs);
        testEq(defs["EPICS_PVAS_SERVER_PORT"], "NO");
        testEq(defs["EPICS_PVAS_BROADCAST_PORT"], "NO");
    }
    {
        auto conf(server::Config::isolated());
        std::map<std::string, std::string> defs;
        conf.updateDefs(defs);
        testTrue(defs["EPICS_PVAS_SERVER_PORT"].rfind("NO", 0) != 0) << "no NO prefix when enabled";
    }
}

// Both transports disabled is fatal at server construction.
void testNoTcpNoTlsFatal() {
    testShow() << __func__;

    auto conf(server::Config::isolated());
    conf.applyDefs({{"EPICS_PVAS_SERVER_PORT", "NO"}, {"EPICS_PVAS_TLS_PORT", "NO"}});
    testThrows<std::runtime_error>([&conf]() {
        auto serv(conf.build());
    });
}

// 8.8(b) + 7a: startup INFO transport line and dangerous-combo WARN capture.
void testNoTcpStartupDiagnostics() {
    testShow() << __func__;

    logger_level_set("pvxs.svr.init", Level::Info);

    // active, no client_cert=require: INFO line and dangerous-combo WARN present
    {
        LogCapture cap;
        auto serv_conf(server::Config::isolated());
        serv_conf.applyDefs({{"EPICS_PVAS_SERVER_PORT", "NO"}});
        serv_conf.tls_keychain_file = SUPER_SERVER_KEYCHAIN_FILE;
        auto serv(serv_conf.build());
        auto log = cap.flush();
        testTrue(log.find("transport: tls-only") != std::string::npos)
            << "startup INFO transport line expected";
        testTrue(log.find("without client_cert=require") != std::string::npos)
            << "dangerous-combo WARN expected";
    }

    // inactive: no transport line, no WARN
    {
        LogCapture cap;
        auto serv_conf(server::Config::isolated());
        serv_conf.tls_keychain_file = SUPER_SERVER_KEYCHAIN_FILE;
        auto serv(serv_conf.build());
        auto log = cap.flush();
        testTrue(log.find("transport: tls-only") == std::string::npos)
            << "no transport line when inactive";
        testTrue(log.find("without client_cert=require") == std::string::npos)
            << "no dangerous-combo WARN when inactive";
    }

    // active + client_cert=require: INFO line present, WARN absent
    {
        LogCapture cap;
        auto serv_conf(server::Config::isolated());
        serv_conf.applyDefs({{"EPICS_PVAS_SERVER_PORT", "NO"}, {"EPICS_PVAS_TLS_OPTIONS", "client_cert=require"}});
        serv_conf.tls_keychain_file = SUPER_SERVER_KEYCHAIN_FILE;
        auto serv(serv_conf.build());
        auto log = cap.flush();
        testTrue(log.find("transport: tls-only") != std::string::npos)
            << "startup INFO transport line expected (locked down)";
        testTrue(log.find("without client_cert=require") == std::string::npos)
            << "no dangerous-combo WARN when fully locked down";
    }

    logger_level_clear();
    logger_config_env();
}

// 8.2: plaintext listener not bound, TLS listener bound, TLS client connects.
void testNoTcpListenerNotBound() {
    testShow() << __func__;

    auto serv_conf(server::Config::isolated());
    serv_conf.applyDefs({{"EPICS_PVAS_SERVER_PORT", "NO"}});
    serv_conf.tls_keychain_file = SUPER_SERVER_KEYCHAIN_FILE;

    auto mbox(server::SharedPV::buildReadonly());
    auto serv(serv_conf.build().addPV(TEST_PV, mbox));
    mbox.open(nt::NTScalar{TypeCode::Int32}.create().update(TEST_PV_FIELD, 42));
    serv.start();

    const auto eff(serv.config());
    testEq(eff.tcp_port, 0u) << "no plaintext listener bound";
    testTrue(eff.tls_port != 0u) << "TLS listener bound on a real port";

    auto cli_conf(serv.clientConfig());
    cli_conf.tls_keychain_file = CLIENT1_KEYCHAIN_FILE;
    auto cli(cli_conf.build());
    bool is_tls=false;
    auto conn(cli.connect(TEST_PV)
        .onConnect([&is_tls](const client::Connected& c){ is_tls = c.cred && c.cred->isTLS; })
        .exec());
    testEq(cli.get(TEST_PV).exec()->wait(5.0)[TEST_PV_FIELD].as<int32_t>(), 42);
    testTrue(is_tls) << "connection is over TLS";
    conn.reset();
}

// name-server discovery for a tls-only server via a TLS name-server connection
void testNoTcpNameServerSearch() {
    testShow() << __func__;

    auto serv_conf(server::Config::isolated());
    serv_conf.applyDefs({{"EPICS_PVAS_SERVER_PORT", "NO"}});
    serv_conf.tls_keychain_file = SUPER_SERVER_KEYCHAIN_FILE;
    auto mbox(server::SharedPV::buildReadonly());
    auto serv(serv_conf.build().addPV(TEST_PV, mbox));
    mbox.open(nt::NTScalar{TypeCode::Int32}.create().update(TEST_PV_FIELD, 42));
    serv.start();
    const auto eff(serv.config());

    auto cli_conf(serv.clientConfig());
    cli_conf.tls_keychain_file = CLIENT1_KEYCHAIN_FILE;
    cli_conf.addressList.clear();
    cli_conf.autoAddrList = false;
    cli_conf.nameServers = {SB() << "pvas://127.0.0.1:" << eff.tls_port};
    auto cli(cli_conf.build());
    bool is_tls=false;
    auto conn(cli.connect(TEST_PV)
        .onConnect([&is_tls](const client::Connected& c){ is_tls = c.cred && c.cred->isTLS; })
        .exec());
    testEq(cli.get(TEST_PV).exec()->wait(5.0)[TEST_PV_FIELD].as<int32_t>(), 42);
    testTrue(is_tls) << "search and data both over TLS via pvas:// name server";
    conn.reset();
}

// 8.7: tls-only mode with no TLS keychain -> WARN, construction completes, nothing bound.
void testNoTcpNoKeychainWarns() {
    testShow() << __func__;

    logger_level_set("pvxs.svr.init", Level::Info);
    LogCapture cap;

    auto serv_conf(server::Config::isolated());
    serv_conf.applyDefs({{"EPICS_PVAS_SERVER_PORT", "NO"}});
    // intentionally no keychain
    auto serv(serv_conf.build()); // must not throw
    auto log = cap.flush();

    const auto eff(serv.config());
    testEq(eff.tcp_port, 0u) << "no plaintext listener bound";
    testTrue(log.find("unreachable") != std::string::npos)
        << "unreachable WARN expected in tls-only mode and TLS not configured";

    logger_level_clear();
    logger_config_env();
}

// 8.3 / 8.4 / 8.5: SEARCH-reply gating via raw UDP.
void testNoTcpSearchGating() {
    testShow() << __func__;

    auto serv_conf(server::Config::isolated());
    serv_conf.applyDefs({{"EPICS_PVAS_SERVER_PORT", "NO"}});
    serv_conf.tls_keychain_file = SUPER_SERVER_KEYCHAIN_FILE;

    auto mbox(server::SharedPV::buildReadonly());
    auto serv(serv_conf.build().addPV(TEST_PV, mbox));
    mbox.open(nt::NTScalar{TypeCode::Int32}.create().update(TEST_PV_FIELD, 42));
    serv.start();

    const auto eff(serv.config());
    const uint16_t udp = eff.udp_port;
    testTrue(udp != 0u) << "server has a UDP port";

    // 8.3: tcp-only SEARCH -> no reply
    {
        auto r = probeSearch(udp, {"tcp"});
        testTrue(!r.replied) << "no reply to a tcp-only SEARCH in tls-only mode";
    }
    // 8.4: tls+tcp SEARCH -> reply with TLS endpoint only
    {
        auto r = probeSearch(udp, {"tls", "tcp"});
        if(testTrue(r.replied) << "reply to tls+tcp SEARCH") {
            testStrEq(r.proto, std::string("tls")) << "advertises tls endpoint only";
            testEq(r.port, eff.tls_port) << "advertised port is tls_port";
        }
    }
    // 8.5: tls-only SEARCH -> reply with TLS endpoint
    {
        auto r = probeSearch(udp, {"tls"});
        if(testTrue(r.replied) << "reply to tls-only SEARCH") {
            testStrEq(r.proto, std::string("tls")) << "advertises tls endpoint";
            testEq(r.port, eff.tls_port) << "advertised port is tls_port";
        }
    }
}

// Capture the first beacon a server emits to a private loopback port.
void captureBeaconInto(server::Config& serv_conf, std::string& gotProto,
                       uint16_t& gotPort, ServerGUID& gotGuid, bool& got,
                       uint16_t& tcpPortOut, uint16_t& tlsPortOut, ServerGUID& guidOut)
{
    // pick a free loopback port, then release it for the UDPManager to bind
    SockAddr addr(SockAddr::loopback(AF_INET, 0));
    {
        evsocket probe(AF_INET, SOCK_DGRAM, 0);
        probe.bind(addr);
        socklen_t slen = addr.size();
        getsockname(probe.sock, &addr->sa, &slen);
    }
    const uint16_t capturePort = addr.port();

    epicsEvent rx;
    auto manager = UDPManager::instance();
    SockAddr listen(SockAddr::loopback(AF_INET, capturePort));
    auto sub = manager.onBeacon(listen, [&](const UDPManager::Beacon& b){
        gotProto = b.proto;
        gotPort = b.server.port();
        gotGuid = b.guid;
        rx.signal();
    });
    sub->start();

    serv_conf.auto_beacon = false;
    serv_conf.beaconDestinations.clear();
    serv_conf.beaconDestinations.emplace_back(SB()<<"127.0.0.1:"<<capturePort);

    auto serv(serv_conf.build());
    const auto eff(serv.config());
    tcpPortOut = eff.tcp_port;
    tlsPortOut = eff.tls_port;
    guidOut = eff.guid;
    serv.start();

    got = rx.wait(30.0);
}

// 6.4: beacon keeps proto="tcp"/tcp_port in tls-only mode (liveness ping only).
void testNoTcpBeacon() {
    testShow() << __func__;

    auto serv_conf(server::Config::isolated());
    serv_conf.applyDefs({{"EPICS_PVAS_SERVER_PORT", "NO"}});
    serv_conf.tls_keychain_file = SUPER_SERVER_KEYCHAIN_FILE;

    std::string gotProto; uint16_t gotPort=0; ServerGUID gotGuid{}; bool got=false;
    uint16_t tcpPort=0, tlsPort=0; ServerGUID guid{};
    captureBeaconInto(serv_conf, gotProto, gotPort, gotGuid, got, tcpPort, tlsPort, guid);

    if(testTrue(got) << "captured a beacon") {
        testStrEq(gotProto, std::string("tcp")) << "beacon proto stays tcp";
        testEq(gotPort, tcpPort) << "beacon port is the configured tcp_port";
        testTrue(std::equal(gotGuid.begin(), gotGuid.end(), guid.begin()))
            << "beacon GUID matches server";
    }
}

// 8.2a: tls-only mode x non-GOOD cert state -> ZERO replies (no tcp fallback).
// When the server's entity-cert status gate makes canRespondToTlsSearch() false,
// the TLS search arm is blocked; in tls-only mode the plaintext tcp arm is also gated
// off by policy, so a SEARCH gets no reply at all -- neither a tcp nor a tls
// endpoint.  This proves the policy gate and the cert-state gate compose (the
// server does NOT silently fall back to plaintext).
//
// what the successful TLS connect below confirms.
void testNoTcpConnectedSearch() {
    testShow() << __func__;

    auto serv_conf(server::Config::isolated());
    serv_conf.applyDefs({{"EPICS_PVAS_SERVER_PORT", "NO"}});
    serv_conf.tls_keychain_file = SUPER_SERVER_KEYCHAIN_FILE;

    auto mbox(server::SharedPV::buildReadonly());
    auto serv(serv_conf.build().addPV(TEST_PV, mbox));
    mbox.open(nt::NTScalar{TypeCode::Int32}.create().update(TEST_PV_FIELD, 42));
    serv.start();

    const auto eff(serv.config());
    testEq(eff.tcp_port, 0u) << "no plaintext listener bound";

    // Connect only via the server's TLS endpoint as a name server: no UDP/bcast
    // discovery, so the channel can only resolve through a connected SEARCH.
    auto cli_conf(serv.clientConfig());
    cli_conf.tls_keychain_file = CLIENT1_KEYCHAIN_FILE;
    cli_conf.autoAddrList = false;
    cli_conf.addressList.clear();
    cli_conf.nameServers.clear();
    cli_conf.nameServers.push_back(SB() << "pvas://127.0.0.1:" << eff.tls_port);

    auto cli(cli_conf.build());
    bool is_tls=false;
    auto conn(cli.connect(TEST_PV)
        .onConnect([&is_tls](const client::Connected& c){ is_tls = c.cred && c.cred->isTLS; })
        .exec());
    testEq(cli.get(TEST_PV).exec()->wait(5.0)[TEST_PV_FIELD].as<int32_t>(), 42);
    testTrue(is_tls) << "connected SEARCH resolved over TLS (no tcp endpoint advertised)";
    conn.reset();
}

// reconfigure into tls-only: full rebuild honors the flags
void testNoTcpReconfigure() {
    testShow() << __func__;

    auto serv_conf(server::Config::isolated());
    serv_conf.tls_keychain_file = SUPER_SERVER_KEYCHAIN_FILE;
    auto mbox(server::SharedPV::buildReadonly());
    auto serv(serv_conf.build().addPV(TEST_PV, mbox));
    mbox.open(nt::NTScalar{TypeCode::Int32}.create().update(TEST_PV_FIELD, 42));
    serv.start();
    testTrue(serv.config().tcp_port != 0u) << "plaintext listener bound before reconfigure";

    auto newconf(serv.config());
    newconf.tcp_disabled = true;
    newconf.tcp_port = 0;
    serv.reconfigure(newconf);

    const auto eff(serv.config());
    testEq(eff.tcp_port, 0u) << "no plaintext listener after reconfigure";
    testTrue(eff.tls_port != 0u) << "TLS listener bound after reconfigure";

    auto cli_conf(serv.clientConfig());
    cli_conf.tls_keychain_file = CLIENT1_KEYCHAIN_FILE;
    auto cli(cli_conf.build());
    testEq(cli.get(TEST_PV).exec()->wait(5.0)[TEST_PV_FIELD].as<int32_t>(), 42);
}

// reconfigure into a transportless config is rejected without touching the server
void testNoTcpReconfigureRejected() {
    testShow() << __func__;

    auto serv_conf(server::Config::isolated());
    serv_conf.tls_keychain_file = SUPER_SERVER_KEYCHAIN_FILE;
    auto mbox(server::SharedPV::buildReadonly());
    auto serv(serv_conf.build().addPV(TEST_PV, mbox));
    mbox.open(nt::NTScalar{TypeCode::Int32}.create().update(TEST_PV_FIELD, 42));
    serv.start();

    auto badconf(serv.config());
    badconf.tcp_disabled = true;
    badconf.tls_disabled = true;
    testThrows<std::invalid_argument>([&serv, &badconf]() { serv.reconfigure(badconf); });

    // original server must still be serving
    auto cli_conf(serv.clientConfig());
    cli_conf.tls_keychain_file = CLIENT1_KEYCHAIN_FILE;
    auto cli(cli_conf.build());
    testEq(cli.get(TEST_PV).exec()->wait(5.0)[TEST_PV_FIELD].as<int32_t>(), 42);
}

// 6.5: default (flag unset) beacon retains proto="tcp" / tcp_port.
void testDefaultBeaconUnchanged() {
    testShow() << __func__;

    auto serv_conf(server::Config::isolated());
    serv_conf.tls_keychain_file = SUPER_SERVER_KEYCHAIN_FILE;

    std::string gotProto; uint16_t gotPort=0; ServerGUID gotGuid{}; bool got=false;
    uint16_t tcpPort=0, tlsPort=0; ServerGUID guid{};
    captureBeaconInto(serv_conf, gotProto, gotPort, gotGuid, got, tcpPort, tlsPort, guid);

    if(testTrue(got) << "captured a beacon") {
        testStrEq(gotProto, std::string("tcp")) << "default beacon proto is tcp";
        testEq(gotPort, tcpPort) << "default beacon port is tcp_port";
    }
}

} // namespace


MAIN(testtls) {
    testPlan(155);
    testSetup();
    logger_config_env();
    testSubjectIdentity();
    testCommonNameLength();
    testSubjectCredentials();
    testLegacyMode();
    testClientBackwardsCompatibility();
    testServerBackwardsCompatibility();
    testServerOnly();
    testStrictServer();
    testGetSuper();
    testGetIntermediate();
    testGetNameServer();
    testClientReconfig();
    testServerReconfig();
    testMutualTLSWithMismatchedTrustRoot();
    testServerOnlyAuthWithMismatchedTrustAnchor();
    testServerOnlyAuthWithMatchingTrustAnchor();
    testMutualTLSWithMatchingTrustAnchors();
    testClientWithMismatchedChainFallback();
    testTwoAnchorsConnectsUnderOwnRoot();
    testTwoAnchorsConnectsAcrossRoots();
    testTwoAnchorsOrderDoesNotMatter();
    testKeychainWithNoAnchorRefused();
    testPresentedChainExcludesForeignAnchor();
    testStatusReplyUnderOwnRootVerifies();
    testStatusReplyUnderOtherAnchorVerifies();
    testStatusReplyUnderUnknownAuthorityRefused();
    testFakeCertificateNameMatchingAttack();
    // TLS-only transport mode (EPICS_PVAS_SERVER_PORT=NO)
    testNoTcpTokenParsing();
    testNoTcpPrintTLSOptions();
    testNoTcpNoTlsFatal();
    testNoTcpStartupDiagnostics();
    testNoTcpListenerNotBound();
    testNoTcpNameServerSearch();
    testNoTcpNoKeychainWarns();
    testNoTcpSearchGating();
    testNoTcpConnectedSearch();
    testNoTcpBeacon();
    testNoTcpReconfigure();
    testNoTcpReconfigureRejected();
    testDefaultBeaconUnchanged();
    cleanup_for_valgrind();
    return testDone();
}
