/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
#define PVXS_ENABLE_EXPERT_API

#include <algorithm>
#include <cstring>
#include <map>
#include <sstream>
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

    // NO,<alt_search_port> sets the search-only listener port
    {
        auto conf(server::Config::isolated());
        conf.applyDefs({{"EPICS_PVAS_SERVER_PORT", "no,5080"}});
        testTrue(conf.tcp_disabled) << "tcp disabled via no,<port>";
        testEq(conf.tcp_port, 5080u) << "alternative search port applied";
    }

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
        testTrue(defs["EPICS_PVAS_SERVER_PORT"].rfind("NO,", 0) == 0) << "SERVER_PORT round-trips as NO,<port>";
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
    testTrue(eff.tcp_port != 0u) << "plaintext listener still bound (search-only)";
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

// name-server discovery: TLS client searches over the plaintext connection,
// gets the tls endpoint, and connects over TLS
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
    cli_conf.nameServers = {SB() << "127.0.0.1:" << eff.tcp_port};
    auto cli(cli_conf.build());
    bool is_tls=false;
    auto conn(cli.connect(TEST_PV)
        .onConnect([&is_tls](const client::Connected& c){ is_tls = c.cred && c.cred->isTLS; })
        .exec());
    testEq(cli.get(TEST_PV).exec()->wait(5.0)[TEST_PV_FIELD].as<int32_t>(), 42);
    testTrue(is_tls) << "name-server search over plaintext resolved to a TLS connection";
    conn.reset();

    // a plain (no TLS) client via the same name server must get no claim
    auto plain_conf(serv.clientConfig());
    plain_conf.addressList.clear();
    plain_conf.autoAddrList = false;
    plain_conf.nameServers = {SB() << "127.0.0.1:" << eff.tcp_port};
    auto plain(plain_conf.build());
    testThrows<client::Timeout>([&plain]() {
        plain.get(TEST_PV).exec()->wait(1.5);
    }) << "plaintext-only client gets no claim from a tls-only server";
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
    testTrue(eff.tcp_port != 0u) << "plaintext listener still bound (search-only)";
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

// 6.4: beacon emitted with proto="tls" and tls_port in tls-only mode.
void testNoTcpBeacon() {
    testShow() << __func__;

    auto serv_conf(server::Config::isolated());
    serv_conf.applyDefs({{"EPICS_PVAS_SERVER_PORT", "NO"}});
    serv_conf.tls_keychain_file = SUPER_SERVER_KEYCHAIN_FILE;

    std::string gotProto; uint16_t gotPort=0; ServerGUID gotGuid{}; bool got=false;
    uint16_t tcpPort=0, tlsPort=0; ServerGUID guid{};
    captureBeaconInto(serv_conf, gotProto, gotPort, gotGuid, got, tcpPort, tlsPort, guid);

    if(testTrue(got) << "captured a beacon") {
        testStrEq(gotProto, std::string("tls")) << "beacon proto is tls";
        testEq(gotPort, tlsPort) << "beacon port is tls_port";
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
    testTrue(eff.tcp_port != 0u) << "plaintext listener still bound (search-only)";

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
    testTrue(eff.tcp_port != 0u) << "plaintext search-only listener after reconfigure";
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
    testPlan(112);
    testSetup();
    logger_config_env();
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
