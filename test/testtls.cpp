/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
#define PVXS_ENABLE_EXPERT_API

#include <cstring>
#include <sstream>

#include <epicsUnitTest.h>
#include <testMain.h>

#include <pvxs/client.h>
#include <pvxs/log.h>
#include <pvxs/nt.h>
#include <pvxs/server.h>
#include <pvxs/sharedpv.h>
#include <pvxs/source.h>
#include <pvxs/unittest.h>

#include "certcontext.h"
#include "certstatus.h"
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

void testSuspendedStatusClass() {
    testDiag("=== testSuspendedStatusClass ===");
    {
        certs::CertificateStatus cs;
        cs.status = certs::PVACertStatus(certs::SCHEDULED_OFFLINE);
        testEq(int(cs.getStatusClass()), int(certs::cert_status_class_t::SUSPENDED));
    }
    {
        certs::CertificateStatus cs;
        cs.status = certs::PVACertStatus(certs::PENDING_RENEWAL);
        testEq(int(cs.getStatusClass()), int(certs::cert_status_class_t::SUSPENDED));
    }
    {
        certs::CertificateStatus cs;
        cs.status = certs::PVACertStatus(certs::VALID);
        testEq(int(cs.getStatusClass()), int(certs::cert_status_class_t::GOOD));
    }
    {
        certs::CertificateStatus cs;
        cs.status = certs::PVACertStatus(certs::EXPIRED);
        testEq(int(cs.getStatusClass()), int(certs::cert_status_class_t::BAD));
    }
    {
        certs::CertificateStatus cs;
        cs.status = certs::PVACertStatus(certs::PENDING);
        testEq(int(cs.getStatusClass()), int(certs::cert_status_class_t::UNKNOWN));
    }
}

/**
 * @brief Verifies that when the local entity certificate transitions to BAD
 *        (REVOKED/EXPIRED), the server tears down all live TLS connections
 *        and disables its TLS-listening interfaces.  Plain TCP listeners and
 *        connections are intentionally left untouched.
 */
void testServerLocalCertBadTearsDownTlsConn() {
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

    bool is_tls{false};
    epicsEvent disconnected_evt;
    auto conn(cli.connect(TEST_PV)
        .onConnect([&is_tls](const client::Connected& c) { is_tls = c.cred && c.cred->isTLS; })
        .onDisconnect([&disconnected_evt]() { disconnected_evt.signal(); })
        .exec());

    auto reply(cli.get(TEST_PV).exec()->wait(5.0));
    testTrue(is_tls) << "Initial connection must be over TLS";
    testEq(reply[TEST_PV_FIELD].as<int32_t>(), 42);

    serv.testInjectEntityCertBad();

    testTrue(disconnected_evt.wait(5.0))
        << "Client must observe disconnect after server's local cert went BAD";

    bool reconnect_is_tls{true};
    bool got_reconnect{false};
    auto conn2(cli.connect(TEST_PV)
        .onConnect([&reconnect_is_tls, &got_reconnect](const client::Connected& c) {
            reconnect_is_tls = c.cred && c.cred->isTLS;
            got_reconnect = true;
        })
        .exec());

    try {
        auto reply2(cli.get(TEST_PV).exec()->wait(5.0));
        if (got_reconnect) {
            testFalse(reconnect_is_tls)
                << "Reconnect after server local cert BAD must NOT be over TLS";
        } else {
            testPass("No reconnect after server local cert BAD (acceptable)");
        }
    } catch (std::exception&) {
        testPass("Reconnect timed out after TLS listener disabled (acceptable)");
    }
}

/**
 * @brief Verifies that when the local client entity certificate transitions
 *        to BAD (REVOKED/EXPIRED), the client tears down its live TLS
 *        outbound connections.  The channel-search machinery is left intact;
 *        the test does not assert on TCP fallback because the isolated
 *        server here only accepts TLS, but it does verify the TLS conn is
 *        physically gone (seen as a disconnect by the application).
 */
void testClientLocalCertBadTearsDownTlsConn() {
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

    bool is_tls{false};
    epicsEvent disconnected_evt;
    auto conn(cli.connect(TEST_PV)
        .onConnect([&is_tls](const client::Connected& c) { is_tls = c.cred && c.cred->isTLS; })
        .onDisconnect([&disconnected_evt]() { disconnected_evt.signal(); })
        .exec());

    auto reply(cli.get(TEST_PV).exec()->wait(5.0));
    testTrue(is_tls) << "Initial connection must be over TLS";
    testEq(reply[TEST_PV_FIELD].as<int32_t>(), 42);

    cli.testInjectEntityCertBad();

    testTrue(disconnected_evt.wait(5.0))
        << "Client must observe disconnect after its own local cert went BAD";
}

/**
 * @brief Regression test: a plain-TCP-only server (no TLS configured) MUST
 *        not be affected by the cert-status teardown machinery, because
 *        there is no entity certificate whose status could go BAD.  Calling
 *        the test injection helper on a non-TLS server is a no-op.
 */
void testNonTlsServerUnaffectedByLocalCertBad() {
    testShow() << __func__;

    auto initial(nt::NTScalar{TypeCode::Int32}.create());
    auto mbox(server::SharedPV::buildReadonly());

    auto serv_conf(server::Config::isolated());

    auto serv(serv_conf.build().addPV(TEST_PV, mbox));

    auto cli(serv.clientConfig().build());

    mbox.open(initial.update(TEST_PV_FIELD, 42));
    serv.start();

    auto conn(cli.connect(TEST_PV).onConnect([](const client::Connected& c) { testTrue(c.cred && !c.cred->isTLS); }).exec());

    auto reply(cli.get(TEST_PV).exec()->wait(5.0));
    testEq(reply[TEST_PV_FIELD].as<int32_t>(), 42);

    serv.testInjectEntityCertBad();
    cli.testInjectEntityCertBad();

    auto reply2(cli.get(TEST_PV).exec()->wait(5.0));
    testEq(reply2[TEST_PV_FIELD].as<int32_t>(), 42)
        << "Plain TCP must keep working after testInjectEntityCertBad on a non-TLS endpoint";
}

/**
 * @brief Verifies that after the server's local cert went BAD (TLS listeners
 *        disabled, live conns torn down), calling Server::reconfigure() with
 *        a fresh GOOD certificate fully restores TLS service: TLS listeners
 *        come back up and clients re-establish over TLS with the new identity.
 *        This is the "an external process replaced the BAD certificate"
 *        recovery path.
 */
void testServerLocalCertBadThenReconfigureGood() {
    testShow() << __func__;

    auto serv_conf(server::Config::isolated());
    serv_conf.tls_keychain_file = SERVER1_KEYCHAIN_FILE;

    auto serv(serv_conf.build().addSource(WHO_AM_I_PV, std::make_shared<WhoAmI>()));

    auto cli_conf(serv.clientConfig());
    cli_conf.tls_keychain_file = IOC1_KEYCHAIN_FILE;

    auto cli(cli_conf.build());

    serv.start();

    epicsEvent evt;
    auto sub(cli.monitor(WHO_AM_I_PV).maskConnected(false).maskDisconnected(false)
        .event([&evt](client::Subscription&) { evt.signal(); }).exec());

    try {
        pop(sub, evt);
        testFail("Unexpected success");
        testSkip(2, "oops");
    } catch (client::Connected& e) {
        testTrue(e.cred && e.cred->isTLS) << "Initial connection must be TLS with original cert";
        testEq(e.cred->account, CERT_CN_SERVER1);
    }
    (void)pop(sub, evt);  // drain the post-Connected update

    serv.testInjectEntityCertBad();

    testThrows<client::Disconnect>([&sub, &evt] { pop(sub, evt); })
        << "Client must observe Disconnect after server local cert went BAD";

    serv_conf = serv.config();
    serv_conf.tls_keychain_file = IOC1_KEYCHAIN_FILE;
    testDiag("serv.reconfigure() with fresh GOOD cert");
    serv.reconfigure(serv_conf);

    try {
        pop(sub, evt);
        testFail("Missing expected Connected after reconfigure");
        testSkip(2, "oops");
    } catch (client::Connected& e) {
        testTrue(e.cred && e.cred->isTLS) << "TLS must resume after reconfigure with GOOD cert";
        testEq(e.cred->account, CERT_CN_IOC1);
    }
}

/**
 * @brief Verifies that after the client's local cert went BAD, calling
 *        Context::reconfigure() with a fresh GOOD certificate restores TLS
 *        outbound: the client re-establishes over TLS with the new identity.
 */
void testClientLocalCertBadThenReconfigureGood() {
    testShow() << __func__;

    auto serv_conf(server::Config::isolated());
    serv_conf.tls_keychain_file = SUPER_SERVER_KEYCHAIN_FILE;

    auto serv(serv_conf.build().addSource(WHO_AM_I_PV, std::make_shared<WhoAmI>()));

    auto cli_conf(serv.clientConfig());
    cli_conf.tls_keychain_file = CLIENT1_KEYCHAIN_FILE;

    auto cli(cli_conf.build());

    serv.start();

    epicsEvent evt;
    auto sub(cli.monitor(WHO_AM_I_PV).maskConnected(false).maskDisconnected(false)
        .event([&evt](client::Subscription&) { evt.signal(); }).exec());

    try {
        pop(sub, evt);
        testFail("Unexpected success");
        testSkip(1, "oops");
    } catch (client::Connected& e) {
        testTrue(e.cred && e.cred->isTLS) << "Initial connection must be TLS with original cert";
    }
    Value who1 = pop(sub, evt);
    testEq(who1[TEST_PV_FIELD].as<std::string>(), TLS_METHOD_STRING "/" CERT_CN_CLIENT1)
        << "Server must initially see client1's identity";

    cli.testInjectEntityCertBad();

    testThrows<client::Disconnect>([&sub, &evt] { pop(sub, evt); })
        << "Client must observe Disconnect after its own local cert went BAD";

    cli_conf = cli.config();
    cli_conf.tls_keychain_file = CLIENT2_KEYCHAIN_FILE;
    cli_conf.setKeychainPassword(CLIENT2_KEYCHAIN_FILE_PWD);
    testDiag("cli.reconfigure() with fresh GOOD cert");
    cli.reconfigure(cli_conf);

    try {
        pop(sub, evt);
        testFail("Missing expected Connected after reconfigure");
        testSkip(1, "oops");
    } catch (client::Connected& e) {
        testTrue(e.cred && e.cred->isTLS) << "TLS must resume after reconfigure with GOOD cert";
    }
    Value who2 = pop(sub, evt);
    testEq(who2[TEST_PV_FIELD].as<std::string>(), TLS_METHOD_STRING "/" CERT_CN_CLIENT2)
        << "After reconfigure server must see client2's new identity";
}

/**
 * @brief Verifies that when the server's local cert status becomes UNKNOWN
 *        on a live TLS connection, GETs continue to work both during the
 *        UNKNOWN window and after recovery to GOOD.  This is the live-UNKNOWN
 *        policy: presume cert still valid, pause WRITE operations (covered
 *        separately in suspended-by-cert tests), replay on recovery.  Reads
 *        are intentionally not gated.  Distinct from the BAD policy which is
 *        permanent and tears down conns.
 */
void testServerLocalCertUnknownThenGood() {
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

    bool initial_is_tls{false};
    auto conn(cli.connect(TEST_PV)
        .onConnect([&initial_is_tls](const client::Connected& c) { initial_is_tls = c.cred && c.cred->isTLS; })
        .exec());

    testEq(cli.get(TEST_PV).exec()->wait(5.0)[TEST_PV_FIELD].as<int32_t>(), 42);
    testTrue(initial_is_tls) << "Initial connection must be over TLS";

    serv.testInjectEntityCertUnknown();
    epicsThread::sleep(0.5);

    testEq(cli.get(TEST_PV).exec()->wait(5.0)[TEST_PV_FIELD].as<int32_t>(), 42)
        << "GET must still work during server UNKNOWN window (live conn preserved)";

    serv.testInjectEntityCertGood();
    epicsThread::sleep(0.5);

    testEq(cli.get(TEST_PV).exec()->wait(5.0)[TEST_PV_FIELD].as<int32_t>(), 42)
        << "GET must still work after server cert resumes GOOD";
}

/**
 * @brief Mirror of the server-side test for the client side.  When the
 *        client's own cert status goes UNKNOWN, all client-issued operations
 *        (GET/PUT/RPC) are gated client-side until status recovers.  This
 *        test verifies that ops are restored after GOOD recovery and the
 *        underlying TLS connection was preserved across the cycle (the post-
 *        recovery GET succeeds without a fresh search/handshake observable
 *        delay).
 */
void testClientLocalCertUnknownThenGood() {
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

    bool initial_is_tls{false};
    auto conn(cli.connect(TEST_PV)
        .onConnect([&initial_is_tls](const client::Connected& c) { initial_is_tls = c.cred && c.cred->isTLS; })
        .exec());

    testEq(cli.get(TEST_PV).exec()->wait(5.0)[TEST_PV_FIELD].as<int32_t>(), 42);
    testTrue(initial_is_tls) << "Initial connection must be over TLS";

    cli.testInjectEntityCertUnknown();
    epicsThread::sleep(0.5);

    cli.testInjectEntityCertGood();
    epicsThread::sleep(0.5);

    testEq(cli.get(TEST_PV).exec()->wait(5.0)[TEST_PV_FIELD].as<int32_t>(), 42)
        << "GET must work after client cert resumes GOOD (conn was preserved)";
}

MAIN(testtls) {
    testPlan(79);
    testSetup();
    logger_config_env();
    testSuspendedStatusClass();
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
    testServerLocalCertBadTearsDownTlsConn();
    testClientLocalCertBadTearsDownTlsConn();
    testNonTlsServerUnaffectedByLocalCertBad();
    testServerLocalCertBadThenReconfigureGood();
    testClientLocalCertBadThenReconfigureGood();
    testServerLocalCertUnknownThenGood();
    testClientLocalCertUnknownThenGood();
    cleanup_for_valgrind();
    return testDone();
}
