/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#define PVXS_ENABLE_EXPERT_API

#include <string>

#include <epicsUnitTest.h>
#include <testMain.h>

#include <pvxs/unittest.h>

#include "certstatus.h"

namespace {

using pvxs::certs::CertStatusManager;
using pvxs::certs::CertStatusNoExtensionException;

}

MAIN(testcertstatuspv)
{
    testPlan(5);

    const std::string issuer("0293823f");

    // (a) canonical CERT:STATUS:<8hex>:<20-digit> -> trailing cert id
    {
        const std::string serial("00007246297371190731775");
        testEq(CertStatusManager::getCertIdFromStatusPv("CERT:STATUS:" + issuer + ":" + serial),
               CertStatusManager::getCertIdFromSerialAndIssuer(issuer, serial));
    }

    // (b) multi-segment colon-bearing prefix -> same trailing cert id (prefix-length-agnostic)
    {
        const std::string serial("00007246297371190731775");
        testEq(CertStatusManager::getCertIdFromStatusPv("MYCMS:CERT:STATUS:" + issuer + ":" + serial),
               CertStatusManager::getCertIdFromSerialAndIssuer(issuer, serial));
    }

    // (c) a serial that is NOT 20 wide is re-canonicalised to the 20-digit form
    {
        const std::string raw_serial("7246297371190731775");
        testEq(CertStatusManager::getCertIdFromStatusPv("CERT:STATUS:" + issuer + ":" + raw_serial),
               CertStatusManager::getCertIdFromSerialAndIssuer(issuer, raw_serial));
    }

    // (d) empty / fewer-than-two-colon inputs fail closed
    pvxs::testThrows<CertStatusNoExtensionException>([]() {
        (void)CertStatusManager::getCertIdFromStatusPv("");
    });
    pvxs::testThrows<CertStatusNoExtensionException>([]() {
        (void)CertStatusManager::getCertIdFromStatusPv("STATUS");
    });

    return testDone();
}
