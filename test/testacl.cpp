/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <testMain.h>
#include <epicsUnitTest.h>
#include <epicsEvent.h>
#include <epicsThread.h>

#include <pvxs/unittest.h>
#include <pvxs/log.h>
#include <pvxs/client.h>
#include <pvxs/server.h>
#include <pvxs/sharedpv.h>
#include <pvxs/source.h>
#include <pvxs/nt.h>

namespace {
using namespace pvxs;

struct AclTester {
    Value initial;
    server::Server serv;
    client::Context cli;

    AclTester(server::SharedPV& pv)
        :initial(nt::NTScalar{TypeCode::Int32}.create())
        ,serv(server::Config::isolated(AF_INET)
              .build()
              .addPV("test:pv", pv))
        ,cli(serv.clientConfig().build())
    {
        initial["value"] = 0;
        pv.open(initial);
        serv.start();
    }
};

void testWritablePV()
{
    testDiag("%s", __func__);

    auto pv = server::SharedPV::buildMailbox();

    AclTester t(pv);

    auto mon = t.cli.monitor("test:pv")
        .event([&](client::Subscription& sub) {
            try { sub.pop(); } catch(...) {}
        })
        .exec();

    auto conn = t.cli.connect("test:pv")
        .onConnect([](){ })
        .exec();

    epicsThreadSleep(1.0);

    testOk1(conn->connected());
}

void testReadonlyPV()
{
    testDiag("%s", __func__);

    auto pv = server::SharedPV::buildReadonly();

    AclTester t(pv);

    auto conn = t.cli.connect("test:pv")
        .onConnect([](){ })
        .exec();

    epicsThreadSleep(1.0);

    testOk1(conn->connected());
}

void testSignalRightsChange()
{
    testDiag("%s", __func__);

    server::SharedPV pv(server::SharedPV::buildMailbox());
    Value initial(nt::NTScalar{TypeCode::Int32}.create());
    initial["value"] = 42;

    server::Server serv = server::Config::isolated(AF_INET)
        .build()
        .addPV("test:rights", pv);
    client::Context cli(serv.clientConfig().build());

    pv.open(initial);
    serv.start();

    epicsEvent evt;
    auto conn = cli.connect("test:rights")
        .onConnect([&evt](){ evt.signal(); })
        .exec();

    testOk1(evt.wait(5.0));
    testOk1(conn->connected());

    epicsThreadSleep(0.1);
}

}

MAIN(testacl)
{
    testPlan(4);
    testSetup();
    pvxs::logger_config_env();
    testWritablePV();
    testReadonlyPV();
    testSignalRightsChange();
    cleanup_for_valgrind();
    return testDone();
}
