/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <testMain.h>

#include <epicsUnitTest.h>

#include <epicsEvent.h>

#include <pvxs/unittest.h>
#include <pvxs/log.h>
#include <pvxs/client.h>
#include <pvxs/server.h>
#include <pvxs/sharedpv.h>
#include <pvxs/source.h>
#include <pvxs/nt.h>
#include "utilpvt.h"

namespace {
using namespace pvxs;

void testNameServer()
{
    testShow()<<__func__;

    auto pv(server::SharedPV::buildReadonly());
    pv.open(nt::NTScalar{TypeCode::UInt32}.create()
            .update("value", 42u));

    auto serv(server::Config::isolated()
              .build()
              .addPV("testpv", pv)
              .start());

    testShow()<<"Server config\n"<<serv.config();

    auto cliconf(serv.clientConfig());
    for(auto& addr : cliconf.addressList)
        cliconf.nameServers.push_back(SB()<<"pva://"<<addr<<':'<<cliconf.tcp_port<<'/');
    cliconf.autoAddrList = false;
    cliconf.addressList.clear();

    auto cli(cliconf.build());

    testShow()<<"Client config\n"<<cli.config();

    epicsEvent update;
    auto mon(cli.monitor("testpv")
             .maskConnected(false)
             .maskDisconnected(false)
             .event([&update](client::Subscription&){
                 testDiag("event");
                 update.signal();
             }).exec());

    auto popExc = [&mon, &update]() -> std::exception_ptr {
        while(true) {
            if(auto var = mon->pop()) {
                throw std::runtime_error(SB()<<" Unexpected update\n"<<var);
            }
            if(!update.wait(500.0))
                throw std::runtime_error(SB()<<" Timeout");
        }
    };

    auto popVal = [&mon, &update]() {
        while(true) {
            try {
                if(auto var = mon->pop()) {
                    testEq(var["value"].as<uint32_t>(), 42u);
                    return;
                }
                if(!update.wait(500.0))
                    throw std::runtime_error(SB()<<" Timeout");
            } catch(std::exception& e) {
                testTrue(false)<<" Unexpected update: "<<e.what();
                return;
            }
        }
    };

    testThrows<client::Connected>([&popExc]() { popExc(); });
    popVal();

    testDiag("Stopping server");
    serv.stop();

    testThrows<client::Disconnect>([&popExc]() { popExc(); });

    testDiag("Restarting server");
    serv.start();

    testThrows<client::Connected>([&popExc]() { popExc(); });
    popVal();
}

// A name server is kept as configured, and a name that does not resolve is kept rather than
// discarded, because it is resolved again each time it is dialled.
//
// Resolving when the configuration was read meant a peer that had not started yet was dropped
// for the lifetime of the process, and one that had was pinned to the address it held at that
// moment. Both matter wherever peers are restarted or come up in an arbitrary order.
void testNameServerDeferredResolution()
{
    testShow()<<__func__;

    client::Config conf;
    conf.applyDefs(std::map<std::string, std::string>{
        {"EPICS_PVA_NAME_SERVERS", "no.such.host.invalid:5075 127.0.0.1:5099"},
        {"EPICS_PVA_AUTO_ADDR_LIST", "NO"},
        {"EPICS_PVA_ADDR_LIST", ""},
    });

    testEq(conf.nameServers.size(), 2u)
        <<"a name that does not resolve is kept, and does not take its neighbour with it";

    // Kept verbatim rather than rewritten to whatever it resolved to, which is what lets it be
    // resolved again later. The list is sorted, as it always has been, so neither position is
    // asserted here.
    const auto holds([&conf](const char* spec) {
        for(const auto& ns : conf.nameServers)
            if(ns == spec) return true;
        return false;
    });
    testTrue(holds("no.such.host.invalid:5075"))<<"kept as written, not resolved away";
    testTrue(holds("127.0.0.1:5099"))<<"kept as written";

    // Applying again replaces rather than appends.
    conf.applyDefs(std::map<std::string, std::string>{
        {"EPICS_PVA_NAME_SERVERS", "127.0.0.1:5099"},
    });
    testEq(conf.nameServers.size(), 1u)<<"a second reading replaces the list";

    // The unresolvable entry must not stop the context being built, nor stop the other one
    // being used. Building it is the whole assertion; it used to be refused configuration.
    auto cli(conf.build());
    testTrue(!!cli.config().nameServers.size())
        <<"context keeps its name servers";
}

} // namespace

MAIN(testnamesrv)
{
    testPlan(10);
    testSetup();
    logger_config_env();
    testNameServer();
    testNameServerDeferredResolution();
    cleanup_for_valgrind();
    return testDone();
}
