/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
#include <testMain.h>

#include <epicsUnitTest.h>

#include <pvxs/unittest.h>
#include "utilpvt.h"

using namespace pvxs;
namespace {

void testPlainAccountUnchanged()
{
    testDiag("%s", __func__);
    testEq(impl::stripCaUserReservedPrefix("sly"), "sly");
}

void testStructuredAccountPreserved()
{
    testDiag("%s", __func__);
    testEq(impl::stripCaUserReservedPrefix("ops/sly"), "ops/sly");
}

void testKerberosLikePrincipalPreserved()
{
    testDiag("%s", __func__);
    testEq(impl::stripCaUserReservedPrefix("sly/admin@SLAC.STANFORD.EDU"),
           "sly/admin@SLAC.STANFORD.EDU");
}

void testRolePrefixStripped()
{
    testDiag("%s", __func__);
    testEq(impl::stripCaUserReservedPrefix("role/admins"), "admins");
}

void testX509PrefixStripped()
{
    testDiag("%s", __func__);
    testEq(impl::stripCaUserReservedPrefix("x509/sly"), "sly");
}

void testCaseSensitiveRolePreserved()
{
    testDiag("%s", __func__);
    testEq(impl::stripCaUserReservedPrefix("Role/admins"), "Role/admins");
}

void testCaseSensitiveX509Preserved()
{
    testDiag("%s", __func__);
    testEq(impl::stripCaUserReservedPrefix("X509/sly"), "X509/sly");
}

void testMidStringReservedWordNotStripped()
{
    testDiag("%s", __func__);
    testEq(impl::stripCaUserReservedPrefix("sly/role/admin"), "sly/role/admin");
}

void testEmptyInput()
{
    testDiag("%s", __func__);
    testEq(impl::stripCaUserReservedPrefix(""), "");
}

void testRoleAloneNotStripped()
{
    testDiag("%s", __func__);
    testEq(impl::stripCaUserReservedPrefix("role"), "role");
}

void testX509AloneNotStripped()
{
    testDiag("%s", __func__);
    testEq(impl::stripCaUserReservedPrefix("x509"), "x509");
}

void testRolePrefixWithEmptyTail()
{
    testDiag("%s", __func__);
    testEq(impl::stripCaUserReservedPrefix("role/"), "");
}

} // namespace

MAIN(testcaingestpolicy)
{
    testPlan(12);
    testSetup();
    testPlainAccountUnchanged();
    testStructuredAccountPreserved();
    testKerberosLikePrincipalPreserved();
    testRolePrefixStripped();
    testX509PrefixStripped();
    testCaseSensitiveRolePreserved();
    testCaseSensitiveX509Preserved();
    testMidStringReservedWordNotStripped();
    testEmptyInput();
    testRoleAloneNotStripped();
    testX509AloneNotStripped();
    testRolePrefixWithEmptyTail();
    return testDone();
}
