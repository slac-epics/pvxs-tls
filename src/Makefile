TOP=..

include $(TOP)/configure/CONFIG
# cfg/ sometimes isn't correctly included due to a Base bug
# so we do here (maybe again) as workaround
-include $(wildcard $(TOP)/cfg/CONFIG*)
#----------------------------------------
#  ADD MACRO DEFINITIONS AFTER THIS LINE
#=============================
ifeq ($(EVENT2_HAS_OPENSSL),YES)
USR_CPPFLAGS += -DPVXS_ENABLE_OPENSSL
endif # EVENT2_HAS_OPENSSL

USR_CPPFLAGS += -DPVXS_API_BUILDING
USR_CPPFLAGS += -DPVXS_ENABLE_EXPERT_API

PVXS_ENABLE_SSLKEYLOGFILE ?= YES

PVXS_ENABLE_SSLKEYLOGFILE_YES = -DPVXS_ENABLE_SSLKEYLOGFILE
USR_CPPFLAGS += $(PVXS_ENABLE_SSLKEYLOGFILE_$(PVXS_ENABLE_SSLKEYLOGFILE))

ifdef T_A
ifneq ($(CONFIG_LOADED),YES)
$(warning Toolchain inspection failed $(MAKEFILE_LIST))
endif
endif

ifdef BASE_3_15
ifeq ($(GNUISH),YES)
# we explicitly mark dllimport/export anyway.
# So hide our internal symbols to speed up linking/loading on all targets.
USR_CFLAGS += -fvisibility=hidden
USR_CXXFLAGS += -fvisibility=hidden -fvisibility-inlines-hidden
endif
endif

# fault on any undefined symbols (eg. from missing LIB_SYS_LIBS)
# breaks on older ncurses (circa RHEL6) not using the INPUT() trick to pull in libtinfo.so
#USR_LDFLAGS_Linux += -Wl,--no-undefined -Wl,--no-allow-shlib-undefined

# see below for special case versionNum.h
EXPAND += describe.h

EXPANDVARS += PVXS_MAJOR_VERSION
EXPANDVARS += PVXS_MINOR_VERSION
EXPANDVARS += PVXS_MAINTENANCE_VERSION
EXPANDVARS += EPICS_HOST_ARCH T_A OS_CLASS
ifdef BASE_3_15
EXPANDVARS += CMPLR_CLASS
endif

EXPANDFLAGS += $(foreach var,$(EXPANDVARS),-D$(var)="$(strip $($(var)))")

GENVERSION = pvxsVCS.h
GENVERSIONMACRO = PVXS_VCS_VERSION

SHRLIB_VERSION = $(PVXS_MAJOR_VERSION).$(PVXS_MINOR_VERSION)

# Access to certs specific headers
USR_CPPFLAGS += -I$(TOP)/certs
SRC_DIRS += $(TOP)/certs

INC += pvxs/client.h
INC += pvxs/config.h
INC += pvxs/data.h
INC += pvxs/log.h
INC += pvxs/netcommon.h
INC += pvxs/nt.h
INC += pvxs/server.h
INC += pvxs/sharedArray.h
INC += pvxs/sharedpv.h
INC += pvxs/sharedwildcardpv.h
INC += pvxs/source.h
INC += pvxs/srvcommon.h
INC += pvxs/unittest.h
INC += pvxs/util.h
INC += pvxs/version.h
INC += pvxs/versionNum.h

LIBRARY = pvxs

LIB_SRCS += bitmask.cpp
LIB_SRCS += certstatus.cpp
LIB_SRCS += certstatusmanager.cpp
LIB_SRCS += client.cpp
LIB_SRCS += clientconn.cpp
LIB_SRCS += clientdiscover.cpp
LIB_SRCS += clientget.cpp
LIB_SRCS += clientintrospect.cpp
LIB_SRCS += clientmon.cpp
LIB_SRCS += clientreq.cpp
LIB_SRCS += config.cpp
LIB_SRCS += conn.cpp
LIB_SRCS += data.cpp
LIB_SRCS += dataencode.cpp
LIB_SRCS += datafmt.cpp
LIB_SRCS += describe.cpp
LIB_SRCS += evhelper.cpp
LIB_SRCS += log.cpp
LIB_SRCS += nt.cpp
LIB_SRCS += openssl.cpp
LIB_SRCS += sslinit.cpp
LIB_SRCS += osdSockExt.cpp
LIB_SRCS += osgroups.cpp
LIB_SRCS += pvrequest.cpp
LIB_SRCS += server.cpp
LIB_SRCS += serverchan.cpp
LIB_SRCS += serverconn.cpp
LIB_SRCS += serverget.cpp
LIB_SRCS += serverintrospect.cpp
LIB_SRCS += servermon.cpp
LIB_SRCS += serversource.cpp
LIB_SRCS += sharedarray.cpp
LIB_SRCS += sharedpv.cpp
LIB_SRCS += sharedwildcardpv.cpp
LIB_SRCS += type.cpp
LIB_SRCS += udp_collector.cpp
LIB_SRCS += unittest.cpp
LIB_SRCS += util.cpp

LIB_SRCS += certfactory.cpp
LIB_SRCS += certfilefactory.cpp
LIB_SRCS += p12filefactory.cpp

LIB_LIBS += Com

# special case matching configure/RULES_PVXS_MODULE
ifeq (,$(LIBEVENT_PREFIX))
LIB_SYS_LIBS += $(LIBEVENT_BUNDLE_LIBS)
else
LIB_LIBS += $(LIBEVENT_BUNDLE_LIBS)
endif

LIB_SYS_LIBS += $(LIBEVENT_SYS_LIBS)

#ifeq ($(EVENT2_HAS_OPENSSL),YES)
#include $(SECURITY)/Makefile
#endif

#===========================

include $(TOP)/configure/RULES
-include $(wildcard $(TOP)/cfg/RULES*)
#----------------------------------------
#  ADD RULES AFTER THIS LINE

# Can't use EXPAND as generated headers must appear
# in O.Common, but EXPAND emits rules for O.$(T_A)
../O.Common/pvxs/versionNum.h: ../pvxs/versionNum.h@
	$(MKDIR) $(COMMON_DIR)/pvxs
	$(EXPAND_TOOL) $(EXPANDFLAGS) $($@_EXPANDFLAGS) $< $@

describe$(DEP): describe.h
util$(DEP): $(COMMON_DIR)/$(GENVERSION)

ifndef GENVERSIONHEADER
$(COMMON_DIR)/$(GENVERSION):
	echo "/* genVersionHeader.pl missing */" > $@
endif
