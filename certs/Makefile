TOP=..

include $(TOP)/configure/CONFIG
# cfg/ sometimes isn't correctly included due to a Base bug
# so we do here (maybe again) as workaround
-include $(wildcard $(TOP)/cfg/CONFIG*)
#----------------------------------------
#  ADD MACRO DEFINITIONS AFTER THIS LINE
#=============================

ifeq ($(EVENT2_HAS_OPENSSL),YES)
USR_CPPFLAGS += -DPVXS_ENABLE_OPENSSL -I$(TOP)/bundle/CLI11/include
AUTHN = $(TOP)/certs/authn
SRC_DIRS += $(TOP)/src
SRC_DIRS += $(TOP)/ioc
SRCS += p12filefactory.cpp
SRCS += certfilefactory.cpp
SRCS += certfactory.cpp


PROD_LIBS = pvxs Com

# access to API and private headers
USR_CPPFLAGS += -I$(TOP)/src/pvxs
USR_CPPFLAGS += -I$(TOP)/src
USR_CPPFLAGS += -I$(TOP)/ioc

ifeq ($(PVXS_ENABLE_PVACMS),YES)
USR_CPPFLAGS += -DPVXS_ENABLE_PVACMS
PROD += pvacms
pvacms_SRCS += pvacms.cpp
pvacms_SRCS += configcms.cpp
pvacms_SRCS += certstatus.cpp
pvacms_SRCS += certstatusfactory.cpp
pvacms_SRCS += credentials.cpp
pvacms_SRCS += securityclient.cpp

pvacms_LIBS += $(EPICS_BASE_IOC_LIBS)
pvacms_SYS_LIBS += sqlite3 ssl crypto
endif

#PROD += ocsppva
#pvaocsp_SRCS += ocsppva.cpp
#pvaocsp_SRCS += configocsp.cpp

include $(AUTHN)/Makefile

endif # EVENT2_HAS_OPENSSL

#===========================

include $(TOP)/configure/RULES
-include $(wildcard $(TOP)/cfg/RULES*)
#----------------------------------------
#  ADD RULES AFTER THIS LINE
