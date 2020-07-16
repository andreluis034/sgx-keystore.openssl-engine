#
# Copyright (C) 2011-2017 Intel Corporation. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#   * Neither the name of Intel Corporation nor the names of its
#     contributors may be used to endorse or promote products derived
#     from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#



######## SGX SDK Settings ########
SGX_MODE ?= SIM
SGX_ARCH ?= x64
UNTRUSTED_DIR=UtilityApp

ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
	SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
	$(error x86 build is not supported, only x64!!)
else
	SGX_COMMON_CFLAGS := -m64 -Wall
	ifeq ($(LINUX_SGX_BUILD), 1)
		include ../../../../../buildenv.mk
		SGX_LIBRARY_PATH := $(BUILD_DIR)
		SGX_EDGER8R := $(BUILD_DIR)/sgx_edger8r
		SGX_SDK_INC := $(COMMON_DIR)/inc
		SGX_SHARED_LIB_FLAG := -Wl,-rpath,${SGX_LIBRARY_PATH}
	else
		SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
		SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
		SGX_SDK_INC := $(SGX_SDK)/include
	endif
endif

ifeq ($(DEBUG), 1)
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif

OPENSSL_LIBRARY_PATH := $(PACKAGE_LIB)
ifeq ($(DEBUG), 1)
        SGX_COMMON_CFLAGS += -O0 -g
		SgxSSL_Link_Libraries := sgx_usgxssld
else
        SGX_COMMON_CFLAGS += -O2 -D_FORTIFY_SOURCE=2
		SgxSSL_Link_Libraries := sgx_usgxssl
endif


######## App Settings ########


#App_C_Files := $(UNTRUSTED_DIR)/eng_front.c $(UNTRUSTED_DIR)/eng_back.c $(UNTRUSTED_DIR)/sgx_rsa.c $(UNTRUSTED_DIR)/sgx_front.c $(UNTRUSTED_DIR)/sgx_atfork.c $(UNTRUSTED_DIR)/eng_err.c
App_C_Files := $(UNTRUSTED_DIR)/UtilityApp.c
App_C_Objects := $(App_C_Files:.c=.o)

App_Include_Paths := -I$(UNTRUSTED_DIR) -I$(SGX_SDK_INC)

App_C_Flags := $(SGX_COMMON_CFLAGS) -fPIC -fstack-protector -Wformat -Wformat-security -Wno-attributes $(App_Include_Paths)

ifneq ($(SGX_MODE), HW)
	Urts_Library_Name := sgx_urts_sim
	UaeService_Library_Name := sgx_uae_service_sim
else
	Urts_Library_Name := sgx_urts
	UaeService_Library_Name := sgx_uae_service
endif


Security_Link_Flags := -Wl,-z,noexecstack -Wl,-z,relro -Wl,-z,now 

App_Link_Flags := $(SGX_COMMON_CFLAGS) $(Security_Link_Flags) $(SGX_SHARED_LIB_FLAG) -L$(SGX_LIBRARY_PATH) -l$(Urts_Library_Name) -l$(UaeService_Library_Name) -L$(OPENSSL_LIBRARY_PATH) -l$(SgxSSL_Link_Libraries) -lpthread -lcrypto


.PHONY: all test

all: utility

test: all
	@$(CURDIR)/Engine
	@echo "RUN  =>  Engine [$(SGX_MODE)|$(SGX_ARCH), OK]"

######## App Objects ########

$(UNTRUSTED_DIR)/Engine_u.c: $(SGX_EDGER8R) Enclave/Engine.edl
	@cd $(UNTRUSTED_DIR) && $(SGX_EDGER8R) --untrusted ../Enclave/Engine.edl --search-path $(PACKAGE_INC) --search-path $(SGX_SDK_INC)
	@echo "GEN  =>  $@"

$(UNTRUSTED_DIR)/Engine_u.o: $(UNTRUSTED_DIR)/Engine_u.c
	$(VCC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

$(UNTRUSTED_DIR)/%.o: $(UNTRUSTED_DIR)/%.c
	$(VCC) $(App_C_Flags) -c $< -o $@
	@echo "CC  <=  $<"

utility: $(UNTRUSTED_DIR)/Engine_u.o $(App_C_Objects)
	echo $(VCC) $^ -o $@ $(App_Link_Flags)
	$(VCC) $^ -o $@ $(App_Link_Flags)
	@echo "LINK =>  $@"


.PHONY: clean

clean:
	@rm -f utility  $(App_C_Objects) $(UNTRUSTED_DIR)/Engine_u.* 
	
