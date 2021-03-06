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
UNTRUSTED_DIR=Engine


######## App Settings ########


#App_C_Files := $(UNTRUSTED_DIR)/eng_front.c $(UNTRUSTED_DIR)/eng_back.c $(UNTRUSTED_DIR)/sgx_rsa.c $(UNTRUSTED_DIR)/sgx_front.c $(UNTRUSTED_DIR)/sgx_atfork.c $(UNTRUSTED_DIR)/eng_err.c
App_C_Files := $(UNTRUSTED_DIR)/keyhandle.c $(UNTRUSTED_DIR)/engine.c $(UNTRUSTED_DIR)/rsa_meth.c $(UNTRUSTED_DIR)/sgx_front.c
App_C_Objects := $(App_C_Files:.c=.o)

App_Include_Paths := -I$(UNTRUSTED_DIR) -IServer/Include

App_C_Flags := -fPIC -fstack-protector -Wformat -Wformat-security -Wno-attributes $(App_Include_Paths)

ifneq ($(SGX_MODE), HW)
	Urts_Library_Name := sgx_urts_sim
	UaeService_Library_Name := sgx_uae_service_sim
else
	Urts_Library_Name := sgx_urts
	UaeService_Library_Name := sgx_uae_service
endif


Security_Link_Flags := -Wl,-z,noexecstack -Wl,-z,relro -Wl,-z,now 

App_Link_Flags :=  $(Security_Link_Flags) -lpthread -lcrypto


.PHONY: all test

all: Engine.so

test: all
	@$(CURDIR)/Engine
	@echo "RUN  =>  Engine [$(SGX_MODE)|$(SGX_ARCH), OK]"

######## App Objects ########

$(UNTRUSTED_DIR)/%.o: $(UNTRUSTED_DIR)/%.c
	$(VCC) $(App_C_Flags) -c $< -o $@
	@echo "CC  <=  $<"

Engine.so: $(App_C_Objects)
	echo $(VCC) $^ -shared -o $@ $(App_Link_Flags)
	$(VCC) $^ -shared -o $@ $(App_Link_Flags)
	@echo "LINK =>  $@"


.PHONY: clean

clean:
	@rm -f Engine.so  $(App_C_Objects)
	
