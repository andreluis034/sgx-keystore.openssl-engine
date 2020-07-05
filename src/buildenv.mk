export SGXSSL := /home/andre/git/intel-sgx-ssl/Linux
export PACKAGE_LIB := $(SGXSSL)/package/lib64/
export PACKAGE_INC := $(SGXSSL)/package/include/
export TRUSTED_LIB := libsgx_tsgxssl.a
export UNTRUSTED_LIB := libsgx_usgxssl.a
export SGX_SDK ?= /opt/intel/sgxsdk/
export VCC := @$(CC)
export VCXX := @$(CXX)

ifeq ($(DEBUG), 1)
	OBJDIR := debug
	OPENSSL_LIB := libsgx_tsgxssl_cryptod.a
	TRUSTED_LIB := libsgx_tsgxssld.a
	UNTRUSTED_LIB := libsgx_usgxssld.a
else
	OBJDIR := release
	OPENSSL_LIB := libsgx_tsgxssl_crypto.a
	TRUSTED_LIB := libsgx_tsgxssl.a
	UNTRUSTED_LIB := libsgx_usgxssl.a
endif

ifeq ($(VERBOSE),1)
      VCC=$(CC)
      VCXX=$(CXX)
else
      VCC=@$(CC)
      VCXX=@$(CXX)
endif
