#pragma once
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include "sgx_urts.h"

typedef struct SGX_Enclave_st SGX_ENCLAVE;

/** SGX key object (public or private) */
typedef struct SGX_key_st {
    unsigned int keyId;
	const char label[BUFSIZ];
	unsigned char isPrivate;	/**< private key present? */
	EVP_PKEY *evp_key;		/**< initially NULL, need to call PKCS11_load_key */
	SGX_ENCLAVE* enclave;
} SGX_KEY;


const char* sgx_get_error_message(sgx_status_t status);

sgx_status_t sgx_init_enclave(const char* enclave_file, SGX_ENCLAVE** enclave);

sgx_status_t sgx_destroy_enclave_wrapper(SGX_ENCLAVE* enclave);


SGX_KEY* sgx_load_key(SGX_ENCLAVE* enclave, const char* key_path);



//check pkcs11_get_evp_key_rsa on libp11
RSA* sgx_key_get_rsa(SGX_KEY* sgx_key);
