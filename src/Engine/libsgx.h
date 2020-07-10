#pragma once
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/evp.h>

typedef struct SGX_Enclave_st SGX_ENCLAVE;

/** SGX key object (public or private) */
typedef struct SGX_key_st {
    unsigned int keyId;
	const char* label;
	EVP_PKEY *evp_key;		/**< initially NULL, need to call PKCS11_load_key */
	SGX_ENCLAVE* enclave;
} SGX_KEY;



int sgx_init_enclave(const char* enclave_file, SGX_ENCLAVE** enclave);


int sgx_private_encrypt(int flen, const unsigned char *from, unsigned char *to, SGX_KEY* key, int padding);
int sgx_private_decrypt(int flen, const unsigned char *from, unsigned char *to, SGX_KEY* key, int padding);


void sgx_unload_key(SGX_KEY* key);
SGX_KEY* sgx_load_key(SGX_ENCLAVE* enclave, const char* key_path);

char* sgx_rsa_get_n(int key_id);


//check pkcs11_get_evp_key_rsa on libp11
RSA* sgx_key_get_rsa(SGX_KEY* sgx_key);
