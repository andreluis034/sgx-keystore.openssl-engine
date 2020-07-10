#pragma once
#include "sgx_urts.h"




const char* sgx_get_error_message(sgx_status_t status);

sgx_status_t sgx_init_enclave(const char* enclave_path);

sgx_status_t sgx_destroy_enclave_wrapper();

int sgx_private_encrypt(int flen, const unsigned char *from, int tlen, unsigned char *to, int keyId, int padding);
int sgx_private_decrypt(int flen, const unsigned char *from, int tlen, unsigned char *to, int keyId, int padding);


char* sgx_rsa_get_n(int key_id);
char* sgx_rsa_get_e(int key_id);

void sgx_unload_key(int keyId);
int sgx_load_key(const char* key_path);



//check pkcs11_get_evp_key_rsa on libp11
//RSA* sgx_key_get_rsa(SGX_KEY* sgx_key);
