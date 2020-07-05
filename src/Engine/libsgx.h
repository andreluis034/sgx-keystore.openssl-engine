#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include "sgx_urts.h"


/** SGX key object (public or private) */
typedef struct SGX_key_st {
    unsigned int keyId;
	const char *label;
	unsigned char isPrivate;	/**< private key present? */
	EVP_PKEY *evp_key;		/**< initially NULL, need to call PKCS11_load_key */
	void *_private;
    pid_t creatingPid;
	sgx_enclave_id_t enclade_id;
} SGX_KEY;



const char* sgx_get_error_message(sgx_status_t status);

sgx_status_t sgx_init_enclave(const char* enclave_file, sgx_enclave_id_t* encalve_id_out);
