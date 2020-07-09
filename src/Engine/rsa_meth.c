#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <string.h>
#include "methods.h"
#include "engine_id.h"
#include "libsgx.h"


int keystore_rsa_priv_enc(int flen, const unsigned char* from, unsigned char* to, RSA* rsa, int padding) 
{
    fprintf(stderr, "%s(%d, %p, %p, %p, %d)\n", __FUNCTION__, flen, from, to, rsa, padding);

    int (*priv_enc) (int flen, const unsigned char *from,
		unsigned char *to, RSA *rsa, int padding) = NULL;
	
    SGX_KEY* sgx_key = RSA_get_ex_data(rsa, rsa_key_handle);
    if (sgx_key == NULL) {
        fprintf(stderr, "[-] key had no sgx_key! calling default priv_enc function\n");
	    priv_enc = RSA_meth_get_priv_enc(RSA_get_default_method());

        return priv_enc(flen, from, to, rsa, padding);
    }

    int retVal = sgx_private_encrypt(flen, from, to, sgx_key, padding);
        fprintf(stderr, "sgx_key=%p keystore_rsa_priv_enc => returning %d %p len %llu ", sgx_key, retVal, to,
            (unsigned long long) RSA_size(rsa));


    return retVal;
}

int keystore_rsa_priv_dec(int flen, const unsigned char* from, unsigned char* to, RSA* rsa, int padding) 
{
    fprintf(stderr, "%s(%d, %p, %p, %p, %d)", __FUNCTION__, flen, from, to, rsa, padding);
    int (*priv_dec) (int flen, const unsigned char *from,
		unsigned char *to, RSA *rsa, int padding) = NULL;
	
    SGX_KEY* sgx_key = RSA_get_ex_data(rsa, rsa_key_handle);
    if (sgx_key == NULL) {
        fprintf(stderr, "[-] key had no sgx_key! calling default priv_dev function\n");
	    priv_dec = RSA_meth_get_priv_dec(RSA_get_default_method());

        return priv_dec(flen, from, to, rsa, padding);
    }


    int retVal = sgx_private_decrypt(flen, from, to, sgx_key, padding);
        fprintf(stderr, "sgx_key=%p sgx_private_decrypt => returning %d %p len %llu ", sgx_key, retVal, to,
            (unsigned long long) flen);


    return retVal;
}



static RSA_METHOD * get_rsa_method() {
	static RSA_METHOD *ops = NULL;

    if(ops != NULL)
    {
        return ops;

    }

	ops = RSA_meth_dup(RSA_get_default_method());
	if (ops == NULL)
		return NULL;

    RSA_meth_set1_name(ops, ENGINE_ID);
    RSA_meth_set_priv_enc(ops, keystore_rsa_priv_enc);
    RSA_meth_set_priv_dec(ops, keystore_rsa_priv_dec);
    //TODO:
	//RSA_meth_set_finish(ops, pkcs11_rsa_free_method);
 //   RSA_meth_set_flags(ops, RSA_FLAG_EXT_PKEY);

    return ops;
}


EVP_PKEY* sgx_get_evp_key_rsa(SGX_KEY* sgx_key)
{
    RSA* rsa;
    EVP_PKEY* pk;
    rsa = sgx_key_get_rsa(sgx_key);

	if (!rsa)
		return NULL;
	pk = EVP_PKEY_new();
	if (!pk) {
		RSA_free(rsa);
		return NULL;
	}
	EVP_PKEY_set1_RSA(pk, rsa); /* Also increments the rsa ref count */

	RSA_set_method(rsa, get_rsa_method());
	RSA_set_flags(rsa, RSA_FLAG_EXT_PKEY);
    RSA_set_ex_data(rsa, rsa_key_handle, sgx_key);

	RSA_free(rsa); /* Drops our reference to it */
	return pk;

}

int rsa_register(ENGINE* e) {
    if (!ENGINE_set_RSA(e, get_rsa_method())) {
        fprintf(stderr, "Could not set up keystore RSA methods");
        return 0;
    }

    return 1;
}
