#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <string.h>
#include "methods.h"
#include "engine_id.h"
#include "libsgx.h"


int keystore_rsa_priv_enc(int flen, const unsigned char* from, unsigned char* to, RSA* rsa,
        int padding) {
    fprintf(stderr, "%s(%d, %p, %p, %p, %d)\n", __FUNCTION__, flen, from, to, rsa, padding);

	
    SGX_KEY* sgx_key = RSA_get_ex_data(rsa, rsa_key_handle);
    if (sgx_key == NULL) {
        fprintf(stderr, "[-] key had no sgx_key!");
        return 0;
    }

    int retVal = sgx_private_encrypt(flen, from, to, sgx_key, padding);
        fprintf(stderr, "sgx_key=%p keystore_rsa_priv_enc => returning %d %p len %llu ", sgx_key, retVal, to,
            (unsigned long long) RSA_size(rsa));


    return retVal;
}

int keystore_rsa_priv_dec(int flen, const unsigned char* from, unsigned char* to, RSA* rsa,
        int padding) {
     fprintf(stderr, "keystore_rsa_priv_dec(%d, %p, %p, %p, %d)", flen, from, to, rsa, padding);

    uint8_t* key_id = (uint8_t*)RSA_get_ex_data(rsa, rsa_key_handle); //TODO -> SGX_KEYDATA
    if (key_id == NULL) {
         fprintf(stderr, "key had no key_id!");
        return 0;
    }

    /*sp<IServiceManager> sm = defaultServiceManager();
    sp<IBinder> binder = sm->getService(String16("android.security.keystore"));
    sp<IKeystoreService> service = interface_cast<IKeystoreService>(binder);

    if (service == NULL) {
         fprintf(stderr, "could not contact keystore");
        return 0;
    }*/

    int num = RSA_size(rsa);

    uint8_t* reply = NULL;
    size_t replyLen;
    int32_t ret = -1;/* service->sign(String16(reinterpret_cast<const char*>(key_id)), from,
            flen, &reply, &replyLen);*/ //SIGN 
    if (ret < 0) {
        fprintf(stderr, "There was an error during rsa_mod_exp: could not connect");
        return 0;
    } else if (ret != 0) {
        fprintf(stderr, "Error during sign from keystore: %d", ret);
        return 0;
    } else if (replyLen <= 0) {
        fprintf(stderr, "No valid signature returned");
        return 0;
    }

    /* Trim off the top zero if it's there */
    uint8_t* alignedReply;
    if (*reply == 0x00) {
        alignedReply = reply + 1;
        replyLen--;
    } else {
        alignedReply = reply;
    }

    unsigned long long outSize;
    switch (padding) {
    case RSA_PKCS1_PADDING:
        outSize = RSA_padding_check_PKCS1_type_2(to, num, alignedReply, replyLen, num);
        break;
    case RSA_X931_PADDING:
        outSize = RSA_padding_check_X931(to, num, alignedReply, replyLen, num);
        break;
    case RSA_NO_PADDING:
        outSize = RSA_padding_check_none(to, num, alignedReply, replyLen, num);
        break;
    default:
        fprintf(stderr, "Unknown padding type: %d", padding);
        outSize = -1;
        break;
    }

    free(reply);

    fprintf(stderr, "rsa=%p keystore_rsa_priv_dec => returning %p len %llu", rsa, to, outSize);
    return outSize;
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
