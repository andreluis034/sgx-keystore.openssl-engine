#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <string.h>
#include "methods.h"
#include "engine_id.h"



int keystore_rsa_priv_enc(int flen, const unsigned char* from, unsigned char* to, RSA* rsa,
        int padding) {
    fprintf(stderr, "keystore_rsa_priv_enc(%d, %p, %p, %p, %d)", flen, from, to, rsa, padding);

    int num = RSA_size(rsa);
    uint8_t* padded = OPENSSL_malloc(sizeof(uint8_t) * num);
    if (padded == NULL) {
        fprintf(stderr, "could not allocate padded signature");
        return 0;
    }

    switch (padding) {
    case RSA_PKCS1_PADDING:
        if (!RSA_padding_add_PKCS1_type_1(padded, num, from, flen)) {
            return 0;
        }
        break;
    case RSA_X931_PADDING:
        if (!RSA_padding_add_X931(padded, num, from, flen)) {
            return 0;
        }
        break;
    case RSA_NO_PADDING:
        if (!RSA_padding_add_none(padded, num, from, flen)) {
            return 0;
        }
        break;
    default:
        fprintf(stderr, "Unknown padding type: %d", padding);
        return 0;
    }

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

    uint8_t* reply = NULL;
    size_t replyLen;
    int32_t ret = -1;/*= service->sign(String16(reinterpret_cast<const char*>(key_id)), padded.get(),
            num, &reply, &replyLen);*/ //TODO
    if (ret < 0) {
        fprintf(stderr, "There was an error during signing: could not connect");
        free(reply);
        return 0;
    } else if (ret != 0) {
        fprintf(stderr, "Error during signing from keystore: %d", ret);
        free(reply);
        return 0;
    } else if (replyLen <= 0) {
        fprintf(stderr, "No valid signature returned");
        return 0;
    }

    memcpy(to, reply, replyLen);
    free(reply);
    OPENSSL_free(padded);
    fprintf(stderr, "rsa=%p keystore_rsa_priv_enc => returning %p len %llu", rsa, to,
            (unsigned long long) replyLen);
    return replyLen;
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
    RSA_meth_set_flags(ops, RSA_FLAG_EXT_PKEY | RSA_FLAG_NO_BLINDING);

    return ops;
}

int rsa_pkey_setup(ENGINE *e, EVP_PKEY *pkey, const char *key_id) {
    RSA* rsa = EVP_PKEY_get1_RSA(pkey);
    if (!RSA_set_ex_data(rsa, rsa_key_handle, (void*)strdup(key_id))) { //TODO create a SGX_KEY struct
        fprintf(stderr, "Could not set ex_data for loaded RSA key");
        return 0;
    }

    RSA_set_method(rsa, get_rsa_method());
    RSA_blinding_off(rsa);

    /*
     * "RSA_set_ENGINE()" should probably be an OpenSSL API. Since it isn't,
     * and EVP_PKEY_free() calls ENGINE_finish(), we need to call ENGINE_init()
     * here.
     */
    //ENGINE_init(e);
    RSA_set_flags(rsa, RSA_FLAG_EXT_PKEY);
    //rsa->engine = e;

    return 1;
}

int rsa_register(ENGINE* e) {
    if (!ENGINE_set_RSA(e, get_rsa_method())) {
        fprintf(stderr, "Could not set up keystore RSA methods");
        return 0;
    }

    return 1;
}
