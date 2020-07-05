#include <openssl/engine.h>
#include "engine_id.h"
#include "methods.h"
#include <string.h>
/*
 * ex_data index for keystore's key alias.
 */
int rsa_key_handle;


/*
 * Only initialize the *_key_handle once.
 */
static pthread_once_t key_handle_control = PTHREAD_ONCE_INIT;




/**
 * Called to initialize RSA's ex_data for the key_id handle. This should
 * only be called when protected by a lock.
 */
static void init_key_handle() {
    rsa_key_handle = RSA_get_ex_new_index(0, NULL, keyhandle_new, keyhandle_dup, keyhandle_free);
}


static EVP_PKEY* keystore_loadkey(ENGINE* e, const char* key_id, UI_METHOD* ui_method,
        void* callback_data) {
#if LOG_NDEBUG
    (void)ui_method;
    (void)callback_data;
#else
    fprintf(stderr, "keystore_loadkey(%p, \"%s\", %p, %p)", e, key_id, ui_method, callback_data);
#endif

   /* sp<IServiceManager> sm = defaultServiceManager();
    sp<IBinder> binder = sm->getService(String16("android.security.keystore"));
    sp<IKeystoreService> service = interface_cast<IKeystoreService>(binder);

    if (service == NULL) {
        fprintf(stderr, "could not contact keystore");
        return 0;
    }*/

    uint8_t *pubkey = NULL;
    size_t pubkeyLen;
    int32_t ret = -1; //service->get_pubkey(String16(key_id), &pubkey, &pubkeyLen);
    if (ret < 0) {
        fprintf(stderr, "could not contact keystore");
        free(pubkey);
        return NULL;
    } else if (ret != 0) {
        fprintf(stderr, "keystore reports error: %d", ret);
        free(pubkey);
        return NULL;
    }

    const unsigned char* tmp = (const unsigned char*)pubkey;
    EVP_PKEY* pkey = d2i_PUBKEY(NULL, &tmp, pubkeyLen);
    free(pubkey);
    if (pkey == NULL) {
        fprintf(stderr, "Cannot convert pubkey");
        return NULL;
    }

    switch (EVP_PKEY_base_id(pkey)) {
    case EVP_PKEY_RSA: {
        rsa_pkey_setup(e, pkey, key_id);
        break;
    }
    default:
        fprintf(stderr, "Unsupported key type %d", EVP_PKEY_base_id(pkey));
        return NULL;
    }

    return pkey;
}

static const ENGINE_CMD_DEFN keystore_cmd_defns[] = {
    {0, NULL, NULL, 0}
};






static int keystore_engine_setup(ENGINE* e) {
    fprintf(stderr, "keystore_engine_setup\n");



    if (!ENGINE_set_id(e, ENGINE_ID)
            || !ENGINE_set_name(e, ENGINE_NAME)
            || !ENGINE_set_load_privkey_function(e, keystore_loadkey)
            || !ENGINE_set_load_pubkey_function(e, keystore_loadkey)
            || !ENGINE_set_flags(e, 0)
            || !ENGINE_set_cmd_defns(e, keystore_cmd_defns)) {
        fprintf(stderr, "Could not set up keystore engine");
        return 0;
    }

    /* We need a handle in the keys types as well for keygen if it's not already initialized. */
    pthread_once(&key_handle_control, init_key_handle);
    if (rsa_key_handle < 0) {
        fprintf(stderr, "Could not set up ex_data index");
        return 0;
    }


    if (!rsa_register(e)) {
        fprintf(stderr, "RSA registration failed");
        return 0;
    }

    return 1;
}

static int keystore_bind_fn(ENGINE *e, const char *id) {

    fprintf(stderr, "keystore_bind_fn\n");
    if (!id) {
        return 0;
    }

    if (strcmp(id, ENGINE_ID)) {
        return 0;
    }

    if (!keystore_engine_setup(e)) {
        return 0;
    }

    return 1;
}

IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(keystore_bind_fn)