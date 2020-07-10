#include <openssl/engine.h>
#include <string.h>
#include <sys/file.h>
#include "engine_id.h"
#include "methods.h"
#include <unistd.h>
#include <sys/types.h>
#include "libsgx.h"
/*
 * ex_data index for keystore's key alias.
 */
int rsa_key_handle;


/*
 * Only initialize the *_key_handle once.
 */
static pthread_once_t key_handle_control = PTHREAD_ONCE_INIT;



static SGX_ENCLAVE* get_enclave_from_engine(ENGINE* engine);

/**
 * Called to initialize RSA's ex_data for the key_id handle. This should
 * only be called when protected by a lock.
 */
static void init_key_handle() {
    rsa_key_handle = RSA_get_ex_new_index(0, ENGINE_ID " rsa", keyhandle_new, keyhandle_dup, keyhandle_free);
}


static EVP_PKEY* keystore_loadkey(ENGINE* e, const char* key_id, UI_METHOD* ui_method,
        void* callback_data) {
#if LOG_NDEBUG
    (void)ui_method;
    (void)callback_data;
#else
    fprintf(stderr, "[%d] keystore_loadkey(%p, \"%s\", %p, %p)\n", getpid(), e, key_id, ui_method, callback_data);
#endif
    //The strncmp function compares not more than n characters (characters that follow a null character 
    // are not compared) from the array pointed to by s1 to the array pointed to by s2."
    if (key_id == NULL || strncmp("sgxkeystore:", key_id, strlen("sgxkeystore:") != 0))
    {
        fprintf(stderr, "Invalid key \n");
        return NULL;
    }
    const char* key_path = key_id + strlen("sgxkeystore:");

    SGX_ENCLAVE* enclave = get_enclave_from_engine(e);

    if (enclave == NULL)
    {
        fprintf(stderr, "[-] Failed to get SGX_ENCLAVE from engine \n");
        return NULL;
    }
    

    SGX_KEY* sgx_key = sgx_load_key(enclave, key_path);

    if (sgx_key == NULL)
    {
        fprintf(stderr, "[-] Failed to load SGX_KEY \n");
        return NULL;
    }
    

    EVP_PKEY* pk = sgx_key->evp_key = sgx_get_evp_key_rsa(sgx_key);
    if(pk == NULL)
    {
        fprintf(stderr, "[-] Failed to load SGX_KEY \n");
        return NULL;
    }

    return pk;
}

static const ENGINE_CMD_DEFN keystore_cmd_defns[] = {
    {0, NULL, NULL, 0}
};

static int sgxkeystore_idx = -1;
static SGX_ENCLAVE* get_enclave_from_engine(ENGINE* engine)
{
    fprintf(stderr, "[%d] get_enclave_from_engine\n", getpid());
    SGX_ENCLAVE* enclave = NULL;
	if (sgxkeystore_idx < 0) {
		sgxkeystore_idx = ENGINE_get_ex_new_index(0, ENGINE_ID, NULL, NULL, 0);
		if (sgxkeystore_idx < 0)
			return NULL;
		enclave = NULL;
	} else {
		enclave = ENGINE_get_ex_data(engine, sgxkeystore_idx);
	}
	if (!enclave) {
        sgx_status_t status = sgx_init_enclave(ENCLAVE_PATH, &enclave);
        fprintf(stderr, "[%d] sgx_init_enclave returned %d\n", getpid(), status);
        if (status == SGX_SUCCESS)
        {
		    ENGINE_set_ex_data(engine, sgxkeystore_idx, enclave);
            return enclave;
        }
        fprintf(stderr, "[%d] sgx_init_enclave failed\n", getpid());
        fprintf(stderr, "%s\n", sgx_get_error_message(status));
        return NULL;
	}
	return enclave;
}

static int engine_init(ENGINE *engine)
{
    fprintf(stderr, "[%d] engine_init\n", getpid());
    SGX_ENCLAVE* enclave = NULL;
    enclave = get_enclave_from_engine(engine);
    if (!enclave)
        return 0;
    
    return 1;
} 

//This function on engine disable
static int engine_finish(ENGINE *engine)
{
    fprintf(stderr, "[%d] engine_finish\n", getpid());
    //Unload all keys from the enclave
    SGX_ENCLAVE* enclave = NULL;
    enclave = get_enclave_from_engine(engine);
    if (!enclave)
        return 0;
    //TODO: Unload all keys from memory
    return 1;
}

//called on engine destruction
static int engine_destroy(ENGINE *engine)
{
    fprintf(stderr, "[%d] engine_destroy\n", getpid());
    SGX_ENCLAVE* enclave = NULL;
    enclave = get_enclave_from_engine(engine);
    if (!enclave)
        return 0;
    sgx_status_t status = sgx_destroy_enclave_wrapper(enclave);
	ENGINE_set_ex_data(engine, sgxkeystore_idx, NULL);
    if (status != SGX_SUCCESS)
    {
        fprintf(stderr, "sgx_destroy_enclave_wrapper failed\n");
        fprintf(stderr, "%s\n", sgx_get_error_message(status));
        return 0;
    }
    printf("Destroyed enclave\n");
    
    return 1;
}

static int keystore_engine_setup(ENGINE* e) {
    fprintf(stderr, "keystore_engine_setup\n");



    if (!ENGINE_set_id(e, ENGINE_ID)
            || !ENGINE_set_name(e, ENGINE_NAME)
            || !ENGINE_set_init_function(e, engine_init)
            || !ENGINE_set_finish_function(e, engine_finish)
            || !ENGINE_set_destroy_function(e, engine_destroy)
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


    /*if (!rsa_register(e)) {
        fprintf(stderr, "RSA registration failed");
        return 0;
    }*/

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