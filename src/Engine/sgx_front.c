#include "libsgx.h"
#include <unistd.h>
typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;


static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
};

struct SGX_Enclave_st {
#if OPENSSL_VERSION_NUMBER >= 0x10100004L && !defined(LIBRESSL_VERSION_NUMBER)
	CRYPTO_RWLOCK *rwlock;
#else
	int rwlock;
#endif
	const char* enclave_binary_path;
	sgx_enclave_id_t enclave_id;
    pid_t pid;

};


sgx_status_t sgx_init_enclave(const char* enclave_file, SGX_ENCLAVE** enclave_out)
{
    if (enclave_out == NULL)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    *enclave_out = NULL;
    SGX_ENCLAVE* enclave = (SGX_ENCLAVE*)malloc(sizeof(SGX_ENCLAVE));
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    sgx_enclave_id_t enclave_id = 0;
 

    /* Call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(enclave_file, SGX_DEBUG_FLAG, NULL, NULL, &enclave_id, NULL);
    if (ret != SGX_SUCCESS) {
        free(enclave);
        return ret;
    }

#if OPENSSL_VERSION_NUMBER >= 0x10100004L && !defined(LIBRESSL_VERSION_NUMBER)
    enclave->rwlock = CRYPTO_THREAD_lock_new();    
#else
	enclave->rwlock  = CRYPTO_get_dynlock_create_callback() ?
		CRYPTO_get_new_dynlockid() : 0;
#endif

    enclave->enclave_binary_path = enclave_file;
    enclave->enclave_id = enclave_id;
    enclave->pid = getpid();
    *enclave_out = enclave;
    return SGX_SUCCESS;
}


const char* sgx_get_error_message(sgx_status_t status)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(status == sgx_errlist[idx].err) {
            return sgx_errlist[idx].msg;
        }
    }
    return NULL;

}

sgx_status_t sgx_destroy_enclave_wrapper(SGX_ENCLAVE* enclave)
{
    sgx_enclave_id_t id = enclave->enclave_id;
    printf("Destroying enclave %d\n", id);
   // free(enclave);
    return sgx_destroy_enclave(id);
}