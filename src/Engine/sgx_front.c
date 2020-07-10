#include "libsgx.h"
#include <unistd.h>
#include <sys/stat.h>
#include <openssl/pem.h>
#include "Engine_u.h"
#include "methods.h"
#include "engine_id.h"
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
    printf("Created enclave with id %ld\n", enclave_id);
    
    teste_ecall(enclave_id);
    enclave_init_rsa_lock(enclave_id);

    enclave->rwlock = CRYPTO_THREAD_lock_new();    
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
    printf("Destroying enclave %ld\n", id);
    CRYPTO_THREAD_lock_free(enclave->rwlock);
    free(enclave);
    return sgx_destroy_enclave(id);
}

RSA* sgx_key_get_rsa(SGX_KEY* sgx_key)
{
    int length;
    char *rsa_n, *rsa_e;
    sgx_status_t status;
    BIGNUM *bn_n, *bn_e;
    RSA* rsa;
    status = enclave_rsa_get_n(sgx_key->enclave->enclave_id, &length, sgx_key->keyId, NULL, 0);
    if (status != SGX_SUCCESS || length == 0)
        return NULL;

    rsa_n = OPENSSL_zalloc(length + 1);    
    status = enclave_rsa_get_n(sgx_key->enclave->enclave_id, &length, sgx_key->keyId, rsa_n, length + 1);
    if (status != SGX_SUCCESS || length == 0)
    {
        OPENSSL_free(rsa_n);
        return NULL;
    }

    status = enclave_rsa_get_e(sgx_key->enclave->enclave_id, &length, sgx_key->keyId, NULL, 0);
    if (status != SGX_SUCCESS || length == 0)
    {
        OPENSSL_free(rsa_n);
        return NULL;
    }

    rsa_e = OPENSSL_zalloc(length + 1);    
    status = enclave_rsa_get_e(sgx_key->enclave->enclave_id, &length, sgx_key->keyId, rsa_e, length + 1);
    if (status != SGX_SUCCESS || length == 0)
    {
        OPENSSL_free(rsa_n);
        OPENSSL_free(rsa_e);
        return NULL;
    }
    if ((bn_n = BN_new()) == NULL || BN_hex2bn(&bn_n, rsa_n) == 0)
    {
        OPENSSL_free(rsa_n);
        OPENSSL_free(rsa_e);
        return NULL;
    }
    if ((bn_e = BN_new()) == NULL || BN_hex2bn(&bn_e, rsa_e) == 0)
    {
        BN_free(bn_n);
        OPENSSL_free(rsa_n);
        OPENSSL_free(rsa_e);
        return NULL;
    }
    OPENSSL_free(rsa_n);
    OPENSSL_free(rsa_e);
	rsa = RSA_new();
    if(rsa == NULL)
    {
        BN_free(bn_n);
        BN_free(bn_e);
        return NULL;
    }
    RSA_set0_key(rsa, bn_n, bn_e, NULL);

    return rsa;

}

int sgx_handle_forked(SGX_KEY* sgx_key)
{
    sgx_status_t status;
    SGX_ENCLAVE* new_enclave;
    SGX_KEY* new_key;
    if (sgx_key->pid == getpid())
        return 1;

    fprintf(stderr, "[%d] received key from different pid(%d)\n", getpid(), sgx_key->pid);
    
    if (sgx_key->enclave->pid != getpid())
    {
        fprintf(stderr, "[%d] enclave not loaded in current process\n", getpid());
        sleep(5);
        status = sgx_init_enclave(ENCLAVE_PATH, &new_enclave);
        if (status != SGX_SUCCESS)
        {
            fprintf(stderr, "[%d] Failed to load enclave: 0x%x\n", getpid(), status);
            return 0;
        }
        //Keep using the data in the old enclave struct
        CRYPTO_THREAD_lock_free(new_enclave->rwlock);
        sgx_key->enclave->pid = new_enclave->pid;
        sgx_key->enclave->enclave_id = new_enclave->enclave_id;
        sgx_key->enclave->enclave_binary_path = new_enclave->enclave_binary_path;
        free(new_enclave);        
    }
    new_key = sgx_load_key(sgx_key->enclave, sgx_key->label);
    if(new_key == NULL)
        return 0;

    sgx_key->keyId = new_key->keyId;
    sgx_key->pid = new_key->pid;

    OPENSSL_free(new_key);

    return 1;
}

//currently only support RSA
int sgx_get_key_size(SGX_KEY* key)
{
    EVP_PKEY *evp_key = key->evp_key;
    const RSA* rsa;
    if(evp_key == NULL)
        return 0;
    rsa = EVP_PKEY_get0_RSA(evp_key);
    if (rsa == NULL)
        return 0;

    return RSA_size(rsa);    
}

int sgx_private_decrypt(int flen, const unsigned char *from, unsigned char *to, SGX_KEY* key, int padding)
{
    sgx_status_t status;
    int ret;
  
    fprintf(stderr, "[%d] %s(%d, %p, %p, (id: %d, pid: %d), %d)\n",getpid(), __FUNCTION__, flen, from, to, key->keyId, key->enclave->pid, padding);
    if (!sgx_handle_forked(key))
        return -1;
    

    if (key == NULL)
        return -1;
    
    int tlen = flen;
    if(tlen == 0)
        return -1;


    status = enclave_private_decrypt(key->enclave->enclave_id, &ret, flen, from, tlen, to, key->keyId, padding);
    if(status != SGX_SUCCESS)
    {
        fprintf(stderr, "enclave_private_decrypt ecall status: 0x%x\n", status);
        return -1;
    }
    return ret;
}

int sgx_private_encrypt(int flen, const unsigned char *from, unsigned char *to, SGX_KEY* key, int padding)
{
    sgx_status_t status;
    int ret;

    fprintf(stderr, "[%d] %s(%d, %p, %p, (id: %d, pid: %d), %d)\n",getpid(), __FUNCTION__, flen, from, to, key->keyId, key->enclave->pid, padding);
    if (!sgx_handle_forked(key))
        return -1;

    if (key == NULL)
        return -1;
    
    int tlen = sgx_get_key_size(key);   
    if(tlen == 0)
        return -1;

    fprintf(stderr, "[%d] key size: %d\n", getpid(), tlen);
    status = enclave_private_encrypt(key->enclave->enclave_id, &ret, flen, from, tlen, to, key->keyId, padding);
    if(status != SGX_SUCCESS)
    {
        fprintf(stderr, "enclave_private_encrypt ecall status: 0x%x\n", status);
        return -1;
    }
    return ret;
}


void sgx_unload_key(SGX_KEY* key)
{
    if(key == NULL)
        return;
    sgx_status_t status = enclave_unload_key_from_enclave(key->enclave->enclave_id, key->keyId);
    if(status != SGX_SUCCESS)
    {
        printf("[-] Failed to unload SGX_KEY %x\n", status);
    }
    free(key);

}

SGX_KEY* sgx_load_key(SGX_ENCLAVE* enclave, const char* key_path)
{
    SGX_KEY* sgx_key = (SGX_KEY*)OPENSSL_zalloc(sizeof(SGX_KEY));
    if(sgx_key == NULL)
        return NULL;
    FILE* fd  = fopen(key_path, "rb");
    if (fd == NULL)
    {
        fprintf(stderr, "[%d] Failed to open file from disk\n", getpid());
        OPENSSL_free(sgx_key);
        return NULL;
    }

    struct stat st;
    stat(key_path, &st);
    size_t size = st.st_size;

    unsigned char* buffer = malloc(size);
    size_t read = fread(buffer, 1, size, fd);

   // fclose(fd);
    if(read <= 0)
    {
        OPENSSL_free(sgx_key);
        return NULL;
    }

    int key_slot = -1;
    
    sgx_status_t status = enclave_rsa_load_key(enclave->enclave_id, &key_slot, buffer, read, key_path);
    if (status != SGX_SUCCESS)
    {
        OPENSSL_free(sgx_key);
        return NULL;
    }
    if (key_slot < 0)
    {
        fprintf(stderr, "[%d] Failed to load key in SGX, error code: %d\n", getpid(), key_slot);
        OPENSSL_free(sgx_key);
        return NULL;
    }
    fprintf(stderr, "[%d] Loaded key into slot %d\n", getpid(), key_slot);
    
    sgx_key->enclave = enclave;
    sgx_key->keyId = key_slot;
    sgx_key->pid = enclave->pid;
    OPENSSL_strlcpy((char*)sgx_key->label, key_path, BUFSIZ);
    
    
    //teste_ecall(enclave->enclave_id);
    //printf("%s\n", buffer);
    //PEM_read_bio_PrivateKey(bio, &pk, NULL, NULL);

  /*  sgx_key = OPENSSL_zalloc(sizeof(SGX_KEY));
    OPENSSL_strlcpy((char*)sgx_key->label, key_path, BUFSIZ);
    sgx_key->enclave = enclave;*/

    return sgx_key;

}

