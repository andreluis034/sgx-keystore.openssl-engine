#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "libsgx.h"
#include "Engine_u.h"

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


sgx_enclave_id_t enclave_id = 0;

sgx_status_t sgx_init_enclave(const char* enclave_path)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
 

    /* Call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(enclave_path, SGX_DEBUG_FLAG, NULL, NULL, &enclave_id, NULL);
    if (ret != SGX_SUCCESS) {
        return ret;
    }
    printf("Created enclave with id %ld\n", enclave_id);
    
    teste_ecall(enclave_id);
    enclave_init_rsa_lock(enclave_id);

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

void print_hex(const unsigned char* buffer, int n)
{
    for (int i = 0; i < n; i++)
    {
        printf("%02X", buffer[i]);
    }
}

int sgx_private_encrypt(int flen, const unsigned char *from, int tlen, unsigned char *to, int key_id, int padding)
{
    sgx_status_t status;
    int ret;
    // CRYPTO_THREAD_write_lock(key->enclave->rwlock);

    //fprintf(stderr, "[%d] %s(%d, %p, %p, (id: %d, pid: %d), %d)\n",getpid(), __FUNCTION__, flen, from, to, key->keyId, key->enclave->pid, padding);
    printf("%d, ", flen);
    print_hex(from, flen);
    printf(", %d, %d, %d\n", tlen, key_id, padding);
    if(tlen == 0)
    {
        // CRYPTO_THREAD_unlock(key->enclave->rwlock);
        return -1;
    }        

   // fprintf(stderr, "[%d] key size: %d\n", getpid(), tlen);
    status = enclave_private_encrypt(enclave_id, &ret, flen, from, tlen, to, key_id, padding);
    if(status != SGX_SUCCESS)
    {
        fprintf(stderr, "enclave_private_encrypt ecall status: 0x%x\n", status);
        // CRYPTO_THREAD_unlock(key->enclave->rwlock);
        return -1;
    }
    fprintf(stderr, "enclave_private_encrypt ret: %d\n", ret);
    // CRYPTO_THREAD_unlock(key->enclave->rwlock);
    return ret;
}



int sgx_load_key(const char* key_path)
{
    FILE* fd  = fopen(key_path, "rb");
    if (fd == NULL)
    {
        fprintf(stderr, "[%d] Failed to open file from disk\n", getpid());
        return -1;
    }

    struct stat st;
    stat(key_path, &st);
    size_t size = st.st_size;

    unsigned char* buffer = malloc(size);
    size_t read = fread(buffer, 1, size, fd);

    if(read <= 0)
    {
        free(buffer);
        return -1;
    }
    fclose(fd);
    int key_slot = -1;
    
    sgx_status_t status = enclave_rsa_load_key(enclave_id, &key_slot, buffer, read, key_path);
    if (status != SGX_SUCCESS)
    {
        printf("Enclave returned 0x%x\n", status);
        free(buffer);
        return -1;
    }
    if (key_slot < 0)
    {
        printf("returned key_slot %d\n", key_slot);
        free(buffer);
        return -1;
    }
    printf("[%d] Loaded key into slot %d\n", getpid(), key_slot);

    return key_slot;
}

char* sgx_rsa_get_n(int key_id)
{
    sgx_status_t status;
    char *rsa_n;
    int length;
    status = enclave_rsa_get_n(enclave_id, &length, key_id, NULL, 0);
    if (status != SGX_SUCCESS || length == 0)
        return NULL;

    rsa_n = malloc(length + 1);
    memset(rsa_n, 0, length + 1);    
    status = enclave_rsa_get_n(enclave_id, &length, key_id, rsa_n, length + 1);
    if (status != SGX_SUCCESS || length == 0)
    {
        free(rsa_n);
        return NULL;
    }

    return rsa_n;
}

char* sgx_rsa_get_e(int key_id)
{
    sgx_status_t status;
    char *rsa_e;
    int length;
    status = enclave_rsa_get_e(enclave_id, &length, key_id, NULL, 0);
    if (status != SGX_SUCCESS || length == 0)
        return NULL;

    rsa_e = malloc(length + 1);
    memset(rsa_e, 0, length + 1);    
    status = enclave_rsa_get_e(enclave_id, &length, key_id, rsa_e, length + 1);
    if (status != SGX_SUCCESS || length == 0)
    {
        free(rsa_e);
        return NULL;
    }

    return rsa_e;
}