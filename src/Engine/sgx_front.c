#include "libsgx.h"
#include <unistd.h>
#include <sys/stat.h>
#include <openssl/pem.h>
#include <string.h>
#include "methods.h"
#include "engine_id.h"
#include "sgx_keystore.h"
#include <sys/types.h>          /* See NOTES */
#include <sys/socket.h>
#include <sys/un.h>

struct SGX_Enclave_st {
	CRYPTO_RWLOCK *rwlock;
	const char* socket_path;
    
};

int connect_to_keystore(const char* keystore_socket)
{
    struct sockaddr_un addr;
    int fd;
    if ( (fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        perror("socket error");
        return -1;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, keystore_socket, sizeof(addr.sun_path)-1);

    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        perror("connect error");
        return -1;
    }
    return fd;
}

int sgx_init_enclave(const char* keystore_socket, SGX_ENCLAVE** enclave_out)
{
    SGX_ENCLAVE* enclave;
    int fd;
    if (enclave_out == NULL)
        return 0;
    if ((fd = connect_to_keystore(keystore_socket)) == -1)
        return 0;

    close(fd);
    *enclave_out = enclave = (SGX_ENCLAVE*)malloc(sizeof(SGX_ENCLAVE));

    enclave->rwlock = CRYPTO_THREAD_lock_new();
    enclave->socket_path = keystore_socket;
    
    return 1;
}


RSA* sgx_key_get_rsa(SGX_KEY* sgx_key)
{
    int length, fd, lwrite;
    char *rsa_n, *rsa_e, *data;
    int rsa_n_length, rsa_e_length;
    BIGNUM *bn_n, *bn_e;
    RSA* rsa;
    struct Request* request;

    if ((fd = connect_to_keystore(sgx_key->enclave->socket_path)) == -1)
        return 0;
    request = OPENSSL_zalloc(sizeof(struct Request));
    request->type = rsa_get_e_n;
    request->message.rsa_get_e_n.keySlot = sgx_key->keyId;
    lwrite = write(fd, request, sizeof(struct Request));
    data = malloc(1024*2);//Should be enough for all keys?
    if ( (length = read(fd, data, 1024*2)) < 0)
    {
        free(data);
        return NULL;
    }
    rsa_n_length = *(int*)data;
    rsa_n = strdup(data + sizeof(rsa_n_length));
    if ((length = read(fd, data, 1024*2)) < 0)
    {
        free(data);
        return NULL;
    }
    rsa_e_length = *(int*)data;
    rsa_e = strdup(data + sizeof(rsa_e_length));
    
    if ((bn_n = BN_new()) == NULL || BN_hex2bn(&bn_n, rsa_n) == 0)
    {
        free(rsa_n);
        free(rsa_e);
        free(data);
        return NULL;
    }
    if ((bn_e = BN_new()) == NULL || BN_hex2bn(&bn_e, rsa_e) == 0)
    {
        free(rsa_n);
        free(rsa_e);
        free(data);
        BN_free(bn_n);
        return NULL;
    }
    free(rsa_n);
    free(rsa_e);
    free(data);

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
    return -1;
    /*
    sgx_status_t status;
    int ret;
  
    //fprintf(stderr, "[%d] %s(%d, %p, %p, (id: %d, pid: %d), %d)\n",getpid(), __FUNCTION__, flen, from, to, key->keyId, key->enclave->pid, padding);
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
    return ret;*/
}

int sgx_private_encrypt(int flen, const unsigned char *from, unsigned char *to, SGX_KEY* key, int padding)
{
    return -1;
    /*
    sgx_status_t status;
    int ret;
    CRYPTO_THREAD_write_lock(key->enclave->rwlock);

    //fprintf(stderr, "[%d] %s(%d, %p, %p, (id: %d, pid: %d), %d)\n",getpid(), __FUNCTION__, flen, from, to, key->keyId, key->enclave->pid, padding);
    if (!sgx_handle_forked(key))
    {
        CRYPTO_THREAD_unlock(key->enclave->rwlock);
        return -1;
    }

    if (key == NULL)
    {
        CRYPTO_THREAD_unlock(key->enclave->rwlock);
        return -1;
    }
    
    int tlen = sgx_get_key_size(key);   
    if(tlen == 0)
    {
        CRYPTO_THREAD_unlock(key->enclave->rwlock);
        return -1;
    }        

   // fprintf(stderr, "[%d] key size: %d\n", getpid(), tlen);
    status = enclave_private_encrypt(key->enclave->enclave_id, &ret, flen, from, tlen, to, key->keyId, padding);
    if(status != SGX_SUCCESS)
    {
        fprintf(stderr, "enclave_private_encrypt ecall status: 0x%x\n", status);
        CRYPTO_THREAD_unlock(key->enclave->rwlock);
        return -1;
    }
    CRYPTO_THREAD_unlock(key->enclave->rwlock);
    return ret;*/
}


SGX_KEY* sgx_load_key(SGX_ENCLAVE* enclave, const char* key_path)
{
    int lwrite, lread;
    int key_slot;
    int fd;
    struct Request* request;
    SGX_KEY* sgx_key;

    request = OPENSSL_zalloc(sizeof(struct Request));
    if (request == NULL)
        return NULL;
    sgx_key = OPENSSL_zalloc(sizeof(SGX_KEY));
    if (sgx_key == NULL)
    {
        OPENSSL_free(request);
        return NULL;
    }
    
    if ((fd = connect_to_keystore(enclave->socket_path)) == -1)
        return NULL;

    
    request->type = load_key;
    OPENSSL_strlcpy(request->message.load_key.keyId, key_path, sizeof(request->message.load_key.keyId));

    lwrite = write(fd, request, sizeof(struct Request));
    
    if (lwrite <= 0)
    {
        OPENSSL_free(sgx_key);
        OPENSSL_free(request);
        return NULL;
    }
    
    lread = read(fd, &key_slot, sizeof(key_slot));

    if (lread <= 0)
    {
        OPENSSL_free(sgx_key);
        OPENSSL_free(request);
        return NULL;
    }

    sgx_key->enclave = enclave;
    sgx_key->keyId = key_slot;
    sgx_key->label = key_path;
    
    return sgx_key;
}

