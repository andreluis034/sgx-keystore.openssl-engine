#include <openssl/crypto.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <string.h>
#define MAX_KEYS 10

CRYPTO_RWLOCK *rwlock = NULL;

typedef struct stored_key
{
    char path[BUFSIZ];
    size_t index;
    EVP_PKEY* pkey;
} stored_key;

stored_key* keys[MAX_KEYS];

void sgx_init_rsa_lock()
{
   rwlock = CRYPTO_THREAD_lock_new();    
}

int sgx_rsa_get_e(int key_id, char* output, int length)
{
    if(rwlock == NULL)
        return 0;
    CRYPTO_THREAD_write_lock(rwlock);
    stored_key* key = keys[key_id];
    if (key == NULL)
    {
	    CRYPTO_THREAD_unlock(rwlock);
        return 0;
    }

    RSA* rsa = EVP_PKEY_get0_RSA(key->pkey);    
    if (rsa == NULL)
    {
	    CRYPTO_THREAD_unlock(rwlock);
        return 0;
    }  
    int alloced = 0;
    BIGNUM *rsa_e = (BIGNUM*)RSA_get0_e(rsa); 

    if (BN_is_zero(rsa_e))/* Non valid public exponent */
    {
        //se the most common default 
        rsa_e = BN_new();
        if(rsa_e == NULL)
            return 0;
        alloced = 1;
        BN_set_word(rsa_e, RSA_F4);
        
    }
    


    char* hex_e = BN_bn2hex(rsa_e);
    int length_e = strlen(hex_e);
    if(alloced)
        OPENSSL_free(rsa_e);
    if (output == NULL || length == 0)
    {
        OPENSSL_free(hex_e);
	    CRYPTO_THREAD_unlock(rwlock);
        return length_e;
    }
    if (length_e <= length)
    {
        memcpy(output, hex_e, length_e);
        OPENSSL_free(hex_e);
	    CRYPTO_THREAD_unlock(rwlock);
        return length_e;
    }
    OPENSSL_free(hex_e);
    CRYPTO_THREAD_unlock(rwlock);

    return 0;
      
}

int sgx_rsa_get_n(int key_id, char* output, int length)
{
    if(rwlock == NULL)
        return 0;
    CRYPTO_THREAD_write_lock(rwlock);
    stored_key* key = keys[key_id];
    if (key == NULL)
    {
	    CRYPTO_THREAD_unlock(rwlock);
        return 0;
    }

    RSA* rsa = EVP_PKEY_get0_RSA(key->pkey);    
    if (rsa == NULL)
    {
	    CRYPTO_THREAD_unlock(rwlock);
        return 0;
    }        

    BIGNUM *rsa_n = (BIGNUM*) RSA_get0_n(rsa); 
    char* hex_n = BN_bn2hex(rsa_n);
    int length_n = strlen(hex_n);
    if (output == NULL || length == 0)
    {
        OPENSSL_free(hex_n);
	    CRYPTO_THREAD_unlock(rwlock);
        return length_n;
    }
    if (length_n <= length)
    {
        memcpy(output, hex_n, length_n);
        OPENSSL_free(hex_n);
	    CRYPTO_THREAD_unlock(rwlock);
        return length_n;
    }
    OPENSSL_free(hex_n);
    CRYPTO_THREAD_unlock(rwlock);
    return 0;
}

//Loads a key and returns its id. If the key was already loaded the previously assigned id is returned
int sgx_rsa_load_key(const unsigned char * keybuffer, int length, const char* path)
{
    printf("[>] sgx_rsa_load_key(%p, %d, %s)\n",keybuffer, length, path);
    if(keybuffer == NULL || path == NULL)
        return -3;
    if (rwlock == NULL)
        return -7;
    CRYPTO_THREAD_write_lock(rwlock);
    EVP_PKEY* pk;
    RSA* rsa = NULL;
    BIO* bio = BIO_new_mem_buf((void*)keybuffer, length);
    if (bio == NULL)
    {
	    CRYPTO_THREAD_unlock(rwlock);
        return -4;
    }
    PEM_read_bio_RSAPrivateKey(bio, &rsa, 0, NULL);
    BIO_free(bio);
    if (rsa == NULL)
    {
	    CRYPTO_THREAD_unlock(rwlock);
        return -4;
    }
    pk = EVP_PKEY_new();
    if (pk == NULL)
    {
        RSA_free(rsa);
	    CRYPTO_THREAD_unlock(rwlock);
        return -5;
    }
    if(EVP_PKEY_assign_RSA(pk, rsa) == 0)
    {
        RSA_free(rsa);
        EVP_PKEY_free(pk);
	    CRYPTO_THREAD_unlock(rwlock);
        return -6;
    }

    size_t availableSlot = -1;
    for (size_t i = 0; i < MAX_KEYS; i++)
    {
        if (keys[i] != NULL && EVP_PKEY_cmp(pk, keys[i]->pkey) == 0)
        {
	        CRYPTO_THREAD_unlock(rwlock);
            return i;
        }
        if (keys[i] == NULL && availableSlot == -1)
            availableSlot = i;
    }
    //No more space available
    if (availableSlot == -1)
    {
        RSA_free(rsa);
        EVP_PKEY_free(pk);
	    CRYPTO_THREAD_unlock(rwlock);
        return -1;
    }
    stored_key* key = malloc(sizeof(stored_key));
    if (key == NULL)
    {
	    CRYPTO_THREAD_unlock(rwlock);
        return -2;
    }
    OPENSSL_strlcpy(key->path, path, BUFSIZ);
    key->index = availableSlot;
    key->pkey = pk;
    keys[availableSlot] = key;
    CRYPTO_THREAD_unlock(rwlock);
    return availableSlot;
}