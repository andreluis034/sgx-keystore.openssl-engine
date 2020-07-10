#include <openssl/crypto.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <string.h>
#define MAX_KEYS 10

CRYPTO_RWLOCK *rwlock = NULL;
//TODO add reference count?
typedef struct stored_key
{
    char path[BUFSIZ];
    size_t index;
    EVP_PKEY* pkey;
} stored_key;

stored_key* keys[MAX_KEYS];

void enclave_init_rsa_lock()
{
   rwlock = CRYPTO_THREAD_lock_new();    
}

int enclave_rsa_get_e(int key_id, char* output, int length)
{
    //Out of bounds
    if (key_id >= MAX_KEYS || key_id < 0)
        return 0;
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

int enclave_rsa_get_n(int key_id, char* output, int length)
{
    //Out of bounds
    if (key_id >= MAX_KEYS || key_id < 0)
        return 0;
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

int enclave_rsa_private_decrypt(int flen, const unsigned char *from, int tlen, unsigned char *to, const RSA* rsa, int padding)
{
    if (flen != tlen)
        return -1;
    const RSA_METHOD* rsa_method = NULL;
    int (*priv_dec) (int flen, const unsigned char *from,
		unsigned char *to, RSA *rsa, int padding) = NULL;
    rsa_method = RSA_get_method(rsa);
    if (rsa_method == NULL)
    {
        return -1;
    }
    
	priv_dec = RSA_meth_get_priv_dec(rsa_method);
    if (priv_dec == NULL)
    {
        return -1;
    }
    
    return priv_dec(flen, from, to, (RSA*) rsa, padding);
}

int enclave_rsa_private_encrypt(int flen, const unsigned char *from, int tlen, unsigned char *to, const RSA* rsa, int padding)
{
    if (RSA_size(rsa) != tlen)
    {
        return -1;
    }
    
    const RSA_METHOD* rsa_method = NULL;
    int (*priv_enc) (int flen, const unsigned char *from,
		unsigned char *to, RSA *rsa, int padding) = NULL;
    rsa_method = RSA_get_method(rsa);
    if (rsa_method == NULL)
    {
        return -1;
    }
    
	priv_enc = RSA_meth_get_priv_enc(rsa_method);
    if (priv_enc == NULL)
    {
        return -1;
    }
    
    return priv_enc(flen, from, to, (RSA*) rsa, padding);
}

//TODO handle other key types, currently only supports RSA
int enclave_private_encrypt(int flen, const unsigned char *from, int tlen, unsigned char *to, int key_id, int padding)
{
    const RSA* rsa;
    if (from == NULL || to == NULL)
        return -1;    
    if (key_id >= MAX_KEYS || key_id < 0)
        return -1;
    if(rwlock == NULL)
        return -1;
    CRYPTO_THREAD_write_lock(rwlock);
    stored_key* key = keys[key_id];
    if (key == NULL)
    {
	    CRYPTO_THREAD_unlock(rwlock);
        return -1;
    }
    
    //TODO handle other key types, currently only supports RSA
    rsa = EVP_PKEY_get0_RSA(key->pkey);
    if(rsa == NULL)
    {
	    CRYPTO_THREAD_unlock(rwlock);
        return -1;
    }
    int ret = enclave_rsa_private_encrypt(flen, from, tlen, to, rsa, padding);
	CRYPTO_THREAD_unlock(rwlock);
    return ret;
}

int enclave_private_decrypt(int flen, const unsigned char *from, int tlen, unsigned char *to, int key_id, int padding)
{
    const RSA* rsa;
    if (from == NULL || to == NULL)
        return -1;    
    if (key_id >= MAX_KEYS || key_id < 0)
        return -1;
    if(rwlock == NULL)
        return -1;
    CRYPTO_THREAD_write_lock(rwlock);    
    stored_key* key = keys[key_id];
    if (key == NULL)
    {
	    CRYPTO_THREAD_unlock(rwlock);
        return -1;
    }
    //TODO handle other key types, currently only supports RSA
    rsa = EVP_PKEY_get0_RSA(key->pkey);
    if(rsa == NULL)
    {
	    CRYPTO_THREAD_unlock(rwlock);
        return -1;
    }
    int ret = enclave_rsa_private_decrypt(flen, from, tlen, to, rsa, padding);
	CRYPTO_THREAD_unlock(rwlock);
    return ret;
}


void enclave_unload_key_from_enclave(int key_id)
{
    //Out of bounds
    if (key_id >= MAX_KEYS || key_id < 0)
        return;
    if(rwlock == NULL)
        return;
    CRYPTO_THREAD_write_lock(rwlock);
    stored_key* key = keys[key_id];
    if (key == NULL)
    {
	    CRYPTO_THREAD_unlock(rwlock);
        return;
    }
    keys[key_id] = NULL;
    EVP_PKEY_free(key->pkey);
    free(key);
    CRYPTO_THREAD_unlock(rwlock);
}

//Loads a key and returns its id. If the key was already loaded the previously assigned id is returned
int enclave_rsa_load_key(const unsigned char * keybuffer, int length, const char* path)
{
    //printf("[>] enclave_rsa_load_key(%p, %d, %s)\n",keybuffer, length, path);
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
        if (keys[i] != NULL && BN_cmp(RSA_get0_n(rsa), RSA_get0_n(EVP_PKEY_get0_RSA(keys[i]->pkey))) == 0)
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