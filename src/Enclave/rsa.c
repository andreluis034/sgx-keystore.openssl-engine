#include <openssl/crypto.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <stdio.h>
#define MAX_KEYS 10

	CRYPTO_RWLOCK *rwlock = NULL;

typedef struct stored_key
{
    char path[BUFSIZ];
    size_t index;
    EVP_PKEY* pkey;
} stored_key;

stored_key* keys[MAX_KEYS];

void initLock()
{
   rwlock = CRYPTO_THREAD_lock_new();    
}
//Loads a key and returns its id. If the key was already loaded the previously assigned id is returned
int sgx_rsa_load_key(const unsigned char * keybuffer, int length, const char* path)
{
    if (rwlock == NULL)
        initLock();
    
    CRYPTO_THREAD_write_lock(rwlock);
    EVP_PKEY* pk;
    BIO* bio = BIO_new(BIO_s_mem());
    BIO_write(bio, keybuffer, length);
    PEM_read_bio_PrivateKey(bio, &pk, NULL, NULL);

    size_t availableSlot = -1;
    for (size_t i = 0; i < MAX_KEYS; i++)
    {
        if (keys[i] != NULL && EVP_PKEY_cmp(pk, keys[i]->pkey) == 0)
        {
	        CRYPTO_THREAD_unlock(rwlock);
            return i;
        }
        if (keys[i] == NULL)
            availableSlot = i;
    }
    if (availableSlot == -1)
    {
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
    CRYPTO_THREAD_unlock(rwlock);
    return availableSlot;
}