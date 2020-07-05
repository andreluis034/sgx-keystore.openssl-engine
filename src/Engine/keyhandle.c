#include "methods.h"
#include <string.h>
/**
 * Makes sure the ex_data for the keyhandle is initially set to NULL.
 */
void keyhandle_new(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
                           int idx, long argl, void *argp) {

    (void)parent;
    (void)ptr;
    (void)ad;
    (void)argl;
    (void)argp;

    CRYPTO_set_ex_data(ad, idx, NULL);
}

/**
 * Frees a previously allocated keyhandle stored in ex_data.
 */
void keyhandle_free(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
                             int idx, long argl, void *argp) {
    (void)parent;
    (void)ad;
    (void)idx;
    (void)argl;
    (void)argp;

    char* keyhandle = (char*)ptr;
    if (keyhandle != NULL) {
        free(keyhandle);
    }
}

/**
 * Duplicates a keyhandle stored in ex_data in case we copy a key.
 */
int keyhandle_dup(CRYPTO_EX_DATA *to, const CRYPTO_EX_DATA *from,
                           void *from_d, int idx, long argl, void *argp) {
    // This appears to be a bug in OpenSSL.
    void** ptr = (void**)(from_d);
    char* keyhandle = (char*)(*ptr);
    if (keyhandle != NULL) {
        char* keyhandle_copy = strdup(keyhandle);
        *ptr = keyhandle_copy;

        // Call this in case OpenSSL is fixed in the future.
        (void) CRYPTO_set_ex_data(to, idx, keyhandle_copy);
    }
    return 1;
}

void *ex_data_dup(void *data) {
    char* keyhandle = (char*)data;
    return strdup(keyhandle);
}

void ex_data_free(void *data) {
    char* keyhandle = (char*)data;
    free(keyhandle);
}

void ex_data_clear_free(void *data) {
    char* keyhandle = (char*)data;
    memset(data, '\0', strlen(keyhandle));
    free(keyhandle);
}
