#pragma once
#define SGX_KEYSTORE_SOCKET_PATH "/var/run/sgx-keystore/keystore.socket"
#define SGX_KEYSTORE_MAX_BUFFER_LENGTH 512
enum RequestType
{
    load_key = 0,
    unload_key = 1,
    rsa_get_e_n = 2,
    rsa_priv_enc = 3,
    rsa_priv_dec = 4
};

struct Request
{
    enum RequestType type;
    union
    {
        struct
        {
            char keyId[SGX_KEYSTORE_MAX_BUFFER_LENGTH];
        } load_key;
        
        struct 
        {
            int keySlot;
        } rsa_get_e_n;
        
    } message;
    
};