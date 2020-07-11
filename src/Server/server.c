#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdlib.h>
#include "Include/sgx_keystore.h"
#include "libsgx.h"

void handle_loadkey(int fd, struct Request* request)
{
    int key_slot = sgx_load_key(request->message.load_key.keyId);
    int lwrite = write(fd, &key_slot, sizeof(key_slot));
    (void)lwrite;
}

void handle_get_e_n(int fd, struct Request* request)
{
    char* rsa_n = sgx_rsa_get_n(request->message.rsa_get_e_n.keySlot);
    if (rsa_n == NULL)
        return;
    
    int rsa_n_length = strlen(rsa_n);
    char* data =  malloc(sizeof(rsa_n_length) + rsa_n_length + 1);
    memset(data, 0, sizeof(rsa_n_length) + rsa_n_length + 1);
    memcpy(data, &rsa_n_length, sizeof(rsa_n_length)); memcpy(data + sizeof(rsa_n_length), rsa_n, rsa_n_length);
    int lwrite = write(fd, data, sizeof(rsa_n_length) + rsa_n_length + 1);
    free(data);
    free(rsa_n);

    char* rsa_e = sgx_rsa_get_e(request->message.rsa_get_e_n.keySlot);
    int rsa_e_length = strlen(rsa_e);
    data =  malloc(sizeof(rsa_e_length) + rsa_e_length + 1);
    memset(data, 0, sizeof(rsa_e_length) + rsa_e_length + 1);
    memcpy(data, &rsa_e_length, sizeof(rsa_e_length)); memcpy(data + sizeof(rsa_e_length), rsa_e, rsa_e_length);
    lwrite = write(fd, data, sizeof(rsa_e_length) + rsa_e_length + 1);
    free(data);
    free(rsa_e);
    (void)lwrite;
}

void handle_rsa_priv_enc(int fd, struct Request* request)
{   
    int lwrite;
    struct Response response;
    printf("%d %d\n", request->message.rsa_priv.flen, request->message.rsa_priv.tlen);

    int result = sgx_private_encrypt(request->message.rsa_priv.flen, request->message.rsa_priv.from, request->message.rsa_priv.tlen, response.message.rsa_priv.to, request->message.rsa_priv.keySlot, request->message.rsa_priv.padding);
    response.message.rsa_priv.retValue = result; 
    lwrite = write(fd, &response, sizeof(response));
    (void)lwrite;
    printf("%d\n", result);
}

void handle_rsa_priv_dec(int fd, struct Request* request)
{   
    int lwrite;
    struct Response response;
    printf("%d %d\n", request->message.rsa_priv.flen, request->message.rsa_priv.tlen);

    int result = sgx_private_decrypt(request->message.rsa_priv.flen, request->message.rsa_priv.from, request->message.rsa_priv.tlen, response.message.rsa_priv.to, request->message.rsa_priv.keySlot, request->message.rsa_priv.padding);
    response.message.rsa_priv.retValue = result; 
    lwrite = write(fd, &response, sizeof(response));
    (void)lwrite;
    printf("%d\n", result);
}


void handle_message(int fd, struct Request* request)
{
    printf("Type: %d\n", request->type);

    switch (request->type)
    {
    case load_key:
        handle_loadkey(fd, request);
        break;
    case rsa_get_e_n:
        handle_get_e_n(fd, request);
        break;
    case rsa_priv_enc:
        handle_rsa_priv_enc(fd, request);
        break;
    case rsa_priv_dec:
        handle_rsa_priv_dec(fd, request);
        break;
    default:
        break;
    }       
}

void receive_message(int fd)
{
    struct Request request;
    int lread;
    lread = read(fd, &request, sizeof(request));

    if (lread != sizeof(request))
        return;

    handle_message(fd, &request);
}

#define ENCLAVE_PATH "Enclave.signed.so"
void load_enclave()
{
    sgx_status_t status = sgx_init_enclave(ENCLAVE_PATH);
    if (status == SGX_SUCCESS)
    {
        printf("[+] Enclave loaded\n");
        return;
    }
    fprintf(stderr, "[%d] sgx_init_enclave failed %x\n", getpid(), status);
    fprintf(stderr, "%s\n", sgx_get_error_message(status));
    exit(-1);
}

int main(int argc, const char* argv[])
{
    struct sockaddr_un addr;
    
    int fd,cl;

    load_enclave();

    if ( (fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        perror("socket error");
        exit(-1);
    }
    printf("[+] Created socket\n");
    memset(&addr, 0, sizeof(addr));

    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SGX_KEYSTORE_SOCKET_PATH, sizeof(addr.sun_path)-1);
    
    unlink(SGX_KEYSTORE_SOCKET_PATH);
    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        perror("bind error");
        exit(-1);
    }

    if (listen(fd, 256) == -1) {
        perror("listen error");
        exit(-1);
    }

    while (1) {
        if ( (cl = accept(fd, NULL, NULL)) == -1) {
            perror("accept error");
            continue;
        }   
        receive_message(cl);
        close(cl);

    }

    close(fd);
}