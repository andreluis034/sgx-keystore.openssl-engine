#ifndef ENGINE_T_H__
#define ENGINE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void teste_ecall(void);
void enclave_init_rsa_lock(void);
void enclave_unload_key_from_enclave(int key_id);
int enclave_private_encrypt(int flen, const unsigned char* frm, int tlen, unsigned char* to, int key_id, int padding);
int enclave_private_decrypt(int flen, const unsigned char* frm, int tlen, unsigned char* to, int key_id, int padding);
int enclave_rsa_get_n(int key_id, char* output, int length);
int enclave_rsa_get_e(int key_id, char* output, int length);
int enclave_rsa_load_key(const unsigned char* keybuffer, int length, const char* path, int sealed);
uint32_t get_sealed_data_size(uint32_t data_size);
sgx_status_t seal_data(uint8_t* clear, uint32_t clear_size, uint8_t* sealed_blob, uint32_t data_size);

sgx_status_t SGX_CDECL ocall_print_string(const char* str);
sgx_status_t SGX_CDECL u_sgxssl_ftime(void* timeptr, uint32_t timeb_len);
sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf);
sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter);
sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
