#ifndef ENGINE_U_H__
#define ENGINE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef OCALL_PRINT_STRING_DEFINED__
#define OCALL_PRINT_STRING_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_string, (const char* str));
#endif
#ifndef U_SGXSSL_FTIME_DEFINED__
#define U_SGXSSL_FTIME_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, u_sgxssl_ftime, (void* timeptr, uint32_t timeb_len));
#endif
#ifndef SGX_OC_CPUIDEX_DEFINED__
#define SGX_OC_CPUIDEX_DEFINED__
void SGX_UBRIDGE(SGX_CDECL, sgx_oc_cpuidex, (int cpuinfo[4], int leaf, int subleaf));
#endif
#ifndef SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_wait_untrusted_event_ocall, (const void* self));
#endif
#ifndef SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_untrusted_event_ocall, (const void* waiter));
#endif
#ifndef SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_setwait_untrusted_events_ocall, (const void* waiter, const void* self));
#endif
#ifndef SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_multiple_untrusted_events_ocall, (const void** waiters, size_t total));
#endif

sgx_status_t teste_ecall(sgx_enclave_id_t eid);
sgx_status_t enclave_init_rsa_lock(sgx_enclave_id_t eid);
sgx_status_t enclave_unload_key_from_enclave(sgx_enclave_id_t eid, int key_id);
sgx_status_t enclave_private_encrypt(sgx_enclave_id_t eid, int* retval, int flen, const unsigned char* frm, int tlen, unsigned char* to, int key_id, int padding);
sgx_status_t enclave_private_decrypt(sgx_enclave_id_t eid, int* retval, int flen, const unsigned char* frm, int tlen, unsigned char* to, int key_id, int padding);
sgx_status_t enclave_rsa_get_n(sgx_enclave_id_t eid, int* retval, int key_id, char* output, int length);
sgx_status_t enclave_rsa_get_e(sgx_enclave_id_t eid, int* retval, int key_id, char* output, int length);
sgx_status_t enclave_rsa_load_key(sgx_enclave_id_t eid, int* retval, const unsigned char* keybuffer, int length, const char* path);
sgx_status_t get_sealed_data_size(sgx_enclave_id_t eid, uint32_t* retval, uint32_t data_size);
sgx_status_t seal_data(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* clear, uint32_t clear_size, uint8_t* sealed_blob, uint32_t data_size);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
