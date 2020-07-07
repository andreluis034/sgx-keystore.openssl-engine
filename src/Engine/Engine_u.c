#include "Engine_u.h"
#include <errno.h>

typedef struct ms_sgx_rsa_get_n_t {
	int ms_retval;
	int ms_key_id;
	char* ms_output;
	int ms_length;
} ms_sgx_rsa_get_n_t;

typedef struct ms_sgx_rsa_get_e_t {
	int ms_retval;
	int ms_key_id;
	char* ms_output;
	int ms_length;
} ms_sgx_rsa_get_e_t;

typedef struct ms_sgx_rsa_load_key_t {
	int ms_retval;
	const unsigned char* ms_keybuffer;
	int ms_length;
	const char* ms_path;
	size_t ms_path_len;
} ms_sgx_rsa_load_key_t;

typedef struct ms_ocall_print_string_t {
	const char* ms_str;
} ms_ocall_print_string_t;

typedef struct ms_u_sgxssl_ftime_t {
	void* ms_timeptr;
	uint32_t ms_timeb_len;
} ms_u_sgxssl_ftime_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	const void* ms_waiter;
	const void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	const void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

static sgx_status_t SGX_CDECL Engine_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ocall_print_string(ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Engine_u_sgxssl_ftime(void* pms)
{
	ms_u_sgxssl_ftime_t* ms = SGX_CAST(ms_u_sgxssl_ftime_t*, pms);
	u_sgxssl_ftime(ms->ms_timeptr, ms->ms_timeb_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Engine_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Engine_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Engine_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Engine_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall(ms->ms_waiter, ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Engine_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall(ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[7];
} ocall_table_Engine = {
	7,
	{
		(void*)Engine_ocall_print_string,
		(void*)Engine_u_sgxssl_ftime,
		(void*)Engine_sgx_oc_cpuidex,
		(void*)Engine_sgx_thread_wait_untrusted_event_ocall,
		(void*)Engine_sgx_thread_set_untrusted_event_ocall,
		(void*)Engine_sgx_thread_setwait_untrusted_events_ocall,
		(void*)Engine_sgx_thread_set_multiple_untrusted_events_ocall,
	}
};
sgx_status_t teste_ecall(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 0, &ocall_table_Engine, NULL);
	return status;
}

sgx_status_t sgx_init_rsa_lock(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 1, &ocall_table_Engine, NULL);
	return status;
}

sgx_status_t sgx_rsa_get_n(sgx_enclave_id_t eid, int* retval, int key_id, char* output, int length)
{
	sgx_status_t status;
	ms_sgx_rsa_get_n_t ms;
	ms.ms_key_id = key_id;
	ms.ms_output = output;
	ms.ms_length = length;
	status = sgx_ecall(eid, 2, &ocall_table_Engine, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t sgx_rsa_get_e(sgx_enclave_id_t eid, int* retval, int key_id, char* output, int length)
{
	sgx_status_t status;
	ms_sgx_rsa_get_e_t ms;
	ms.ms_key_id = key_id;
	ms.ms_output = output;
	ms.ms_length = length;
	status = sgx_ecall(eid, 3, &ocall_table_Engine, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t sgx_rsa_load_key(sgx_enclave_id_t eid, int* retval, const unsigned char* keybuffer, int length, const char* path)
{
	sgx_status_t status;
	ms_sgx_rsa_load_key_t ms;
	ms.ms_keybuffer = keybuffer;
	ms.ms_length = length;
	ms.ms_path = path;
	ms.ms_path_len = path ? strlen(path) + 1 : 0;
	status = sgx_ecall(eid, 4, &ocall_table_Engine, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

