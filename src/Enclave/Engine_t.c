#include "Engine_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


typedef struct ms_enclave_unload_key_from_enclave_t {
	int ms_key_id;
} ms_enclave_unload_key_from_enclave_t;

typedef struct ms_enclave_private_encrypt_t {
	int ms_retval;
	int ms_flen;
	const unsigned char* ms_frm;
	int ms_tlen;
	unsigned char* ms_to;
	int ms_key_id;
	int ms_padding;
} ms_enclave_private_encrypt_t;

typedef struct ms_enclave_private_decrypt_t {
	int ms_retval;
	int ms_flen;
	const unsigned char* ms_frm;
	int ms_tlen;
	unsigned char* ms_to;
	int ms_key_id;
	int ms_padding;
} ms_enclave_private_decrypt_t;

typedef struct ms_enclave_rsa_get_n_t {
	int ms_retval;
	int ms_key_id;
	char* ms_output;
	int ms_length;
} ms_enclave_rsa_get_n_t;

typedef struct ms_enclave_rsa_get_e_t {
	int ms_retval;
	int ms_key_id;
	char* ms_output;
	int ms_length;
} ms_enclave_rsa_get_e_t;

typedef struct ms_enclave_rsa_load_key_t {
	int ms_retval;
	const unsigned char* ms_keybuffer;
	int ms_length;
	const char* ms_path;
	size_t ms_path_len;
	int ms_sealed;
} ms_enclave_rsa_load_key_t;

typedef struct ms_get_sealed_data_size_t {
	uint32_t ms_retval;
	uint32_t ms_data_size;
} ms_get_sealed_data_size_t;

typedef struct ms_seal_data_t {
	sgx_status_t ms_retval;
	uint8_t* ms_clear;
	uint32_t ms_clear_size;
	uint8_t* ms_sealed_blob;
	uint32_t ms_data_size;
} ms_seal_data_t;

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

static sgx_status_t SGX_CDECL sgx_teste_ecall(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	teste_ecall();
	return status;
}

static sgx_status_t SGX_CDECL sgx_enclave_init_rsa_lock(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	enclave_init_rsa_lock();
	return status;
}

static sgx_status_t SGX_CDECL sgx_enclave_unload_key_from_enclave(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enclave_unload_key_from_enclave_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enclave_unload_key_from_enclave_t* ms = SGX_CAST(ms_enclave_unload_key_from_enclave_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	enclave_unload_key_from_enclave(ms->ms_key_id);


	return status;
}

static sgx_status_t SGX_CDECL sgx_enclave_private_encrypt(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enclave_private_encrypt_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enclave_private_encrypt_t* ms = SGX_CAST(ms_enclave_private_encrypt_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const unsigned char* _tmp_frm = ms->ms_frm;
	int _tmp_flen = ms->ms_flen;
	size_t _len_frm = _tmp_flen;
	unsigned char* _in_frm = NULL;
	unsigned char* _tmp_to = ms->ms_to;
	int _tmp_tlen = ms->ms_tlen;
	size_t _len_to = _tmp_tlen;
	unsigned char* _in_to = NULL;

	CHECK_UNIQUE_POINTER(_tmp_frm, _len_frm);
	CHECK_UNIQUE_POINTER(_tmp_to, _len_to);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_frm != NULL && _len_frm != 0) {
		if ( _len_frm % sizeof(*_tmp_frm) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_frm = (unsigned char*)malloc(_len_frm);
		if (_in_frm == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_frm, _len_frm, _tmp_frm, _len_frm)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_to != NULL && _len_to != 0) {
		if ( _len_to % sizeof(*_tmp_to) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_to = (unsigned char*)malloc(_len_to)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_to, 0, _len_to);
	}

	ms->ms_retval = enclave_private_encrypt(_tmp_flen, (const unsigned char*)_in_frm, _tmp_tlen, _in_to, ms->ms_key_id, ms->ms_padding);
	if (_in_to) {
		if (memcpy_s(_tmp_to, _len_to, _in_to, _len_to)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_frm) free(_in_frm);
	if (_in_to) free(_in_to);
	return status;
}

static sgx_status_t SGX_CDECL sgx_enclave_private_decrypt(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enclave_private_decrypt_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enclave_private_decrypt_t* ms = SGX_CAST(ms_enclave_private_decrypt_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const unsigned char* _tmp_frm = ms->ms_frm;
	int _tmp_flen = ms->ms_flen;
	size_t _len_frm = _tmp_flen;
	unsigned char* _in_frm = NULL;
	unsigned char* _tmp_to = ms->ms_to;
	int _tmp_tlen = ms->ms_tlen;
	size_t _len_to = _tmp_tlen;
	unsigned char* _in_to = NULL;

	CHECK_UNIQUE_POINTER(_tmp_frm, _len_frm);
	CHECK_UNIQUE_POINTER(_tmp_to, _len_to);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_frm != NULL && _len_frm != 0) {
		if ( _len_frm % sizeof(*_tmp_frm) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_frm = (unsigned char*)malloc(_len_frm);
		if (_in_frm == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_frm, _len_frm, _tmp_frm, _len_frm)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_to != NULL && _len_to != 0) {
		if ( _len_to % sizeof(*_tmp_to) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_to = (unsigned char*)malloc(_len_to)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_to, 0, _len_to);
	}

	ms->ms_retval = enclave_private_decrypt(_tmp_flen, (const unsigned char*)_in_frm, _tmp_tlen, _in_to, ms->ms_key_id, ms->ms_padding);
	if (_in_to) {
		if (memcpy_s(_tmp_to, _len_to, _in_to, _len_to)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_frm) free(_in_frm);
	if (_in_to) free(_in_to);
	return status;
}

static sgx_status_t SGX_CDECL sgx_enclave_rsa_get_n(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enclave_rsa_get_n_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enclave_rsa_get_n_t* ms = SGX_CAST(ms_enclave_rsa_get_n_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_output = ms->ms_output;
	int _tmp_length = ms->ms_length;
	size_t _len_output = _tmp_length;
	char* _in_output = NULL;

	CHECK_UNIQUE_POINTER(_tmp_output, _len_output);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_output != NULL && _len_output != 0) {
		if ( _len_output % sizeof(*_tmp_output) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_output = (char*)malloc(_len_output)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_output, 0, _len_output);
	}

	ms->ms_retval = enclave_rsa_get_n(ms->ms_key_id, _in_output, _tmp_length);
	if (_in_output) {
		if (memcpy_s(_tmp_output, _len_output, _in_output, _len_output)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_output) free(_in_output);
	return status;
}

static sgx_status_t SGX_CDECL sgx_enclave_rsa_get_e(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enclave_rsa_get_e_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enclave_rsa_get_e_t* ms = SGX_CAST(ms_enclave_rsa_get_e_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_output = ms->ms_output;
	int _tmp_length = ms->ms_length;
	size_t _len_output = _tmp_length;
	char* _in_output = NULL;

	CHECK_UNIQUE_POINTER(_tmp_output, _len_output);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_output != NULL && _len_output != 0) {
		if ( _len_output % sizeof(*_tmp_output) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_output = (char*)malloc(_len_output)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_output, 0, _len_output);
	}

	ms->ms_retval = enclave_rsa_get_e(ms->ms_key_id, _in_output, _tmp_length);
	if (_in_output) {
		if (memcpy_s(_tmp_output, _len_output, _in_output, _len_output)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_output) free(_in_output);
	return status;
}

static sgx_status_t SGX_CDECL sgx_enclave_rsa_load_key(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enclave_rsa_load_key_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enclave_rsa_load_key_t* ms = SGX_CAST(ms_enclave_rsa_load_key_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const unsigned char* _tmp_keybuffer = ms->ms_keybuffer;
	int _tmp_length = ms->ms_length;
	size_t _len_keybuffer = _tmp_length;
	unsigned char* _in_keybuffer = NULL;
	const char* _tmp_path = ms->ms_path;
	size_t _len_path = ms->ms_path_len ;
	char* _in_path = NULL;

	CHECK_UNIQUE_POINTER(_tmp_keybuffer, _len_keybuffer);
	CHECK_UNIQUE_POINTER(_tmp_path, _len_path);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_keybuffer != NULL && _len_keybuffer != 0) {
		if ( _len_keybuffer % sizeof(*_tmp_keybuffer) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_keybuffer = (unsigned char*)malloc(_len_keybuffer);
		if (_in_keybuffer == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_keybuffer, _len_keybuffer, _tmp_keybuffer, _len_keybuffer)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_path != NULL && _len_path != 0) {
		_in_path = (char*)malloc(_len_path);
		if (_in_path == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_path, _len_path, _tmp_path, _len_path)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_path[_len_path - 1] = '\0';
		if (_len_path != strlen(_in_path) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

	ms->ms_retval = enclave_rsa_load_key((const unsigned char*)_in_keybuffer, _tmp_length, (const char*)_in_path, ms->ms_sealed);

err:
	if (_in_keybuffer) free(_in_keybuffer);
	if (_in_path) free(_in_path);
	return status;
}

static sgx_status_t SGX_CDECL sgx_get_sealed_data_size(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_get_sealed_data_size_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_get_sealed_data_size_t* ms = SGX_CAST(ms_get_sealed_data_size_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = get_sealed_data_size(ms->ms_data_size);


	return status;
}

static sgx_status_t SGX_CDECL sgx_seal_data(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_seal_data_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_seal_data_t* ms = SGX_CAST(ms_seal_data_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_clear = ms->ms_clear;
	uint32_t _tmp_clear_size = ms->ms_clear_size;
	size_t _len_clear = _tmp_clear_size;
	uint8_t* _in_clear = NULL;
	uint8_t* _tmp_sealed_blob = ms->ms_sealed_blob;
	uint32_t _tmp_data_size = ms->ms_data_size;
	size_t _len_sealed_blob = _tmp_data_size;
	uint8_t* _in_sealed_blob = NULL;

	CHECK_UNIQUE_POINTER(_tmp_clear, _len_clear);
	CHECK_UNIQUE_POINTER(_tmp_sealed_blob, _len_sealed_blob);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_clear != NULL && _len_clear != 0) {
		if ( _len_clear % sizeof(*_tmp_clear) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_clear = (uint8_t*)malloc(_len_clear);
		if (_in_clear == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_clear, _len_clear, _tmp_clear, _len_clear)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_sealed_blob != NULL && _len_sealed_blob != 0) {
		if ( _len_sealed_blob % sizeof(*_tmp_sealed_blob) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_sealed_blob = (uint8_t*)malloc(_len_sealed_blob)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_sealed_blob, 0, _len_sealed_blob);
	}

	ms->ms_retval = seal_data(_in_clear, _tmp_clear_size, _in_sealed_blob, _tmp_data_size);
	if (_in_sealed_blob) {
		if (memcpy_s(_tmp_sealed_blob, _len_sealed_blob, _in_sealed_blob, _len_sealed_blob)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_clear) free(_in_clear);
	if (_in_sealed_blob) free(_in_sealed_blob);
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[10];
} g_ecall_table = {
	10,
	{
		{(void*)(uintptr_t)sgx_teste_ecall, 0, 0},
		{(void*)(uintptr_t)sgx_enclave_init_rsa_lock, 0, 0},
		{(void*)(uintptr_t)sgx_enclave_unload_key_from_enclave, 0, 0},
		{(void*)(uintptr_t)sgx_enclave_private_encrypt, 0, 0},
		{(void*)(uintptr_t)sgx_enclave_private_decrypt, 0, 0},
		{(void*)(uintptr_t)sgx_enclave_rsa_get_n, 0, 0},
		{(void*)(uintptr_t)sgx_enclave_rsa_get_e, 0, 0},
		{(void*)(uintptr_t)sgx_enclave_rsa_load_key, 0, 0},
		{(void*)(uintptr_t)sgx_get_sealed_data_size, 0, 0},
		{(void*)(uintptr_t)sgx_seal_data, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[7][10];
} g_dyn_entry_table = {
	7,
	{
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_print_string(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_string_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_string_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(str, _len_str);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (str != NULL) ? _len_str : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_string_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_string_t));
	ocalloc_size -= sizeof(ms_ocall_print_string_t);

	if (str != NULL) {
		ms->ms_str = (const char*)__tmp;
		if (_len_str % sizeof(*str) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, str, _len_str)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_str);
		ocalloc_size -= _len_str;
	} else {
		ms->ms_str = NULL;
	}
	
	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_sgxssl_ftime(void* timeptr, uint32_t timeb_len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_timeptr = timeb_len;

	ms_u_sgxssl_ftime_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_sgxssl_ftime_t);
	void *__tmp = NULL;

	void *__tmp_timeptr = NULL;

	CHECK_ENCLAVE_POINTER(timeptr, _len_timeptr);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (timeptr != NULL) ? _len_timeptr : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_sgxssl_ftime_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_sgxssl_ftime_t));
	ocalloc_size -= sizeof(ms_u_sgxssl_ftime_t);

	if (timeptr != NULL) {
		ms->ms_timeptr = (void*)__tmp;
		__tmp_timeptr = __tmp;
		memset(__tmp_timeptr, 0, _len_timeptr);
		__tmp = (void *)((size_t)__tmp + _len_timeptr);
		ocalloc_size -= _len_timeptr;
	} else {
		ms->ms_timeptr = NULL;
	}
	
	ms->ms_timeb_len = timeb_len;
	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
		if (timeptr) {
			if (memcpy_s((void*)timeptr, _len_timeptr, __tmp_timeptr, _len_timeptr)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_cpuinfo = 4 * sizeof(int);

	ms_sgx_oc_cpuidex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_oc_cpuidex_t);
	void *__tmp = NULL;

	void *__tmp_cpuinfo = NULL;

	CHECK_ENCLAVE_POINTER(cpuinfo, _len_cpuinfo);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (cpuinfo != NULL) ? _len_cpuinfo : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_oc_cpuidex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_oc_cpuidex_t));
	ocalloc_size -= sizeof(ms_sgx_oc_cpuidex_t);

	if (cpuinfo != NULL) {
		ms->ms_cpuinfo = (int*)__tmp;
		__tmp_cpuinfo = __tmp;
		if (_len_cpuinfo % sizeof(*cpuinfo) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_cpuinfo, 0, _len_cpuinfo);
		__tmp = (void *)((size_t)__tmp + _len_cpuinfo);
		ocalloc_size -= _len_cpuinfo;
	} else {
		ms->ms_cpuinfo = NULL;
	}
	
	ms->ms_leaf = leaf;
	ms->ms_subleaf = subleaf;
	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
		if (cpuinfo) {
			if (memcpy_s((void*)cpuinfo, _len_cpuinfo, __tmp_cpuinfo, _len_cpuinfo)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_wait_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);

	ms->ms_self = self;
	status = sgx_ocall(3, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_set_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);

	ms->ms_waiter = waiter;
	status = sgx_ocall(4, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_setwait_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);

	ms->ms_waiter = waiter;
	ms->ms_self = self;
	status = sgx_ocall(5, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_waiters = total * sizeof(void*);

	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(waiters, _len_waiters);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (waiters != NULL) ? _len_waiters : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_multiple_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);

	if (waiters != NULL) {
		ms->ms_waiters = (const void**)__tmp;
		if (_len_waiters % sizeof(*waiters) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, waiters, _len_waiters)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_waiters);
		ocalloc_size -= _len_waiters;
	} else {
		ms->ms_waiters = NULL;
	}
	
	ms->ms_total = total;
	status = sgx_ocall(6, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

