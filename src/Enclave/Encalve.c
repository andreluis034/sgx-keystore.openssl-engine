#include "Engine_t.h"  /* print_string */
#include "sgx_tseal.h"
#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <string.h>

int printf(const char* fmt, ...)
{
    char buf[BUFSIZ] = { '\0' };
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
    return (int)strnlen(buf, BUFSIZ - 1) + 1;
}
void teste_ecall()
{
    printf("Hell from the enclave\n");

}


uint32_t get_sealed_data_size(uint32_t data_size)
{
    return sgx_calc_sealed_data_size(0, data_size);
}

sgx_status_t seal_data(uint8_t* clear, uint32_t clear_size, uint8_t* sealed_blob, uint32_t data_size)
{
    uint32_t sealed_data_size = sgx_calc_sealed_data_size(0, clear_size);
    if (sealed_data_size == UINT32_MAX)
        return SGX_ERROR_UNEXPECTED;
    if (sealed_data_size > data_size)
        return SGX_ERROR_INVALID_PARAMETER;

    uint8_t *temp_sealed_buf = (uint8_t *)malloc(sealed_data_size);
    if(temp_sealed_buf == NULL)
        return SGX_ERROR_OUT_OF_MEMORY;
    sgx_status_t  err = sgx_seal_data(0, NULL, (uint32_t)clear_size, (uint8_t *)clear, sealed_data_size, (sgx_sealed_data_t *)temp_sealed_buf);
    if (err == SGX_SUCCESS)
    {
        // Copy the sealed data to outside buffer
        memcpy(sealed_blob, temp_sealed_buf, sealed_data_size);
    }

    free(temp_sealed_buf);
    return err;
}


uint32_t get_decrypted_size( const uint8_t *sealed_blob, size_t data_size)
{
    ((void)data_size);
    return sgx_get_encrypt_txt_len((const sgx_sealed_data_t *)sealed_blob);
}


sgx_status_t unseal_data(const uint8_t *sealed_blob, size_t data_size, uint8_t *clear, size_t clear_size)
{
    uint32_t decrypt_data_len = sgx_get_encrypt_txt_len((const sgx_sealed_data_t *)sealed_blob);
    if (decrypt_data_len == UINT32_MAX)
        return SGX_ERROR_UNEXPECTED;
    if(decrypt_data_len > data_size || decrypt_data_len > clear_size)
        return SGX_ERROR_INVALID_PARAMETER;


    sgx_status_t ret = sgx_unseal_data((const sgx_sealed_data_t *)sealed_blob, NULL, NULL, clear, &decrypt_data_len);
    if (ret != SGX_SUCCESS)
    {
        return ret;
    }
    return ret;
}