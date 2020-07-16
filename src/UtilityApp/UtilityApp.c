#include "sgx_urts.h"
#include "Engine_u.h"
#include <stdio.h>
#include <sys/stat.h>


#define ENCLAVE_NAME "Enclave.signed.so"



/* OCall functions */
void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */
    fprintf(stdout, "%s", str);
}



/* Initialize the enclave:
*   Call sgx_create_enclave to initialize an enclave instance
*/
static sgx_status_t initialize_enclave(const char* enclave_path, sgx_enclave_id_t *eid)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    /* Call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(enclave_path, SGX_DEBUG_FLAG, NULL, NULL, eid, NULL);
    if (ret != SGX_SUCCESS) {
        return ret;
    }
    return SGX_SUCCESS;
}

/**
 *  public uint32_t get_sealed_data_size(uint32_t data_size);
 *  public sgx_status_t seal_data([in, size=clear_size]uint8_t* clear, uint32_t clear_size, [out, size=data_size] uint8_t* sealed_blob, uint32_t data_size);
*/

int main(int argc, char* argv[])
{
    (void)argc, (void)argv;
    struct stat st;
	printf("%d\n", argc);
	if (argc == 3 && strcmp(argv[1], "--seal-key") == 0)
	{
	    sgx_enclave_id_t eid_seal = 0;

        if (stat(argv[2], &st) != 0)
        {
            printf("Failed to get key size\n");
			return -1;
        }
        FILE* fd = fopen(argv[2], "rb");
        if (fd == NULL)
        {
            printf("Failed to open file\n");
			return -1;
        }
		sgx_status_t ret = initialize_enclave(ENCLAVE_NAME, &eid_seal);
		if (ret != SGX_SUCCESS)
		{
            printf("Failed to init sgx %x\n", ret);
			return -1;
		}
        char* data = malloc(st.st_size + 1);
        int read = 0;
        if ((read = fread(data, 1, st.st_size + 1, fd)) != st.st_size)
        {
            free(data);
            printf("Failed to read file\n");
            return -1;
        }
        fclose(fd);
        
        
		int filenamelen =  strlen(argv[2]);
		char*outputName = (char*)malloc(filenamelen + (strlen(".sealed")) + 2);
		memset(outputName, 0, filenamelen + (strlen(".sealed")) + 2);
		strcat(outputName, argv[2]);
		strcat(outputName, ".sealed");


        uint32_t sealed_data_size = 0;
        get_sealed_data_size(eid_seal, &sealed_data_size, (uint32_t)read);
        uint8_t *temp_sealed_buf = (uint8_t *)malloc(sealed_data_size);
        sgx_status_t retval;
        ret = seal_data(eid_seal, &retval, (uint8_t*)data, (uint32_t) read, temp_sealed_buf, sealed_data_size);
        free(data);
        if (ret != SGX_SUCCESS)
        {
            free(temp_sealed_buf);
            free(outputName);
            return -1;
        }
        printf("%s\n", outputName);
        fd = fopen(outputName, "wb");
        if (fd != NULL)
        {   
            fwrite(temp_sealed_buf, 1, sealed_data_size, fd);
            fclose(fd);
        }
        else
        {
            printf("Failed to seal file\n");
        }
        
        
        free(outputName);
        free(temp_sealed_buf);

    	sgx_destroy_enclave(eid_seal);

		return 0;
	}
	
    return 0;
}

