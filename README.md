# sgx-keystore-openssl-engine
 
An OpenSSL engine implementation that utilizes a SGX keystore server. Current implementation only supports RSA keys up to 4096 bits.

### Requirements
* An Intel SGX capable CPU
* [Intel SGX SSL](https://github.com/intel/intel-sgx-ssl)
* Apache HTTP Web Server Source code
* OpenSSL 1.1+ 

### How to build
1. Download and Compile Intel SGX SSL
2. Modify the file `buildenv.mk` in the `src` folder so that the variable SGXSSL points to root folder of Intel SGX SSL.
3. Run `make` inside the `src` folder
4. Build the Apache Web Server with the SSL module enabled and with the following patch applied: [patch](https://github.com/andreluis034/sgx-keystore.openssl-engine/blob/master/patch/apache.patch)


### OpenSSL Configuration
You must add the compiled engine to your `openssl.cnf` file like so:
```
[openssl_init]
engines=engine_section

[engine_section]
sgxkeystore = sgxkeystore_section

[sgxkeystore_section]
engine_id = sgxkeystore
dynamic_path = /path/to/sgxkeystore.so
init = 0
```

### How to use
1. Generating a key:
    * Generating using OpenSSL normally ane seal it by running `./UtilityApp <key_file>`
    * or
    * Generate a RSA 4096 bit key using the Utility app `./UtilityApp --gen <key_file>`
2. Run the server
3. To use the key in the enclave the following path must be specified in Apache Config: `sgxkeystore:/path/to/key.pem.sealed>` 
