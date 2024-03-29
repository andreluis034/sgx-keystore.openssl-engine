# sgx-keystore-openssl-engine
 
An OpenSSL engine implementation that utilizes a SGX keystore server. Current implementation only supports RSA keys up to 4096 bits.

The design, implementation and evaluation of the system is described in our Computer & Security journal 2021 [paper](https://jresende.github.io/paper/Hardening_SGX.pdf).


### Requirements
* An Intel SGX capable CPU
* [Intel(R) Software Guard Extensions for Linux* OS](https://github.com/intel/linux-sgx)
* [Intel SGX SSL](https://github.com/intel/intel-sgx-ssl)
* OpenSSL 1.1+ 

### How to build
1. Download and Compile Intel SGX SSL
2. Modify the file `buildenv.mk` in the `src` folder so that the variable SGXSSL points to root folder of Intel SGX SSL.
3. Run `make` inside the `src` folder


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
3. To use the key in the enclave the following path must be specified: `sgxkeystore:/path/to/key.pem.sealed>` 

### Integrating with Apache 
Build the Apache Web Server with the SSL module enabled and with the following patch applied: [patch](https://github.com/andreluis034/sgx-keystore.openssl-engine/blob/master/patch/apache.patch)

