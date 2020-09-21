FROM ubuntu:18.04 as builder

RUN apt-get update && apt-get install  -y \
    autoconf \
    automake \
    build-essential \
    cmake \
    curl \
    debhelper \
    git \
    libcurl4-openssl-dev \
    libprotobuf-dev \
    libssl-dev \
    libtool \
    lsb-release \
    ocaml \
    ocamlbuild \
    protobuf-compiler \
    python \
    wget 


RUN git clone https://github.com/intel/linux-sgx
WORKDIR /linux-sgx
RUN ./download_prebuilt.sh

RUN make sdk_install_pkg_no_mitigation

WORKDIR /opt/intel
RUN sh -c 'echo yes | /linux-sgx/linux/installer/bin/sgx_linux_x64_sdk_*.bin'

WORKDIR /linux-sgx
RUN make psw_install_pkg

WORKDIR /
RUN git clone https://github.com/intel/intel-sgx-ssl
WORKDIR /intel-sgx-ssl/openssl_source
RUN wget https://www.openssl.org/source/openssl-1.1.1g.tar.gz
WORKDIR /intel-sgx-ssl
RUN make

WORKDIR /
RUN git clone https://github.com/andreluis034/sgx-keystore.openssl-engine/
WORKDIR /sgx-keystore.openssl-engine/src
RUN SGXSSL=/intel-sgx-ssl/Linux  make

FROM ubuntu:18.04 as aesm
RUN apt-get update && apt-get install -y \
    libcurl4 \
    libprotobuf10 \
    libssl1.1 \
    make \
    module-init-tools

WORKDIR /installer
COPY --from=builder /linux-sgx/linux/installer/bin/*.bin ./
RUN ./sgx_linux_x64_psw*.bin --no-start-aesm
USER aesmd
WORKDIR /opt/intel/sgxpsw/aesm/
ENV LD_LIBRARY_PATH=.
CMD ./aesm_service --no-daemon




#Setup keystore container
FROM ubuntu:18.04 as keystore
RUN apt-get update && apt-get install -y make module-init-tools libssl1.1 libprotobuf10 libcurl4 build-essential wget libapr1 libapr1-dev  libaprutil1-dev libpcre3-dev
WORKDIR /opt/intel
COPY --from=builder /linux-sgx/linux/installer/bin/*.bin ./
RUN ./sgx_linux_x64_psw*.bin --no-start-aesm
RUN sh -c 'echo yes | ./sgx_linux_x64_sdk_*.bin'
WORKDIR /opt/keystore
COPY --from=builder /sgx-keystore.openssl-engine/src/keystore_server .
COPY --from=builder /sgx-keystore.openssl-engine/src/Enclave.signed.so .
RUN mkdir -p /var/run/sgx-keystore/
RUN chmod +x /opt/keystore/keystore_server
CMD ./keystore_server


#Setup apache container

FROM ubuntu:18.04 as apache
RUN apt-get update && apt-get install -y libssl-dev make module-init-tools libssl1.1 libprotobuf10 libcurl4 build-essential wget libapr1 libapr1-dev  libaprutil1-dev libpcre3-dev
WORKDIR /opt/intel
COPY --from=builder /linux-sgx/linux/installer/bin/*.bin ./
RUN ./sgx_linux_x64_psw*.bin --no-start-aesm
RUN sh -c 'echo yes | ./sgx_linux_x64_sdk_*.bin'
WORKDIR /root
RUN wget https://mirrors.up.pt/pub/apache//httpd/httpd-2.4.43.tar.gz
RUN tar xvf httpd-2.4.43.tar.gz
WORKDIR /root/httpd-2.4.43
RUN wget https://gist.githubusercontent.com/andreluis034/4ad9f1eb945b4310f3f380e7460a15bb/raw/64125f3f0d6840aa8f72118af86713cf8f6da66a/ssl_util.c.patch
RUN patch modules/ssl/ssl_util.c ssl_util.c.patch
RUN ./configure --prefix=/opt/httpd --enable-ssl --enable-so
RUN make
RUN make install
WORKDIR /opt/httpd/bin
RUN rm -rf /root/httpd-2.4.43 /root/httpd-2.4.43.tar.gz
COPY --from=builder /linux-sgx/sgx-keystore.openssl-engine/src/Engine.so /opt/Engine.so
RUN ln -s /opt/Engine.so /usr/lib/x86_64-linux-gnu/engines-1.1/sgxkeystore.so
SHELL ["/bin/bash", "-c"]
RUN echo $'[openssl_init]\n\
engines=engine_section\n\
\n\
[engine_section]\n\
sgxkeystore = sgxkeystore_section\n\
\n\
[sgxkeystore_section]\n\
engine_id = sgxkeystore\n\
dynamic_path = /opt/Engine.so\n\
init = 0\n\
' >> /etc/ssl/openssl.cnf

CMD ./httpd -DFOREGROUND