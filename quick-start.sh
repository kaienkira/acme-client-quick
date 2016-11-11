#!/bin/bash

# check root
if [ `id -u` != '0' ]
then
    echo "must run by root"
    exit 1
fi

script_name=`basename $0`
script_abs_name=`readlink -f $0`
script_path=`dirname $script_abs_name`

# get domain
if [ ! -f ${script_path}/domain.txt ]
then
    echo "can not find domain.txt, please put your domain in domain.txt"
    exit 1
fi
domain_list=`cat ${script_path}/domain.txt`

# search openssl.cnf
openssl_cnf_file_list="
/etc/ssl/openssl.cnf
/etc/pki/tls/openssl.cnf"

for file in $openssl_cnf_file_list
do
    if [ -f $file ]
    then
        openssl_cnf_file=$file
        break
    fi
done

if [ -z "$openssl_cnf_file" ]
then
    echo "can not find openssl.cnf"
    exit 1
fi

# create work dir
mkdir -p ${script_path}/work
mkdir -p ${script_path}/work/acme-challenge
mkdir -p ${script_path}/work/log
mkdir -p ${script_path}/work/tmp
mkdir -p ${script_path}/cert

# generate account private key
if [ ! -f ${script_path}/cert/account.key ]
then
    openssl genrsa -out ${script_path}/cert/account.key 4096
fi

# generate domain private key
if [ ! -f ${script_path}/cert/ssl.key ]
then
    openssl genrsa -out ${script_path}/cert/ssl.key 2048
fi

# generate csr from domain private key
if [ ! -f ${script_path}/cert/domain.csr ]
then
    for domain in $domain_list
    do
        alt_name="$alt_name""DNS:$domain,"
    done

    cp $openssl_cnf_file ${script_path}/cert/domain.conf
    printf "[SAN]\nsubjectAltName=" >> ${script_path}/cert/domain.conf
    printf "$alt_name" | sed 's/,$//g' >> ${script_path}/cert/domain.conf

    openssl req -new -sha256 \
                -key cert/ssl.key \
                -out ${script_path}/cert/domain.csr \
                -subj "/" -reqexts SAN \
                -config ${script_path}/cert/domain.conf
fi

# start cert-nginx process
bash ${script_path}/cert-nginx.init start
# setup cleanup function
do_cleanup() {
    bash ${script_path}/cert-nginx.init stop
}
trap do_cleanup EXIT

# get cert
for domain in $domain_list
do
    domain_param="$domain_param;""$domain"
done
php ${script_path}/acme-client.php \
    -a ${script_path}/cert/account.key \
    -r ${script_path}/cert/domain.csr \
    -d $domain_param \
    -c ${script_path}/work/acme-challenge \
    -o ${script_path}/cert/ssl.crt.new
if [ $? -ne 0 ]
then
    exit 1
fi

cp ${script_path}/cert/ssl.crt.new \
   ${script_path}/cert/ssl.crt

rm -f -- ${script_path}/work/acme-challenge/*

exit 0
