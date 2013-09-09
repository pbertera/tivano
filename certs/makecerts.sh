#!/bin/sh
#
# A script generates self-signed root CA cert/key and certs based on
# script published by Gong Cheng on Freesoftwaremagazine.com: http://fsmsh.com/2964
# certs generated are for testing purposes only!
#
# Author: Gong Cheng, chengg11@yahoo.com, Aug. 2008
# Modified by Pietro Bertera, pietro@bertera.it
#
# You are free to use this script in anyway but absolutely no warranty!
#

usage ()
{
    echo "Usage:"
    echo "  $0 ca [<ca key> <ca cert>]"
    echo "  $0 cert <ca key> <ca cert> [ <cert key>  <cert cert> ]"
}

gen_config ()
{
    echo "Generating ca_config.cnf"
    cat > ca_config.cnf <<EOT
HOME                    = .
RANDFILE                = $ENV::HOME/.rnd
[ ca ]
default_ca      = CA_default
[ CA_default ]
certs           = .
crl_dir         = .
database        = index.txt
new_certs_dir   = .
certificate     = $2
serial          = serial
private_key     = $1
RANDFILE        = .rand
x509_extensions = usr_cert
name_opt        = ca_default
cert_opt        = ca_default
default_days    = 365
default_crl_days= 30
default_md      = sha1
preserve        = no
policy          = policy_match
[ policy_match ]
countryName             = match
stateOrProvinceName     = match
organizationName        = match
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional
[ policy_anything ]
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional
[ req ]
default_bits            = 1024
default_md              = sha1
default_keyfile         = privkey.pem
distinguished_name      = req_distinguished_name
attributes              = req_attributes
x509_extensions = v3_ca
string_mask = MASK:0x2002
[ req_distinguished_name ]
countryName                     = Country Name (2 letter code)
countryName_default             = IT
countryName_min                 = 2
countryName_max                 = 2
stateOrProvinceName             = State or Province Name (full name)
stateOrProvinceName_default     = Milan
localityName                    = Locality Name (eg, city)
localityName_default            = Milan
0.organizationName              = Organization Name (eg, company)
0.organizationName_default      = My Company Ltd
organizationalUnitName          = Organizational Unit Name (eg, section)
commonName                      = Common Name (eg, your name or your server's hostname)
commonName_max                  = 64
emailAddress                    = Email Address
emailAddress_max                = 64
[ req_attributes ]
challengePassword               = A challenge password
challengePassword_min           = 4
challengePassword_max           = 20
unstructuredName                = An optional company name
[ usr_cert ]
basicConstraints=CA:FALSE
nsComment                       = "OpenSSL Generated Certificate"
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
[ v3_ca ]
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer:always
basicConstraints = CA:true
EOT
}

gen_ca ()
{
    echo "generating CA cert:$1, $2";
    openssl req -config ca_config.cnf -new -x509 -extensions v3_ca -days 3650 -passin pass:whatever -passout pass:whatever -keyout $1 -out $2
}

gen_cert ()
{
    echo "generating certificate:$1, $2";
    openssl req -config ca_config.cnf -new -nodes -keyout $1 -out temp.csr -days 3650

    openssl ca -config ca_config.cnf -policy policy_anything -out $2 -days 3650 -key whatever -infiles temp.csr

    rm temp.csr
}

#at least one argument
if [ $# -lt 1 ]
then
    usage
    exit 1
fi


#default file names if not specified in command line
ca_key_file=cakey.pem
ca_cert_file=cacert.pem
key_file=key.pem
cert_file=cert.pem

case $1 in
ca)
    if [ x$2 != x ]
    then
        ca_key_file=$2
        ca_cert_file=$3
    fi
    gen_config $ca_key_file $ca_cert_file
    gen_ca $ca_key_file $ca_cert_file
    if [ -f $ca_key_file -a -f $ca_cert_file ]
    then
        echo "Generated files: key: $ca_key_file , cert: $ca_cert_file"
    else
        echo "Failed to generated all files"
    fi
    ;;
cert)
    if [ $# -ne 3 -a $# -ne 5 ]
    then
        usage
        exit 1
    fi
    ca_key_file=$2
    ca_cert_file=$3
    gen_config $ca_key_file $ca_cert_file
    if [ x$4 != x ]
    then
        key_file=$4
        cert_file=$5
    fi
    if [ ! -f index.txt ]
    then
        touch index.txt
    fi

    if [ ! -f serial ]
    then
        echo 01 > serial
    fi
    gen_cert $key_file $cert_file
    if [ -f $key_file -a -f $cert_file ]
    then
        echo "Generated files: key: $key_file , cert: $cert_file"
    else
        echo "Failed to generated all files"
    fi
    if [ $cert_file != `cat serial.old`.pem ]
    then
        rm `cat serial.old`.pem
    fi
    ;;
*) usage; exit 1;;
esac



#cleanups
rm ca_config.cnf

