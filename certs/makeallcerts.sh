#!/bin/bash

echo 
echo
read -p "MUST I CREATE SAMPLE SSL CERTICATES ? [Y|N] " yesnot
if [ "$yesnot" == "n" -o "$yesnot" == "N"  ];then 
    echo
    echo "You must properly configure server_cert, server_key and clients_cert directives in your config file ($1)"
    echo
    exit -255
fi

echo
echo
echo "#################################################"
echo "##    MAKING CERTIFICATION AUTHORITY CERTS      #"
echo "#################################################"

./makecerts.sh ca

echo
echo
echo "#################################################"
echo "##          MAKING SERVER SIDE CERTS            #"
echo "#################################################"

./makecerts.sh cert cakey.pem cacert.pem servercertkey.pem cervercertkey.pem

echo
echo
echo "#################################################"
echo "##          MAKING CLIENT SIDE CERTS            #"
echo "#################################################"

./makecerts.sh cert cakey.pem cacert.pem clientcertkey.pem clientcertkey.pem

echo
echo
echo "All certificates created:"
echo
echo "- Certification Authority:" 
echo -e "\t- cert file: $PWD/cacert.pem"
echo -e "\t- key file: $PWD/cakey.pem"
echo
echo -e "- Server Certificates:"
echo -e "\t- cert + key file: $PWD/servercertkey.pem"
echo
echo -e "- Client Certificates:"
echo -e "\t- cert + key file: $PWD/clientcertkey.pem"
# cacert.pem       cakey.pem
