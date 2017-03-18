#!/bin/bash
cd keys
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -outform DER -pubout -out public.der
openssl pkcs8 -topk8 -inform PEM -outform DER -in private.pem -out private.der -nocrypt
rm -f private.pem
cd ..
