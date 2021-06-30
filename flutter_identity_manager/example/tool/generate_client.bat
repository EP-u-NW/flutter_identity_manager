set OPENSSL_CONF=%CD%\openssl.cnf
cd output

openssl genrsa -out fake-key.pem 4096
openssl req -new -key fake-key.pem -out fake.csr -sha512 -subj "/C=DE/ST=Baden-Wuerttemberg/L=Schorndorf/O=EPNW/CN=Test Cert 1"
del fake-key.pem

echo Place a pem encoded pkcs1 public key here, name it input.pem and press enter
pause
REM openssl rsa -RSAPublicKey_in -in input.pem -pubout -out pkcs8.pem
openssl x509 -req -in fake.csr -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial -sha512 -days 365 -force_pubkey input.pem -out client-cert.pem
del fake.csr
del pkcs8.pem
echo Your certificate is in client-cert.pem!