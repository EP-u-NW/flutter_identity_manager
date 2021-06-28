set OPENSSL_CONF=%CD%\\openssl.conf
mkdir output
cd output
type nul > index.txt
echo 01 > crlnumber

openssl genrsa -aes256 -out ca-key.pem 4096 \
&& openssl req -x509 -new -nodes -extensions v3_ca -key ca-key.pem -days 365 -out ca-cert.pem -sha512 -subj "/C=DE/ST=Baden-Wuerttemberg/L=Schorndorf/O=EPNW/CN=Test Authority"

openssl genrsa -out fake-key.pem 4096 \
&& openssl req -new -key fake-key.pem -out fake.csr -sha512 -subj "/C=DE/ST=Baden-Wuerttemberg/L=Schorndorf/O=EPNW/CN=Test Cert 1" \
&& rm fake-key.pem

echo Place a pem encoded pkcs1 public key here, name it input.pem and press enter
pause
openssl x509 -req -in fake.csr -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial -sha512 -days 365 -force_pubkey input.pem -out client-cert.pem

openssl genrsa -out server-key.pem 4096 \
&& openssl req -new -key server-key.pem -out server.csr -sha512 -subj "/C=DE/ST=Baden-Wuerttemberg/L=Schorndorf/O=EPNW/CN=Test Server" \
&& openssl x509 -req -in server.csr -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial -sha512 -days 365 -out server-cert.pem \
&& rm server.csr

openssl s_server -port 4453 -cert server-cert.pem -key server-key.pem -build_chain -CAfile ca-cert.pem -Verify