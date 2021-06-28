set OPENSSL_CONF=%CD%\openssl.cnf
mkdir output
cd output
type nul > index.txt
echo 01 > crlnumber

openssl genrsa -aes256 -out ca-key.pem 4096
openssl req -x509 -new -nodes -extensions v3_ca -key ca-key.pem -days 365 -out ca-cert.pem -sha512 -subj "/C=DE/ST=Baden-Wuerttemberg/L=Schorndorf/O=EPNW/CN=Test Authority"

openssl genrsa -out server-key.pem 4096
openssl req -new -key server-key.pem -out server.csr -sha512 -subj "/C=DE/ST=Baden-Wuerttemberg/L=Schorndorf/O=EPNW/CN=Test Server"
openssl x509 -req -in server.csr -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial -sha512 -days 365 -out server-cert.pem
del server.csr