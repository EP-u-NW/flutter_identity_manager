cd output
openssl s_server -port 4453 -cert server-cert.pem -key server-key.pem -build_chain -CAfile ca-cert.pem -Verify 1