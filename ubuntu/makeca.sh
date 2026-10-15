#
IP=192.168.1.49
PORT=444
SEN=key1.com
ID=Client_identity
PSK=0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20
#
fakeprivk=0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF
#
echo generating public and private key within pNHSM at index 11
echo c11
echo -ne ".c11\r\n" | openssl  s_client -quiet -connect $IP:$PORT -servername $SEN -psk_identity $ID -psk $PSK -tls1_3  -groups P-256 -cipher DHE -ciphersuites  TLS_AES_128_CCM_SHA256 -no_ticket  2>/dev/null
echo g11
echo -ne ".g11\r\n" | openssl  s_client -quiet -connect $IP:$PORT -servername $SEN -psk_identity $ID -psk $PSK -tls1_3  -groups P-256 -cipher DHE -ciphersuites  TLS_AES_128_CCM_SHA256 -no_ticket  2>/dev/null
echo p11
echo -ne ".p11\r\n" | openssl  s_client -quiet -connect $IP:$PORT -servername $SEN -psk_identity $ID -psk $PSK -tls1_3  -groups P-256 -cipher DHE -ciphersuites  TLS_AES_128_CCM_SHA256 -no_ticket 1>capub.txt 2>/dev/null
pubk=$(< capub.txt)
echo makek: making fakecakey.pem
./makek $fakeprivk $pubk fakecakey.pem
openssl ec -in fakecakey.pem -text -noout
echo openssl: generating fakecacert.pem
openssl req -config openssl.cnf -x509  -new -sha256 -nodes -key fakecakey.pem -days 3650 -outform PEM -out fakecacert.pem
echo extract: compute hash for fakecacert.pem
./extract fakecacert.pem 1>sha256.txt
hash=$(< sha256.txt)
echo SHA256=$hash
echo signing hash with pNHSM key 11
echo s11$hash
echo -ne ".s11$hash\r\n" | openssl  s_client -quiet -connect $IP:$PORT -servername $SEN -psk_identity $ID -psk $PSK -tls1_3  -groups P-256 -cipher DHE -ciphersuites  TLS_AES_128_CCM_SHA256 -no_ticket 1>sig.txt 2>/dev/null
der=$(< sig.txt)
echo $der
echo sig: replacing fakecacert.pem signature
./sig fakecacert.pem sig.txt cacert.pem
cp cacert.pem cacert.crt
echo openssl: verify cacert.pem
openssl verify -CAfile cacert.pem  cacert.pem
echo =========================================================================================
echo CA Certificate in cacert.pem, Public key in fakecakey.pem, Private key in pNHSM index=11
echo =========================================================================================
read -p "Press RETURN"
echo generating public and private key within pNHSM at index 12
echo c12
echo -ne ".c12\r\n" | openssl  s_client -quiet -connect $IP:$PORT -servername $SEN -psk_identity $ID -psk $PSK -tls1_3  -groups P-256 -cipher DHE -ciphersuites  TLS_AES_128_CCM_SHA256 -no_ticket  2>/dev/null
echo g12
echo -ne ".g12\r\n" | openssl  s_client -quiet -connect $IP:$PORT -servername $SEN -psk_identity $ID -psk $PSK -tls1_3  -groups P-256 -cipher DHE -ciphersuites  TLS_AES_128_CCM_SHA256 -no_ticket  2>/dev/null
echo p12
echo -ne ".p12\r\n" | openssl  s_client -quiet -connect $IP:$PORT -servername $SEN -psk_identity $ID -psk $PSK -tls1_3  -groups P-256 -cipher DHE -ciphersuites  TLS_AES_128_CCM_SHA256 -no_ticket 1>pub.txt 2>/dev/null
REM
cpubk=$(< pub.txt)
echo Pub= $cpubk
#
echo makek: making fakekey.pem file
./makek $fakeprivk $cpubk fakekey.pem
openssl ec -in fakekey.pem -text -noout
echo making a fake CSR in clientreq2.pem
openssl  req -new -key fakekey.pem -passin pass:pascal -sha256  -out clientreq2.pem -config config_client.cnf -reqexts req_extensions
#
echo extract: compute clientreq2.pem CSR hash
./extract clientreq2.pem 1>sha256.txt
hash=$(< sha256.txt)
echo SHA256=$hash
#
echo sign: signing hash with pNHSM key 12
echo  s12$hash
echo -ne ".s12$hash\r\n" | openssl  s_client -quiet -connect $IP:$PORT -servername $SEN -psk_identity $ID -psk $PSK -tls1_3  -groups P-256 -cipher DHE -ciphersuites  TLS_AES_128_CCM_SHA256 -no_ticket 1>nsig.txt 2>/dev/null
#
der=$(< nsig.txt)
echo signature DER= $der
echo ===================================
echo sig: make new CSR in clientreq.pem
echo ===================================
./sig clientreq2.pem nsig.txt clientreq.pem
read -p "Press RETURN"
echo openssl: generate fake certificate
openssl  x509 -days 3000 -req -in clientreq.pem -sha256 -extfile config_client.cnf -extensions certificate_extensions -CA cacert.pem -CAkey fakecakey.pem -CAcreateserial -out clientcert2.pem
echo extract: compute certificate hash
./extract clientcert2.pem 1>sha256.txt
hash=$(< sha256.txt)
echo SHA256=$hash
echo sign hash with pNHSM
echo s11$hash
echo -ne ".s11$hash\r\n" | openssl  s_client -quiet -connect $IP:$PORT -servername $SEN -psk_identity $ID -psk $PSK -tls1_3  -groups P-256 -cipher DHE -ciphersuites  TLS_AES_128_CCM_SHA256 -no_ticket 1>nsig.txt 2>/dev/null
der=$(< nsig.txt)
echo signature DER= $der
echo sig: make new certificate in clientcert.pem
./sig clientcert2.pem nsig.txt clientcert.pem
echo openssl: verify clientcert.pem
openssl verify -CAfile cacert.pem  clientcert.pem
cp clientcert.pem clientcert.crt
echo ==============================================================================================
echo Client certificate in clientcert.pem, Public key in fakekey.pem, Private key in pNHSM index=12
echo ==============================================================================================


