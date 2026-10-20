#
IP=192.168.1.49
PORT=444
SEN=key1.com
ID=Client_identity
PSK=0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20
#
echo generating public and private key within pNHSM at index 21
echo c21
echo -ne ".c21\r\n" | openssl  s_client -quiet -connect $IP:$PORT -servername $SEN -psk_identity $ID -psk $PSK -tls1_3  -groups P-256 -cipher DHE -ciphersuites  TLS_AES_128_CCM_SHA256 -no_ticket  2>/dev/null
echo g21
echo -ne ".g21\r\n" | openssl  s_client -quiet -connect $IP:$PORT -servername $SEN -psk_identity $ID -psk $PSK -tls1_3  -groups P-256 -cipher DHE -ciphersuites  TLS_AES_128_CCM_SHA256 -no_ticket  2>/dev/null
echo p2100
echo -ne ".p2100\r\n" | openssl  s_client -quiet -connect $IP:$PORT -servername $SEN -psk_identity $ID -psk $PSK -tls1_3  -groups P-256 -cipher DHE -ciphersuites  TLS_AES_128_CCM_SHA256 -no_ticket 1>mod.txt 2>/dev/null
echo p2101
echo -ne ".p2101\r\n" | openssl  s_client -quiet -connect $IP:$PORT -servername $SEN -psk_identity $ID -psk $PSK -tls1_3  -groups P-256 -cipher DHE -ciphersuites  TLS_AES_128_CCM_SHA256 -no_ticket 1>expo.txt 2>/dev/null
#
modk=$(< mod.txt)
expok=$(< expo.txt)
echo makekrsa: making fakecakey.pem
./makekrsa $modk $expok fakecakey.pem
openssl rsa -in fakecakey.pem -text -noout
echo openssl: generating fakecacert.pem
openssl req -config openssl.cnf -x509  -new -sha256 -nodes -key fakecakey.pem -days 3650 -outform PEM -out fakecacert.pem
echo extract: compute hash for fakecacert.pem
./extract fakecacert.pem 1>sha256.txt
hash=$(< sha256.txt)
echo SHA256=$hash
echo signing hash with pNHSM key 11
echo s21$hash
echo -ne ".s21$hash\r\n" | openssl  s_client -quiet -connect $IP:$PORT -servername $SEN -psk_identity $ID -psk $PSK -tls1_3  -groups P-256 -cipher DHE -ciphersuites  TLS_AES_128_CCM_SHA256 -no_ticket 1>sig.txt 2>/dev/null
der=$(< sig.txt)
echo $der
echo sig2: replacing fakecacert.pem signature
./sig2 fakecacert.pem sig.txt cacert.pem
cp cacert.pem cacert.crt
echo openssl: verify cacert.pem
openssl verify -CAfile cacert.pem  cacert.pem
echo =========================================================================================
echo CA Certificate in cacert.pem, Public key in fakecakey.pem, Private key in pNHSM index=21
echo =========================================================================================
read -p "Press RETURN"
echo generating public and private key within pNHSM at index 22
echo c12
echo -ne ".c22\r\n" | openssl  s_client -quiet -connect $IP:$PORT -servername $SEN -psk_identity $ID -psk $PSK -tls1_3  -groups P-256 -cipher DHE -ciphersuites  TLS_AES_128_CCM_SHA256 -no_ticket  2>/dev/null
echo g12
echo -ne ".g22\r\n" | openssl  s_client -quiet -connect $IP:$PORT -servername $SEN -psk_identity $ID -psk $PSK -tls1_3  -groups P-256 -cipher DHE -ciphersuites  TLS_AES_128_CCM_SHA256 -no_ticket  2>/dev/null
echo p2200
echo -ne ".p2200\r\n" | openssl  s_client -quiet -connect $IP:$PORT -servername $SEN -psk_identity $ID -psk $PSK -tls1_3  -groups P-256 -cipher DHE -ciphersuites  TLS_AES_128_CCM_SHA256 -no_ticket 1>mod.txt 2>/dev/null
echo p2201
echo -ne ".p2201\r\n" | openssl  s_client -quiet -connect $IP:$PORT -servername $SEN -psk_identity $ID -psk $PSK -tls1_3  -groups P-256 -cipher DHE -ciphersuites  TLS_AES_128_CCM_SHA256 -no_ticket 1>expo.txt 2>/dev/null
REM
modk=$(< mod.txt)
expok=$(< expo.txt)
#
echo makekrsa: making fakekey.pem file
./makekrsa $modk $expok fakekey.pem
openssl ec -in fakekey.pem -text -noout
echo making a fake CSR in clientreq2.pem
openssl  req -new -key fakekey.pem -passin pass:pascal -sha256  -out clientreq2.pem -config config_client.cnf -reqexts req_extensions
#
echo extract: compute clientreq2.pem CSR hash
./extract clientreq2.pem 1>sha256.txt
hash=$(< sha256.txt)
echo SHA256=$hash
#
echo sign: signing hash with pNHSM key 22
echo  s22$hash
echo -ne ".s22$hash\r\n" | openssl  s_client -quiet -connect $IP:$PORT -servername $SEN -psk_identity $ID -psk $PSK -tls1_3  -groups P-256 -cipher DHE -ciphersuites  TLS_AES_128_CCM_SHA256 -no_ticket 1>nsig.txt 2>/dev/null
#
der=$(< nsig.txt)
echo signature DER= $der
echo ===================================
echo sig2: make new CSR in clientreq.pem
echo ===================================
./sig2 clientreq2.pem nsig.txt clientreq.pem
read -p "Press RETURN"
echo openssl: generate fake certificate
openssl  x509 -days 3000 -req -in clientreq.pem -sha256 -extfile config_client.cnf -extensions certificate_extensions -CA cacert.pem -CAkey fakecakey.pem -CAcreateserial -out clientcert2.pem
echo extract: compute certificate hash
./extract clientcert2.pem 1>sha256.txt
hash=$(< sha256.txt)
echo SHA256=$hash
echo sign hash with pNHSM
echo s21$hash
echo -ne ".s21$hash\r\n" | openssl  s_client -quiet -connect $IP:$PORT -servername $SEN -psk_identity $ID -psk $PSK -tls1_3  -groups P-256 -cipher DHE -ciphersuites  TLS_AES_128_CCM_SHA256 -no_ticket 1>nsig.txt 2>/dev/null
der=$(< nsig.txt)
echo signature DER= $der
echo sig2: make new certificate in clientcert.pem
./sig2 clientcert2.pem nsig.txt clientcert.pem
echo openssl: verify clientcert.pem
openssl verify -CAfile cacert.pem  clientcert.pem
cp clientcert.pem clientcert.crt
echo ==============================================================================================
echo Client certificate in clientcert.pem, Public key in fakekey.pem, Private key in pNHSM index=22
echo ==============================================================================================


