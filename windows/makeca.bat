@echo off
set IP=127.0.0.1
set PORT=8888
set IP=192.168.1.49
set PORT=444
set SEN=key1.com
set ID=Client_identity
set PSK=0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20
REM
set fakeprivk=0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF
REM
echo generating public and private key within pNHSM at index 12
echo c11
echo .c11|openssl s_client -quiet -tls1_3 -connect %IP%:%PORT% -servername %SEN% -psk %PSK% -psk_identity %ID% -groups P-256 -cipher DHE -ciphersuites TLS_AES_128_CCM_SHA256 -no_ticket 2>nul 
echo g11
echo .g11|openssl s_client -quiet -tls1_3 -connect %IP%:%PORT% -servername %SEN% -psk %PSK% -psk_identity %ID% -groups P-256 -cipher DHE -ciphersuites TLS_AES_128_CCM_SHA256 -no_ticket 2>nul 
echo p11
echo .p11|openssl s_client -quiet -tls1_3 -connect %IP%:%PORT% -servername %SEN% -psk %PSK% -psk_identity %ID% -groups P-256 -cipher DHE -ciphersuites TLS_AES_128_CCM_SHA256 -no_ticket 2>nul 1>capub.txt
set /p pubk=<capub.txt
echo %pubk%
echo makek: making fakecakey.pem
makek %fakeprivk% %pubk% fakecakey.pem
openssl ec -in fakecakey.pem -text -noout
echo openssl: generating fakecacert.pem
openssl req -config openssl.cnf -x509  -new -sha256 -nodes -key fakecakey.pem -days 3650 -outform PEM -out fakecacert.pem
echo extract: compute hash for fakecacert.pem
extract fakecacert.pem 1>sha256.txt
set /p hash=<sha256.txt
echo SHA256=%hash%
echo signing hash with pNHSM key 11
echo s11%hash%
echo .s11%hash%|openssl s_client -quiet -tls1_3 -connect %IP%:%PORT% -servername %SEN% -psk %PSK% -psk_identity %ID% -groups P-256 -cipher DHE -ciphersuites TLS_AES_128_CCM_SHA256 -no_ticket 2>nul 1>sig.txt 
set /p der=<sig.txt
echo %der%
echo sig: replacing fakecacert.pem signature
sig fakecacert.pem sig.txt cacert.pem
copy cacert.pem cacert.crt
echo openssl: verify cacert.pem
openssl verify -CAfile cacert.pem  cacert.pem
echo =========================================================================================
echo CA Certificate in cacert.pem, Public key in fakecakey.pem, Private key in pNHSM index=11
echo =========================================================================================
PAUSE
echo generating public and private key within pNHSM at index 12
echo c12
echo .c12|openssl s_client -quiet -tls1_3 -connect %IP%:%PORT% -servername %SEN% -psk %PSK% -psk_identity %ID% -groups P-256 -cipher DHE -ciphersuites TLS_AES_128_CCM_SHA256 -no_ticket 2>nul 
echo g12
echo .g12|openssl s_client -quiet -tls1_3 -connect %IP%:%PORT% -servername %SEN% -psk %PSK% -psk_identity %ID% -groups P-256 -cipher DHE -ciphersuites TLS_AES_128_CCM_SHA256 -no_ticket 2>nul 
echo p12
echo .p12|openssl s_client -quiet -tls1_3 -connect %IP%:%PORT% -servername %SEN% -psk %PSK% -psk_identity %ID% -groups P-256 -cipher DHE -ciphersuites TLS_AES_128_CCM_SHA256 -no_ticket 2>nul 1>pub.txt
REM
set /p cpubk=<pub.txt
echo Pub= %cpubk%
REM
echo makek: making fakekey.pem file
makek %fakeprivk% %cpubk% fakekey.pem
openssl ec -in fakekey.pem -text -noout
echo making a fake CSR in clientreq2.pem
openssl  req -new -key fakekey.pem -passin pass:pascal -sha256  -out clientreq2.pem -config config_client.cnf -reqexts req_extensions
REM
echo extract: compute clientreq2.pem CSR hash
extract clientreq2.pem 1>sha256.txt
set /p hash=<sha256.txt
echo SHA256=%hash%
REM
echo sign: signing hash with pNHSM key 12
echo  s12%hash%
echo .s12%hash%|openssl s_client -quiet -tls1_3 -connect %IP%:%PORT% -servername %SEN% -psk %PSK% -psk_identity %ID% -groups P-256 -cipher DHE -ciphersuites TLS_AES_128_CCM_SHA256 -no_ticket 2>nul 1>nsig.txt 
REM
set /p der=<nsig.txt
echo signature DER= %der%
echo ===================================
echo sig: make new CSR in clientreq.pem
echo ===================================
sig clientreq2.pem nsig.txt clientreq.pem
PAUSE
echo openssl: generate fake certificate
openssl  x509 -days 3000 -req -in clientreq.pem -sha256 -extfile config_client.cnf -extensions certificate_extensions -CA cacert.pem -CAkey fakecakey.pem -CAcreateserial -out clientcert2.pem
echo extract: compute certificate hash
extract clientcert2.pem 1>sha256.txt
set /p hash=<sha256.txt
echo SHA256=%hash%
echo sign hash with pNHSM
echo s11%hash%
echo .s11%hash%|openssl s_client -quiet -tls1_3 -connect %IP%:%PORT% -servername %SEN% -psk %PSK% -psk_identity %ID% -groups P-256 -cipher DHE -ciphersuites TLS_AES_128_CCM_SHA256 -no_ticket 2>nul 1>nsig.txt 
set /p der=<nsig.txt
echo signature DER= %der%
echo sig: make new certificate in clientcert.pem
sig clientcert2.pem nsig.txt clientcert.pem
echo openssl: verify clientcert.pem
openssl verify -CAfile cacert.pem  clientcert.pem
copy clientcert.pem clientcert.crt
echo ==============================================================================================
echo Client certificate in clientcert.pem, Public key in fakekey.pem, Private key in pNHSM index=12
echo ==============================================================================================
PAUSE