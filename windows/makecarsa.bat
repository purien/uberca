@echo off
REM
set IP=192.168.1.49
set PORT=444
set SEN=key1.com
REM
set ID=Client_identity
set PSK=0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20
REM
echo generating public and private key within pNHSM at index 21
echo c21
echo .c21|openssl s_client -quiet -tls1_3 -connect %IP%:%PORT% -servername %SEN% -psk %PSK% -psk_identity %ID% -groups P-256 -cipher DHE -ciphersuites TLS_AES_128_CCM_SHA256 -no_ticket 2>nul 
echo g21
REM echo .g21|openssl s_client -quiet -tls1_3 -connect %IP%:%PORT% -servername %SEN% -psk %PSK% -psk_identity %ID% -groups P-256 -cipher DHE -ciphersuites TLS_AES_128_CCM_SHA256 -no_ticket 2>nul 
tlsse -c -H #.g21 -H quiet -H timeout10000 -h %IP% -p %PORT%  -S %SEN% -H identity%ID% -H psk%PSK% 
echo p2100
REM echo .p2100|openssl s_client -quiet -tls1_3 -connect %IP%:%PORT% -servername %SEN% -psk %PSK% -psk_identity %ID% -groups P-256 -cipher DHE -ciphersuites TLS_AES_128_CCM_SHA256 -no_ticket 2>nul 1>mod.txt
tlsse -c -H #.p2100 -H quiet -H timeout10000 -h %IP% -p %PORT%  -S %SEN% -H identity%ID% -H psk%PSK% 2>nul 1>mod.txt
echo p2101
REM echo .p2101|openssl s_client -quiet -tls1_3 -connect %IP%:%PORT% -servername %SEN% -psk %PSK% -psk_identity %ID% -groups P-256 -cipher DHE -ciphersuites TLS_AES_128_CCM_SHA256 -no_ticket 2>nul 1>expo.txt
tlsse -c -H #.p2101 -H quiet -H timeout10000 -h %IP% -p %PORT%  -S %SEN% -H identity%ID% -H psk%PSK% 2>nul 1>expo.txt
set /p modk=<mod.txt
set /p expok=<expo.txt
REM echo expo= %expok%  modulo= %modk%
echo makekrsa: making fakecakey.pem
makekrsa %modk% %expok% fakecakey.pem
openssl rsa -in fakecakey.pem -text -noout
echo openssl: generating fakecacert.pem
openssl req -config openssl.cnf -x509  -new -sha256 -nodes -key fakecakey.pem -days 3650 -outform PEM -out fakecacert.pem
echo extract: compute hash for fakecacert.pem
extract fakecacert.pem 1>sha256.txt
set /p hash=<sha256.txt
echo SHA256=%hash%
echo signing hash with pNHSM key 21
echo s21%hash%
REM echo .s21%hash%|openssl s_client -quiet -tls1_3 -connect %IP%:%PORT% -servername %SEN% -psk %PSK% -psk_identity %ID% -groups P-256 -cipher DHE -ciphersuites TLS_AES_128_CCM_SHA256 -no_ticket 2>nul 1>sig.txt
tlsse -c -H #.s21%hash% -H quiet -H timeout10000 -h %IP% -p %PORT%  -S %SEN% -H identity%ID% -H psk%PSK% 2>nul 1>sig.txt
REM
set /p der=<sig.txt
echo signature= %der%
echo sig: replacing fakecacert.pem signature
sig2 fakecacert.pem sig.txt cacert.pem
copy cacert.pem cacert.crt
echo openssl: verify cacert.pem
openssl verify -CAfile cacert.pem  cacert.pem
echo =========================================================================================
echo CA Certificate in cacert.pem, Public key in fakecakey.pem, Private key in pNHSM index=21
echo =========================================================================================
PAUSE
REM
echo generating public and private key within pNHSM at index 22
echo c22
echo .c22|openssl s_client -quiet -tls1_3 -connect %IP%:%PORT% -servername %SEN% -psk %PSK% -psk_identity %ID% -groups P-256 -cipher DHE -ciphersuites TLS_AES_128_CCM_SHA256 -no_ticket 2>nul 
echo g22
REM echo .g22|openssl s_client -quiet -tls1_3 -connect %IP%:%PORT% -servername %SEN% -psk %PSK% -psk_identity %ID% -groups P-256 -cipher DHE -ciphersuites TLS_AES_128_CCM_SHA256 -no_ticket 2>nul 
tlsse -c -H #.g22 -H quiet -H timeout10000 -h %IP% -p %PORT%  -S %SEN% -H identity%ID% -H psk%PSK% 
echo p2200
REM echo .p2200|openssl s_client -quiet -tls1_3 -connect %IP%:%PORT% -servername %SEN% -psk %PSK% -psk_identity %ID% -groups P-256 -cipher DHE -ciphersuites TLS_AES_128_CCM_SHA256 -no_ticket 2>nul 1>mod.txt
tlsse -c -H #.p2200 -H quiet -H timeout10000 -h %IP% -p %PORT%  -S %SEN% -H identity%ID% -H psk%PSK% 2>nul 1>mod.txt
echo p2201
REM echo .p2201|openssl s_client -quiet -tls1_3 -connect %IP%:%PORT% -servername %SEN% -psk %PSK% -psk_identity %ID% -groups P-256 -cipher DHE -ciphersuites TLS_AES_128_CCM_SHA256 -no_ticket 2>nul 1>expo.txt
tlsse -c -H #.p2201 -H quiet -H timeout10000 -h %IP% -p %PORT%  -S %SEN% -H identity%ID% -H psk%PSK% 2>nul 1>expo.txt
set /p modk=<mod.txt
set /p expok=<expo.txt
REM echo expo= %expok%  modulo= %modk%
echo makekrsa: making fakekey.pem
makekrsa %modk% %expok% fakekey.pem
openssl rsa -in fakekey.pem -text -noout
REM
echo making a fake CSR in clientreq2.pem
openssl  req -new -key fakekey.pem -passin pass:pascal -sha256  -out clientreq2.pem -config config_client.cnf -reqexts req_extensions
REM
echo extract: compute clientreq2.pem CSR hash
extract clientreq2.pem 1>sha256.txt
set /p hash=<sha256.txt
echo SHA256=%hash%
REM
echo sign: signing hash with pNHSM key 22
echo  s22%hash%
REM echo .s22%hash%|openssl s_client -quiet -tls1_3 -connect %IP%:%PORT% -servername %SEN% -psk %PSK% -psk_identity %ID% -groups P-256 -cipher DHE -ciphersuites TLS_AES_128_CCM_SHA256 -no_ticket 2>nul 1>nsig.txt 
tlsse -c -H #.s22%hash% -H quiet -H timeout10000 -h %IP% -p %PORT%  -S %SEN% -H identity%ID% -H psk%PSK% 2>nul 1>nsig.txt
REM
set /p der=<nsig.txt
echo signature DER= %der%
echo ===================================
echo sig: make new CSR in clientreq.pem
echo ===================================
sig2 clientreq2.pem nsig.txt clientreq.pem
PAUSE
echo openssl: generate fake certificate
openssl  x509 -days 3000 -req -in clientreq.pem -sha256 -extfile config_client.cnf -extensions certificate_extensions -CA cacert.pem -CAkey fakecakey.pem -CAcreateserial -out clientcert2.pem
echo extract: compute certificate hash
extract clientcert2.pem 1>sha256.txt
set /p hash=<sha256.txt
echo SHA256=%hash%
echo sign hash with pNHSM
echo s21%hash%
REM echo .s21%hash%|openssl s_client -quiet -tls1_3 -connect %IP%:%PORT% -servername %SEN% -psk %PSK% -psk_identity %ID% -groups P-256 -cipher DHE -ciphersuites TLS_AES_128_CCM_SHA256 -no_ticket 2>nul 1>nsig.txt 
tlsse -c -H #.s21%hash% -H quiet -H timeout10000 -h %IP% -p %PORT%  -S %SEN% -H identity%ID% -H psk%PSK% 2>nul 1>nsig.txt
set /p der=<nsig.txt
echo signature DER= %der%
echo sig: make new certificate in clientcert.pem
sig2 clientcert2.pem nsig.txt clientcert.pem
echo openssl: verify clientcert.pem
openssl verify -CAfile cacert.pem  clientcert.pem
copy clientcert.pem clientcert.crt
echo ==============================================================================================
echo Client certificate in clientcert.pem, Public key in fakekey.pem, Private key in pNHSM index=22
echo ==============================================================================================
PAUSE