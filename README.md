# UBERCA: pNHSM-Backed Certificate Workflow

UBERCA combines OpenSSL with three helper programs—`makek`, `extract`, and `sig`—to create and sign a CA certificate, a client certificate, and a PKCS#10 certificate signing request (CSR).

The pNHSM generates the P-256 key pairs and performs the final ECDSA signatures. In the described setup, commands travel over an end-to-end TLS 1.3 connection authenticated with a pre-shared key (PSK) to the secure element in the pNHSM.

## pNHSM Command Protocol

The script invokes `openssl s_client` for each command. Connection settings—including the IP address, port, PSK identity, and PSK—are configured at the top of `makeca.sh`.

On the wire, each command is prefixed with a dot and terminated by CRLF (`\r\n`).

| Command | Purpose |
| --- | --- |
| `c11`, `c12` | Clear the selected key slot |
| `g11`, `g12` | Generate a P-256 key pair in the selected slot |
| `p11`, `p12` | Retrieve the public key for the selected slot |
| `s11<digest>`, `s12<digest>` | Sign the supplied hexadecimal digest with the key in that slot |

For example, the slot 11 signing request is sent as:

```text
.s11<64-character SHA-256 digest>\r\n
```

The script uses slot 11 for the CA key and slot 12 for the client key.

## CA Certificate: Slot 11

1. The script sends `c11`, `g11`, and `p11`. It saves the returned public key in `capub.txt`.
2. `makek` combines that public key with a hard-coded dummy private scalar and writes `fakecakey.pem`.
3. `openssl req -x509` creates a temporary self-signed CA certificate. It contains the pNHSM public key, but its initial signature is made with the dummy scalar.
4. `extract` hashes the DER-encoded `TBSCertificate`—including its tag and length—with SHA-256. The digest is 32 bytes, or 64 hexadecimal characters.
5. The script sends `s11<digest>` to the pNHSM. The pNHSM returns an ECDSA signature encoded as an ASN.1 DER sequence and represented in hexadecimal.
6. `sig` replaces the temporary signature with the pNHSM signature and writes `cacert.pem`.
7. `openssl verify` checks the CA certificate using itself as the CA file.

## Client Key, CSR, and Certificate: Slot 12

1. The script sends `c12`, `g12`, and `p12`. It saves the returned public key in `pub.txt`.
2. `makek` combines that public key with the same dummy scalar and writes `fakekey.pem`.
3. `openssl req -new` creates a temporary CSR using `fakekey.pem`.
4. `extract` hashes the DER-encoded `CertificationRequestInfo` with SHA-256.
5. The script sends `s12<digest>` to the pNHSM. `sig` replaces the temporary CSR signature and writes `clientreq.pem`.
6. `openssl x509 -req` creates a temporary client certificate from the CSR and CA. Its initial signature is made using `fakecakey.pem`.
7. `extract` hashes the certificate's DER-encoded `TBSCertificate`. The script sends this digest to the pNHSM using `s11<digest>`.
8. `sig` replaces the temporary signature and writes `clientcert.pem`. `openssl verify` then checks it against `cacert.pem`.

In short, slot 12 supplies the client public key and signs the CSR. Slot 11 signs the CA certificate and the client certificate.

## Helper Programs

| Program | Role |
| --- | --- |
| `makek.c` → `makek` | Creates an EC PEM file from a private scalar and a P-256 public key |
| `extract.c` → `extract` | Locates the signed portion of a certificate or CSR and prints its SHA-256 digest in hexadecimal |
| `sig.c` → `sig` | Reads the pNHSM signature in hexadecimal and replaces the signature in a PEM or DER certificate or CSR |

`sig` checks that the supplied signature is a single DER sequence beginning with byte `30`.

## Key Handling and Limitations

The scalar passed to `makek` is hard-coded, known, and different from the private keys generated in the pNHSM. The resulting PEM files deliberately pair this dummy scalar with a pNHSM public key. `makek` detects the mismatch, prints a warning, and continues.

These PEM files are intermediate inputs for OpenSSL. They are **not copies or backups of the pNHSM private keys**. The real CA and client private keys remain in their pNHSM slots in this workflow; the pNHSM performs the final signatures.

The script assumes that HSM responses are valid and does not consistently check command exit statuses before continuing. Protect the TLS PSK appropriately and verify the final certificates before using them.
