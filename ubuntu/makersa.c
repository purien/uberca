/*
 * make_fake_rsa.c
 *
 * Create a deliberately invalid RSA private key containing the
 * correct public parameters N and E.
 *
 * Supported OpenSSL API families:
 *   - OpenSSL 1.0.2
 *   - OpenSSL 1.1.x
 *   - OpenSSL 3.x (legacy RSA API, may generate deprecation warnings)
 *
 * IMPORTANT:
 * This program DOES NOT create a cryptographically valid RSA private key.
 * It creates a placeholder key containing the correct RSA public key
 * (N, E) and deliberately fake private parameters.
 *
 * Intended use:
 *   - Let software load a "private key" object containing the correct
 *     RSA public key.
 *   - Build an object such as a PKCS#10 CSR.
 *   - Replace the placeholder signature afterwards with a real signature
 *     produced by an external secure element / HSM / signing service.
 *
 * DO NOT use the generated key.pem for real cryptographic signing.
 */

#include <stdio.h>
#include <stdlib.h>

#include <openssl/opensslv.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/err.h>


/*
 * Print the OpenSSL error stack.
 */
static void print_openssl_errors(void)
{
    ERR_print_errors_fp(stderr);
}


/*
 * Create a deliberately invalid RSA private key containing
 * the correct public parameters N and E.
 *
 * Fake private parameters:
 *
 *     D    = 1
 *     P    = N
 *     Q    = 1
 *     DP   = 1
 *     DQ   = 0
 *     QINV = 1
 *
 * The resulting RSA object is NOT mathematically valid.
 */
static RSA *create_fake_rsa_key(
    const char *modulus_hex,
    const char *exponent_hex)
{
    RSA *rsa = NULL;

    BIGNUM *n = NULL;
    BIGNUM *e = NULL;
    BIGNUM *d = NULL;

    BIGNUM *p = NULL;
    BIGNUM *q = NULL;

    BIGNUM *dp = NULL;
    BIGNUM *dq = NULL;
    BIGNUM *qinv = NULL;

    int ok = 0;


    /*
     * Convert the real modulus N from hexadecimal.
     */
    if (BN_hex2bn(&n, modulus_hex) == 0) {
        fprintf(stderr, "ERROR: invalid RSA modulus N\n");
        goto end;
    }


    /*
     * Convert the real public exponent E from hexadecimal.
     *
     * Typical value:
     *
     *     010001 = 65537
     */
    if (BN_hex2bn(&e, exponent_hex) == 0) {
        fprintf(stderr, "ERROR: invalid RSA public exponent E\n");
        goto end;
    }


    /*
     * Basic validation of the public parameters.
     */
    if (BN_is_zero(n) || BN_is_negative(n)) {
        fprintf(stderr, "ERROR: modulus N must be positive\n");
        goto end;
    }

    if (BN_is_zero(e) || BN_is_negative(e)) {
        fprintf(stderr, "ERROR: public exponent E must be positive\n");
        goto end;
    }

    if (!BN_is_odd(n)) {
        fprintf(stderr, "ERROR: RSA modulus N must be odd\n");
        goto end;
    }

    if (!BN_is_odd(e)) {
        fprintf(stderr, "ERROR: RSA public exponent E must be odd\n");
        goto end;
    }


    /*
     * Allocate fake private parameters.
     */
    d = BN_new();
    q = BN_new();

    dp = BN_new();
    dq = BN_new();
    qinv = BN_new();

    if (d == NULL ||
        q == NULL ||
        dp == NULL ||
        dq == NULL ||
        qinv == NULL) {

        fprintf(stderr, "ERROR: unable to allocate BIGNUM objects\n");
        goto end;
    }


    /*
     * P is deliberately set to a copy of N.
     */
    p = BN_dup(n);

    if (p == NULL) {
        fprintf(stderr, "ERROR: unable to duplicate modulus N\n");
        goto end;
    }


    /*
     * Initialize deliberately invalid private parameters.
     *
     *     D    = 1
     *     P    = N
     *     Q    = 1
     *     DP   = 1
     *     DQ   = 0
     *     QINV = 1
     */
    if (!BN_one(d) ||
        !BN_one(q) ||
        !BN_one(dp) ||
        !BN_one(qinv)) {

        fprintf(stderr, "ERROR: unable to initialize fake RSA parameters\n");
        goto end;
    }

    /* BN_zero() is void on some OpenSSL versions. */
    BN_zero(dq);


    /*
     * Allocate the RSA object.
     */
    rsa = RSA_new();

    if (rsa == NULL) {
        fprintf(stderr, "ERROR: RSA_new() failed\n");
        goto end;
    }


#if OPENSSL_VERSION_NUMBER < 0x10100000L

    /*
     * ============================================================
     * OpenSSL 1.0.x
     * ============================================================
     *
     * In OpenSSL 1.0.x, the RSA structure is public.
     * Parameters can therefore be assigned directly.
     */

    rsa->n = n;
    rsa->e = e;
    rsa->d = d;

    rsa->p = p;
    rsa->q = q;

    rsa->dmp1 = dp;
    rsa->dmq1 = dq;
    rsa->iqmp = qinv;

    /*
     * Ownership has been transferred to the RSA object.
     */
    n = NULL;
    e = NULL;
    d = NULL;

    p = NULL;
    q = NULL;

    dp = NULL;
    dq = NULL;
    qinv = NULL;

#else

    /*
     * ============================================================
     * OpenSSL 1.1.x and later
     * ============================================================
     *
     * In OpenSSL 1.1.x, the RSA structure is opaque.
     * Use RSA_set0_*() functions.
     */


    /*
     * Install N, E and fake D.
     *
     * On success, ownership of n, e and d is transferred
     * to the RSA object.
     */
    if (!RSA_set0_key(rsa, n, e, d)) {

        fprintf(stderr, "ERROR: RSA_set0_key() failed\n");
        goto end;
    }

    n = NULL;
    e = NULL;
    d = NULL;


    /*
     * Install fake P and Q.
     */
    if (!RSA_set0_factors(rsa, p, q)) {

        fprintf(stderr, "ERROR: RSA_set0_factors() failed\n");
        goto end;
    }

    p = NULL;
    q = NULL;


    /*
     * Install fake CRT parameters.
     */
    if (!RSA_set0_crt_params(
            rsa,
            dp,
            dq,
            qinv)) {

        fprintf(stderr, "ERROR: RSA_set0_crt_params() failed\n");
        goto end;
    }

    dp = NULL;
    dq = NULL;
    qinv = NULL;

#endif


    ok = 1;


end:

    /*
     * Free only values whose ownership has NOT been transferred.
     */
    BN_free(n);
    BN_free(e);
    BN_clear_free(d);

    BN_free(p);
    BN_free(q);

    BN_clear_free(dp);
    BN_clear_free(dq);
    BN_clear_free(qinv);


    if (!ok) {

        RSA_free(rsa);
        rsa = NULL;

        print_openssl_errors();
    }


    return rsa;
}


/*
 * Print some basic information about the RSA public key.
 */
static void print_rsa_info(RSA *rsa)
{
    const BIGNUM *n = NULL;
    const BIGNUM *e = NULL;


#if OPENSSL_VERSION_NUMBER < 0x10100000L

    n = rsa->n;
    e = rsa->e;

#else

    RSA_get0_key(
        rsa,
        &n,
        &e,
        NULL
    );

#endif


    if (n != NULL) {

        printf(
            "RSA modulus size: %d bits\n",
            BN_num_bits(n)
        );
    }


    if (e != NULL) {

        char *e_hex = BN_bn2hex(e);

        if (e_hex != NULL) {

            printf(
                "RSA public exponent: 0x%s\n",
                e_hex
            );

            OPENSSL_free(e_hex);
        }
    }
}


int main(
    int argc,
    char **argv)
{
    RSA *rsa = NULL;

    FILE *fp = NULL;


    /*
     * Expected command line:
     *
     *     make_fake_rsa MODULUS_HEX EXPONENT_HEX key.pem
     */
    if (argc != 4) {

        fprintf(
            stderr,
            "Usage:\n"
            "  %s MODULUS_HEX EXPONENT_HEX key.pem\n\n"
            "Example:\n"
            "  %s AABBCCDD... 010001 key.pem\n\n"
            "MODULUS_HEX  : real RSA modulus N in hexadecimal\n"
            "EXPONENT_HEX : real RSA public exponent E in hexadecimal\n"
            "               010001 means 65537\n",
            argv[0],
            argv[0]
        );

        return EXIT_FAILURE;
    }


    /*
     * Initialize the OpenSSL error strings when using old OpenSSL.
     * These calls are not required by OpenSSL 1.1.x+, but keeping
     * them conditionally makes diagnostics nicer on OpenSSL 1.0.x.
     */
#if OPENSSL_VERSION_NUMBER < 0x10100000L

    ERR_load_crypto_strings();

#endif


    printf(
        "OpenSSL version: %s\n",
        OPENSSL_VERSION_TEXT
    );


    /*
     * Create the deliberately invalid RSA private key.
     */
    rsa = create_fake_rsa_key(
        argv[1],
        argv[2]
    );


    if (rsa == NULL) {

        fprintf(
            stderr,
            "ERROR: unable to create fake RSA key\n"
        );

#if OPENSSL_VERSION_NUMBER < 0x10100000L
        ERR_free_strings();
#endif

        return EXIT_FAILURE;
    }


    print_rsa_info(rsa);


    /*
     * Write a traditional PKCS#1 RSA private key:
     *
     *     -----BEGIN RSA PRIVATE KEY-----
     *     ...
     *     -----END RSA PRIVATE KEY-----
     *
     * No encryption is applied.
     */
    fp = fopen(
        argv[3],
        "wb"
    );


    if (fp == NULL) {

        perror(argv[3]);

        RSA_free(rsa);

#if OPENSSL_VERSION_NUMBER < 0x10100000L
        ERR_free_strings();
#endif

        return EXIT_FAILURE;
    }


    if (!PEM_write_RSAPrivateKey(
            fp,
            rsa,
            NULL,
            NULL,
            0,
            NULL,
            NULL)) {

        fprintf(
            stderr,
            "ERROR: PEM_write_RSAPrivateKey() failed\n"
        );

        print_openssl_errors();

        fclose(fp);
        RSA_free(rsa);

#if OPENSSL_VERSION_NUMBER < 0x10100000L
        ERR_free_strings();
#endif

        return EXIT_FAILURE;
    }


    fclose(fp);


    printf(
        "Fake RSA private key written to: %s\n",
        argv[3]
    );

    printf(
        "WARNING: this is NOT a valid RSA private key.\n"
    );

    printf(
        "The public parameters N and E are real, but the private "
        "parameters are deliberately invalid.\n"
    );

    printf(
        "Use this file only as a temporary placeholder.\n"
    );


    /*
     * RSA_check_key() is expected to fail because the private
     * parameters are deliberately inconsistent.
     *
     * We do not treat that as a program error.
     */
    if (RSA_check_key(rsa) == 1) {

        printf(
            "WARNING: RSA_check_key() unexpectedly reports a valid key.\n"
        );

    } else {

        printf(
            "RSA_check_key(): expected failure (fake private parameters)\n"
        );

        /*
         * Clear the expected OpenSSL error stack so it does not
         * look like an unhandled program error.
         */
        ERR_clear_error();
    }


    RSA_free(rsa);


#if OPENSSL_VERSION_NUMBER < 0x10100000L

    ERR_free_strings();

#endif


    return EXIT_SUCCESS;
}
