#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/obj_mac.h>


static int hex_nibble(int c)
{
    if (c >= '0' && c <= '9')
        return c - '0';

    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;

    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;

    return -1;
}


/*
 * Convert a hexadecimal string to bytes.
 *
 * Accepted formats:
 *
 *   04AABB...
 *   04:AA:BB...
 *   04 AA BB...
 *   0x04AABB...
 */
static int hex_to_bytes(
    const char *hex,
    unsigned char **out,
    size_t *outlen)
{
    size_t len;
    size_t start = 0;
    size_t nhex = 0;
    size_t i;
    size_t pos = 0;

    int high = -1;

    unsigned char *buf = NULL;


    *out = NULL;
    *outlen = 0;


    len = strlen(hex);


    /*
     * Ignore an optional 0x prefix.
     */
    if (len >= 2 &&
        hex[0] == '0' &&
        (hex[1] == 'x' || hex[1] == 'X')) {

        start = 2;
    }


    /*
     * Count hexadecimal digits.
     */
    for (i = start; i < len; i++) {

        if (isspace((unsigned char)hex[i]) ||
            hex[i] == ':' ||
            hex[i] == '-') {

            continue;
        }


        if (hex_nibble((unsigned char)hex[i]) < 0) {

            fprintf(
                stderr,
                "Invalid hexadecimal character: %c\n",
                hex[i]
            );

            return 0;
        }


        nhex++;
    }


    if (nhex == 0 || (nhex & 1) != 0) {

        fprintf(
            stderr,
            "Invalid number of hexadecimal characters\n"
        );

        return 0;
    }


    buf = OPENSSL_malloc(nhex / 2);

    if (buf == NULL)
        return 0;


    for (i = start; i < len; i++) {

        int v;


        if (isspace((unsigned char)hex[i]) ||
            hex[i] == ':' ||
            hex[i] == '-') {

            continue;
        }


        v = hex_nibble((unsigned char)hex[i]);


        if (high < 0) {

            high = v;

        } else {

            buf[pos++] =
                (unsigned char)((high << 4) | v);

            high = -1;
        }
    }


    *out = buf;
    *outlen = pos;

    return 1;
}


/*
 * Create a key:
 *
 *     prime256v1
 *     secp256r1
 *     NIST P-256
 *
 * from:
 *
 *     d
 *
 * and:
 *
 *     Q = 04 || X || Y
 */
static EC_KEY *create_p256_key(
    const char *private_hex,
    const char *public_hex)
{
    EC_KEY *key = NULL;

    const EC_GROUP *group = NULL;

    EC_POINT *public_point = NULL;
    EC_POINT *calculated_public = NULL;

    BIGNUM *private_key = NULL;
    BIGNUM *order = NULL;

    BN_CTX *bnctx = NULL;

    unsigned char *public_bytes = NULL;

    size_t public_len = 0;

    int ok = 0;


    /*
     * ============================================================
     * 1. Convert d to a BIGNUM.
     * ============================================================
     */

    if (BN_hex2bn(
            &private_key,
            private_hex) == 0) {

        fprintf(
            stderr,
            "Invalid hexadecimal private key\n"
        );

        goto end;
    }


    /*
     * ============================================================
     * 2. Create an EC key on prime256v1.
     *
     * prime256v1 = secp256r1 = P-256
     * ============================================================
     */

    key = EC_KEY_new_by_curve_name(
        NID_X9_62_prime256v1
    );


    if (key == NULL)
        goto end;


    /*
     * Force ASN.1 curve encoding as an OID:
     *
     *     prime256v1
     *
     * instead of explicit EC parameters.
     */
    EC_KEY_set_asn1_flag(
        key,
        OPENSSL_EC_NAMED_CURVE
    );


    group = EC_KEY_get0_group(key);

    if (group == NULL)
        goto end;


    /*
     * ============================================================
     * 3. Validate the private key:
     *
     *          1 <= d < n
     * ============================================================
     */

    bnctx = BN_CTX_new();
    order = BN_new();


    if (bnctx == NULL ||
        order == NULL) {

        goto end;
    }


    if (!EC_GROUP_get_order(
            group,
            order,
            bnctx)) {

        goto end;
    }


    if (BN_is_zero(private_key) ||
        BN_is_negative(private_key) ||
        BN_cmp(private_key, order) >= 0) {

        fprintf(
            stderr,
            "Private key is outside the valid P-256 range\n"
        );

        goto end;
    }


    /*
     * ============================================================
     * 4. Set the private key d.
     * ============================================================
     */

    if (!EC_KEY_set_private_key(
            key,
            private_key)) {

        goto end;
    }


    /*
     * ============================================================
     * 5. Convert the public key.
     * ============================================================
     */

    if (!hex_to_bytes(
            public_hex,
            &public_bytes,
            &public_len)) {

        fprintf(
            stderr,
            "Invalid hexadecimal public key\n"
        );

        goto end;
    }


    /*
     * The program accepts:
     *
     *      X || Y
     *
     * 64 bytes
     *
     * or:
     *
     *      04 || X || Y
     *
     * 65 bytes.
     */
    if (public_len == 64) {

        unsigned char *tmp;


        tmp = OPENSSL_malloc(65);

        if (tmp == NULL)
            goto end;


        tmp[0] = 0x04;

        memcpy(
            tmp + 1,
            public_bytes,
            64
        );


        OPENSSL_free(public_bytes);

        public_bytes = tmp;
        public_len = 65;
    }


    if (public_len != 65 ||
        public_bytes[0] != 0x04) {

        fprintf(
            stderr,
            "The public key must have one of the following formats:\n"
            "   X || Y       (64 bytes)\n"
            "or\n"
            "   04 || X || Y (65 bytes)\n"
        );

        goto end;
    }


    /*
     * ============================================================
     * 6. Convert the public key bytes:
     *
     *      04 || X || Y
     *
     * to an EC_POINT.
     * ============================================================
     */

    public_point =
        EC_POINT_new(group);


    if (public_point == NULL)
        goto end;


    if (!EC_POINT_oct2point(
            group,
            public_point,
            public_bytes,
            public_len,
            bnctx)) {

        fprintf(
            stderr,
            "Invalid EC public point\n"
        );

        goto end;
    }


    /*
     * ============================================================
     * 7. Set the public key.
     * ============================================================
     */

    if (!EC_KEY_set_public_key(
            key,
            public_point)) {

        goto end;
    }


    /*
     * ============================================================
     * 8. Explicit verification:
     *
     *          Qcalc = d * G
     *
     * then:
     *
     *          Qcalc == provided Q
     *
     * ============================================================
     */

    calculated_public =
        EC_POINT_new(group);


    if (calculated_public == NULL)
        goto end;


    if (!EC_POINT_mul(
            group,
            calculated_public,

            private_key,   /* d * G */

            NULL,
            NULL,

            bnctx)) {

        goto end;
    }


    if (EC_POINT_cmp(
            group,
            calculated_public,
            public_point,
            bnctx) != 0) {

        fprintf(
            stderr,
            "WARNING:\n"
            "The public key does not match "
            "the private key.\n"
            "Q != d * G\n"
        );

        //goto end;
        goto noend;

    }


    printf(
        "Verification Q = d * G: OK\n"
    );


    /*
     * ============================================================
     * 9. General OpenSSL validation.
     * ============================================================
     */

    if (EC_KEY_check_key(key) != 1) {

        fprintf(
            stderr,
            "EC_KEY_check_key(): FAILED\n"
        );

        goto end;
    }


    printf(
        "EC_KEY_check_key: OK\n"
    );

noend:

    ok = 1;


end:

    if (!ok) {

        ERR_print_errors_fp(stderr);

        EC_KEY_free(key);

        key = NULL;
    }


    BN_clear_free(private_key);

    BN_free(order);

    EC_POINT_free(public_point);

    EC_POINT_free(calculated_public);

    BN_CTX_free(bnctx);

    OPENSSL_free(public_bytes);


    return key;
}


int main(
    int argc,
    char **argv)
{
    EC_KEY *key = NULL;

    FILE *fp = NULL;


    if (argc != 4) {

        fprintf(
            stderr,
            "Usage:\n"
            "  %s PRIVATE_HEX PUBLIC_HEX key.pem\n\n"
            "PUBLIC_HEX :\n"
            "  X || Y\n"
            "or\n"
            "  04 || X || Y\n",
            argv[0]
        );

        return EXIT_FAILURE;
    }


    /*
     * ============================================================
     * Build the EC key.
     * ============================================================
     */

    key = create_p256_key(
        argv[1],
        argv[2]
    );


    if (key == NULL) {

        fprintf(
            stderr,
            "Unable to build the EC key\n"
        );

        return EXIT_FAILURE;
    }


    /*
     * ============================================================
     * Create the PEM file.
     * ============================================================
     */

    fp = fopen(
        argv[3],
        "wb"
    );


    if (fp == NULL) {

        perror(argv[3]);

        EC_KEY_free(key);

        return EXIT_FAILURE;
    }


    /*
     * ============================================================
     * Format SEC1 / RFC 5915 :
     *
     * -----BEGIN EC PRIVATE KEY-----
     *
     * instead of PKCS#8.
     * ============================================================
     */

    if (!PEM_write_ECPrivateKey(
            fp,
            key,

            NULL,       /* no encryption */
            NULL,
            0,

            NULL,
            NULL)) {

        fprintf(
            stderr,
            "PEM_write_ECPrivateKey() failed\n"
        );

        ERR_print_errors_fp(stderr);

        fclose(fp);

        EC_KEY_free(key);

        return EXIT_FAILURE;
    }


    fclose(fp);


    printf(
        "Key written to: %s\n",
        argv[3]
    );


    EC_KEY_free(key);


    return EXIT_SUCCESS;
}