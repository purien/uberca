/*
 * extracti.c
 *
 * Extract the exact DER-encoded signed portion from either:
 *   - an X.509 certificate:        TBSCertificate
 *   - a PKCS#10 certificate request: CertificationRequestInfo
 *
 * Then compute SHA-256 over that complete DER TLV (tag + length + value)
 * and print the digest as hexadecimal text.
 *
 * Input may be PEM or DER.
 *
 * Usage:
 *   extracti input.pem
 *   extracti input.der
 *   extracti input.pem hash.txt
 *
 * Build (MinGW example):
 *   gcc -O2 -Wall -o extracti.exe extracti.c -lcrypto
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

typedef struct {
    unsigned char *der;
    size_t der_len;
    int was_pem;
    char pem_label[80];
} INPUT_DATA;

typedef struct {
    unsigned int tag;
    size_t header_len;
    size_t content_len;
    size_t total_len;
} DER_TLV;

static void free_input(INPUT_DATA *in)
{
    if (in != NULL) {
        free(in->der);
        in->der = NULL;
        in->der_len = 0;
    }
}

static int read_entire_file(const char *path, unsigned char **data, size_t *len)
{
    FILE *f;
    long sz;
    unsigned char *buf;
    size_t n;

    *data = NULL;
    *len = 0;

    f = fopen(path, "rb");
    if (f == NULL) {
        fprintf(stderr, "ERROR: cannot open '%s'\n", path);
        return 0;
    }

    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        fprintf(stderr, "ERROR: cannot seek '%s'\n", path);
        return 0;
    }

    sz = ftell(f);
    if (sz < 0) {
        fclose(f);
        fprintf(stderr, "ERROR: cannot determine size of '%s'\n", path);
        return 0;
    }

    if (fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        fprintf(stderr, "ERROR: cannot rewind '%s'\n", path);
        return 0;
    }

    buf = (unsigned char *)malloc((size_t)sz + 1U);
    if (buf == NULL) {
        fclose(f);
        fprintf(stderr, "ERROR: out of memory\n");
        return 0;
    }

    n = fread(buf, 1, (size_t)sz, f);
    fclose(f);

    if (n != (size_t)sz) {
        free(buf);
        fprintf(stderr, "ERROR: cannot read '%s'\n", path);
        return 0;
    }

    buf[n] = '\0';
    *data = buf;
    *len = n;
    return 1;
}

static int is_b64_char(int c)
{
    return (c >= 'A' && c <= 'Z') ||
           (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') ||
           c == '+' || c == '/' || c == '=';
}

static int decode_pem(const unsigned char *raw, size_t raw_len,
                      unsigned char **der, size_t *der_len,
                      char *label, size_t label_size)
{
    const char *text;
    const char *begin;
    const char *label_start;
    const char *label_end;
    const char *body;
    const char *end;
    char end_marker[128];
    size_t lab_len;
    size_t body_len;
    char *b64;
    size_t b64_len;
    size_t i;
    int dec_len;
    int padding;
    unsigned char *out;

    (void)raw_len;
    text = (const char *)raw;

    begin = text;
    while (*begin != '\0' && isspace((unsigned char)*begin))
        begin++;

    if (strncmp(begin, "-----BEGIN ", 11) != 0)
        return 0;

    label_start = begin + 11;
    label_end = strstr(label_start, "-----");
    if (label_end == NULL)
        return -1;

    lab_len = (size_t)(label_end - label_start);
    if (lab_len == 0 || lab_len + 1 > label_size || lab_len + 17 >= sizeof(end_marker))
        return -1;

    memcpy(label, label_start, lab_len);
    label[lab_len] = '\0';

    strcpy(end_marker, "-----END ");
    strcat(end_marker, label);
    strcat(end_marker, "-----");

    body = strchr(label_end, '\n');
    if (body == NULL)
        return -1;
    body++;

    end = strstr(body, end_marker);
    if (end == NULL)
        return -1;

    body_len = (size_t)(end - body);
    b64 = (char *)malloc(body_len + 1U);
    if (b64 == NULL)
        return -1;

    b64_len = 0;
    for (i = 0; i < body_len; i++) {
        int c = (unsigned char)body[i];
        if (isspace(c))
            continue;
        if (!is_b64_char(c)) {
            free(b64);
            return -1;
        }
        b64[b64_len++] = (char)c;
    }
    b64[b64_len] = '\0';

    if (b64_len == 0 || (b64_len % 4U) != 0U || b64_len > (size_t)INT_MAX) {
        free(b64);
        return -1;
    }

    out = (unsigned char *)malloc((b64_len / 4U) * 3U + 1U);
    if (out == NULL) {
        free(b64);
        return -1;
    }

    dec_len = EVP_DecodeBlock(out, (const unsigned char *)b64, (int)b64_len);
    if (dec_len < 0) {
        free(b64);
        free(out);
        return -1;
    }

    padding = 0;
    if (b64_len >= 1U && b64[b64_len - 1U] == '=')
        padding++;
    if (b64_len >= 2U && b64[b64_len - 2U] == '=')
        padding++;

    dec_len -= padding;
    free(b64);

    if (dec_len < 0) {
        free(out);
        return -1;
    }

    *der = out;
    *der_len = (size_t)dec_len;
    return 1;
}

static int load_input(const char *path, INPUT_DATA *in)
{
    unsigned char *raw;
    size_t raw_len;
    unsigned char *der;
    size_t der_len;
    int r;

    memset(in, 0, sizeof(*in));

    if (!read_entire_file(path, &raw, &raw_len))
        return 0;

    der = NULL;
    der_len = 0;
    r = decode_pem(raw, raw_len, &der, &der_len,
                   in->pem_label, sizeof(in->pem_label));

    if (r < 0) {
        free(raw);
        fprintf(stderr, "ERROR: invalid PEM input\n");
        return 0;
    }

    if (r == 1) {
        free(raw);
        in->der = der;
        in->der_len = der_len;
        in->was_pem = 1;
    } else {
        in->der = raw;
        in->der_len = raw_len;
        in->was_pem = 0;
        in->pem_label[0] = '\0';
    }

    return 1;
}

static int parse_tlv(const unsigned char *p, size_t avail, DER_TLV *tlv)
{
    unsigned char lb;
    size_t nbytes;
    size_t len;
    size_t i;
    size_t header_len;

    if (avail < 2U)
        return 0;

    tlv->tag = p[0];
    lb = p[1];

    if ((lb & 0x80U) == 0U) {
        len = (size_t)lb;
        header_len = 2U;
    } else {
        nbytes = (size_t)(lb & 0x7FU);
        if (nbytes == 0U || nbytes > sizeof(size_t) || avail < 2U + nbytes)
            return 0;
        if (p[2] == 0)
            return 0; /* Non-minimal DER length. */

        len = 0U;
        for (i = 0; i < nbytes; i++) {
            if (len > (((size_t)-1) >> 8))
                return 0;
            len = (len << 8) | p[2U + i];
        }
        if (len < 128U)
            return 0; /* Long form used when short form was required. */
        header_len = 2U + nbytes;
    }

    if (len > avail - header_len)
        return 0;

    tlv->header_len = header_len;
    tlv->content_len = len;
    tlv->total_len = header_len + len;
    return 1;
}

static int locate_signed_part(const unsigned char *der, size_t der_len,
                              size_t *signed_offset, size_t *signed_len)
{
    DER_TLV outer;
    DER_TLV first;
    DER_TLV second;
    DER_TLV third;
    size_t pos;
    size_t end;

    if (!parse_tlv(der, der_len, &outer) || outer.tag != 0x30U) {
        fprintf(stderr, "ERROR: top-level object is not a DER SEQUENCE\n");
        return 0;
    }

    if (outer.total_len != der_len) {
        fprintf(stderr, "ERROR: trailing data after top-level DER SEQUENCE\n");
        return 0;
    }

    pos = outer.header_len;
    end = outer.header_len + outer.content_len;

    if (!parse_tlv(der + pos, end - pos, &first) || first.tag != 0x30U) {
        fprintf(stderr, "ERROR: first element is not a SEQUENCE\n");
        return 0;
    }

    *signed_offset = pos;
    *signed_len = first.total_len;
    pos += first.total_len;

    if (!parse_tlv(der + pos, end - pos, &second) || second.tag != 0x30U) {
        fprintf(stderr, "ERROR: second element is not an AlgorithmIdentifier SEQUENCE\n");
        return 0;
    }
    pos += second.total_len;

    if (!parse_tlv(der + pos, end - pos, &third) || third.tag != 0x03U) {
        fprintf(stderr, "ERROR: third element is not a BIT STRING signature\n");
        return 0;
    }
    pos += third.total_len;

    if (pos != end) {
        fprintf(stderr, "ERROR: unexpected elements after signature\n");
        return 0;
    }

    return 1;
}

static void digest_to_hex(const unsigned char *digest, size_t len, char *hex)
{
    static const char digits[] = "0123456789ABCDEF";
    size_t i;

    for (i = 0; i < len; i++) {
        hex[2U * i] = digits[(digest[i] >> 4) & 0x0F];
        hex[2U * i + 1U] = digits[digest[i] & 0x0F];
    }
    hex[2U * len] = '\0';
}

int main(int argc, char **argv)
{
    INPUT_DATA in;
    size_t signed_offset;
    size_t signed_len;
    unsigned char digest[SHA256_DIGEST_LENGTH];
    char hex[SHA256_DIGEST_LENGTH * 2 + 1];
    FILE *out;

    if (argc != 2 && argc != 3) {
        fprintf(stderr, "Usage: %s input.pem|input.der [hash.txt]\n", argv[0]);
        return 1;
    }

    if (!load_input(argv[1], &in))
        return 1;

    if (!locate_signed_part(in.der, in.der_len, &signed_offset, &signed_len)) {
        free_input(&in);
        return 1;
    }

    if (SHA256(in.der + signed_offset, signed_len, digest) == NULL) {
        fprintf(stderr, "ERROR: SHA-256 computation failed\n");
        free_input(&in);
        return 1;
    }

    digest_to_hex(digest, sizeof(digest), hex);
    printf("%s\n", hex);

    if (argc == 3) {
        out = fopen(argv[2], "wb");
        if (out == NULL) {
            fprintf(stderr, "ERROR: cannot create '%s'\n", argv[2]);
            free_input(&in);
            return 1;
        }
        fprintf(out, "%s\n", hex);
        fclose(out);
    }

    free_input(&in);
    return 0;
}
