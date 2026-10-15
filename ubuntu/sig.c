/*
 * sig.c
 *
 * Replace the signature BIT STRING in either:
 *   - an X.509 certificate, or
 *   - a PKCS#10 certificate request.
 *
 * The new ECDSA signature must be supplied as hexadecimal text containing
 * the complete ASN.1 DER ECDSA-Sig-Value, for example:
 *
 *   3045022100...0220...
 *
 * Input may be PEM or DER. Output uses the same encoding as the input.
 * For PEM input, the original PEM label is preserved.
 *
 * Usage:
 *   sig input.pem signature.txt output.pem
 *   sig input.der signature.txt output.der
 *
 * signature.txt may contain spaces, CR/LF and ':' separators. An optional
 * leading 0x is accepted.
 *
 * Build (MinGW example):
 *   gcc -O2 -Wall -o sig.exe sig.c -lcrypto
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <openssl/evp.h>

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

static int write_entire_file(const char *path, const unsigned char *data, size_t len)
{
    FILE *f;
    size_t n;

    f = fopen(path, "wb");
    if (f == NULL) {
        fprintf(stderr, "ERROR: cannot create '%s'\n", path);
        return 0;
    }

    n = fwrite(data, 1, len, f);
    if (n != len) {
        fclose(f);
        fprintf(stderr, "ERROR: cannot write '%s'\n", path);
        return 0;
    }

    if (fclose(f) != 0) {
        fprintf(stderr, "ERROR: cannot close '%s'\n", path);
        return 0;
    }

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
            return 0;

        len = 0U;
        for (i = 0; i < nbytes; i++) {
            if (len > (((size_t)-1) >> 8))
                return 0;
            len = (len << 8) | p[2U + i];
        }
        if (len < 128U)
            return 0;
        header_len = 2U + nbytes;
    }

    if (len > avail - header_len)
        return 0;

    tlv->header_len = header_len;
    tlv->content_len = len;
    tlv->total_len = header_len + len;
    return 1;
}

static int locate_three_elements(const unsigned char *der, size_t der_len,
                                 DER_TLV *outer,
                                 size_t *first_pos, DER_TLV *first,
                                 size_t *second_pos, DER_TLV *second,
                                 size_t *third_pos, DER_TLV *third)
{
    size_t pos;
    size_t end;

    if (!parse_tlv(der, der_len, outer) || outer->tag != 0x30U) {
        fprintf(stderr, "ERROR: top-level object is not a DER SEQUENCE\n");
        return 0;
    }

    if (outer->total_len != der_len) {
        fprintf(stderr, "ERROR: trailing data after top-level DER SEQUENCE\n");
        return 0;
    }

    pos = outer->header_len;
    end = outer->header_len + outer->content_len;

    *first_pos = pos;
    if (!parse_tlv(der + pos, end - pos, first) || first->tag != 0x30U) {
        fprintf(stderr, "ERROR: first element is not a SEQUENCE\n");
        return 0;
    }
    pos += first->total_len;

    *second_pos = pos;
    if (!parse_tlv(der + pos, end - pos, second) || second->tag != 0x30U) {
        fprintf(stderr, "ERROR: second element is not an AlgorithmIdentifier SEQUENCE\n");
        return 0;
    }
    pos += second->total_len;

    *third_pos = pos;
    if (!parse_tlv(der + pos, end - pos, third) || third->tag != 0x03U) {
        fprintf(stderr, "ERROR: third element is not a BIT STRING signature\n");
        return 0;
    }
    pos += third->total_len;

    if (pos != end) {
        fprintf(stderr, "ERROR: unexpected elements after signature\n");
        return 0;
    }

    return 1;
}

static int hex_value(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int load_signature_hex(const char *path, unsigned char **sig, size_t *sig_len)
{
    unsigned char *raw;
    size_t raw_len;
    char *hex;
    size_t hex_len;
    size_t i;
    size_t start;
    unsigned char *out;

    *sig = NULL;
    *sig_len = 0;

    if (!read_entire_file(path, &raw, &raw_len))
        return 0;

    hex = (char *)malloc(raw_len + 1U);
    if (hex == NULL) {
        free(raw);
        fprintf(stderr, "ERROR: out of memory\n");
        return 0;
    }

    hex_len = 0;
    for (i = 0; i < raw_len; i++) {
        int c = raw[i];
        if (isspace((unsigned char)c) || c == ':')
            continue;
        hex[hex_len++] = (char)c;
    }
    hex[hex_len] = '\0';
    free(raw);

    start = 0;
    if (hex_len >= 2U && hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X'))
        start = 2U;

    if (((hex_len - start) & 1U) != 0U || hex_len == start) {
        free(hex);
        fprintf(stderr, "ERROR: signature hex length is invalid\n");
        return 0;
    }

    *sig_len = (hex_len - start) / 2U;
    out = (unsigned char *)malloc(*sig_len);
    if (out == NULL) {
        free(hex);
        fprintf(stderr, "ERROR: out of memory\n");
        return 0;
    }

    for (i = 0; i < *sig_len; i++) {
        int hi = hex_value((unsigned char)hex[start + 2U * i]);
        int lo = hex_value((unsigned char)hex[start + 2U * i + 1U]);
        if (hi < 0 || lo < 0) {
            free(hex);
            free(out);
            fprintf(stderr, "ERROR: signature contains non-hexadecimal characters\n");
            return 0;
        }
        out[i] = (unsigned char)((hi << 4) | lo);
    }

    free(hex);

    if (*sig_len < 2U || out[0] != 0x30U) {
        free(out);
        *sig_len = 0;
        fprintf(stderr, "ERROR: ECDSA signature must be ASN.1 DER and start with 30\n");
        return 0;
    }

    /* Verify that the signature itself is exactly one DER SEQUENCE. */
    {
        DER_TLV t;
        if (!parse_tlv(out, *sig_len, &t) || t.tag != 0x30U || t.total_len != *sig_len) {
            free(out);
            *sig_len = 0;
            fprintf(stderr, "ERROR: invalid DER ECDSA signature\n");
            return 0;
        }
    }

    *sig = out;
    return 1;
}

static size_t der_length_octets(size_t len)
{
    size_t n;
    size_t v;

    if (len < 128U)
        return 1U;

    n = 0U;
    v = len;
    while (v != 0U) {
        n++;
        v >>= 8;
    }
    return 1U + n;
}

static size_t write_der_length(unsigned char *out, size_t len)
{
    size_t n;
    size_t v;
    size_t i;

    if (len < 128U) {
        out[0] = (unsigned char)len;
        return 1U;
    }

    n = 0U;
    v = len;
    while (v != 0U) {
        n++;
        v >>= 8;
    }

    out[0] = (unsigned char)(0x80U | n);
    v = len;
    for (i = 0; i < n; i++) {
        out[n - i] = (unsigned char)(v & 0xFFU);
        v >>= 8;
    }

    return 1U + n;
}

static int build_replaced_der(const INPUT_DATA *in,
                              const unsigned char *sig, size_t sig_len,
                              unsigned char **new_der, size_t *new_der_len)
{
    DER_TLV outer, first, second, third;
    size_t first_pos, second_pos, third_pos;
    size_t bit_content_len;
    size_t bit_tlv_len;
    size_t inner_len;
    size_t outer_len_len;
    size_t total_len;
    unsigned char *out;
    size_t pos;

    *new_der = NULL;
    *new_der_len = 0;

    if (!locate_three_elements(in->der, in->der_len,
                               &outer,
                               &first_pos, &first,
                               &second_pos, &second,
                               &third_pos, &third))
        return 0;

    (void)third_pos;
    (void)third;

    if (sig_len > (size_t)-2) {
        fprintf(stderr, "ERROR: signature is too large\n");
        return 0;
    }

    bit_content_len = 1U + sig_len; /* 00 = number of unused bits */
    bit_tlv_len = 1U + der_length_octets(bit_content_len) + bit_content_len;

    if (first.total_len > (size_t)-1 - second.total_len ||
        first.total_len + second.total_len > (size_t)-1 - bit_tlv_len) {
        fprintf(stderr, "ERROR: size overflow\n");
        return 0;
    }

    inner_len = first.total_len + second.total_len + bit_tlv_len;
    outer_len_len = der_length_octets(inner_len);

    if (inner_len > (size_t)-1 - 1U - outer_len_len) {
        fprintf(stderr, "ERROR: size overflow\n");
        return 0;
    }

    total_len = 1U + outer_len_len + inner_len;
    out = (unsigned char *)malloc(total_len);
    if (out == NULL) {
        fprintf(stderr, "ERROR: out of memory\n");
        return 0;
    }

    pos = 0U;
    out[pos++] = 0x30U;
    pos += write_der_length(out + pos, inner_len);

    memcpy(out + pos, in->der + first_pos, first.total_len);
    pos += first.total_len;

    memcpy(out + pos, in->der + second_pos, second.total_len);
    pos += second.total_len;

    out[pos++] = 0x03U;
    pos += write_der_length(out + pos, bit_content_len);
    out[pos++] = 0x00U;
    memcpy(out + pos, sig, sig_len);
    pos += sig_len;

    if (pos != total_len) {
        free(out);
        fprintf(stderr, "ERROR: internal DER construction error\n");
        return 0;
    }

    *new_der = out;
    *new_der_len = total_len;
    return 1;
}

static int write_pem(const char *path, const char *label,
                     const unsigned char *der, size_t der_len)
{
    FILE *f;
    unsigned char *b64;
    size_t b64_cap;
    int b64_len;
    size_t i;
    size_t chunk;

    if (der_len > (size_t)INT_MAX) {
        fprintf(stderr, "ERROR: DER object is too large\n");
        return 0;
    }

    b64_cap = 4U * ((der_len + 2U) / 3U) + 1U;
    b64 = (unsigned char *)malloc(b64_cap);
    if (b64 == NULL) {
        fprintf(stderr, "ERROR: out of memory\n");
        return 0;
    }

    b64_len = EVP_EncodeBlock(b64, der, (int)der_len);
    if (b64_len < 0) {
        free(b64);
        fprintf(stderr, "ERROR: Base64 encoding failed\n");
        return 0;
    }

    f = fopen(path, "wb");
    if (f == NULL) {
        free(b64);
        fprintf(stderr, "ERROR: cannot create '%s'\n", path);
        return 0;
    }

    fprintf(f, "-----BEGIN %s-----\r\n", label);
    i = 0U;
    while (i < (size_t)b64_len) {
        chunk = (size_t)b64_len - i;
        if (chunk > 64U)
            chunk = 64U;
        if (fwrite(b64 + i, 1, chunk, f) != chunk) {
            fclose(f);
            free(b64);
            fprintf(stderr, "ERROR: cannot write '%s'\n", path);
            return 0;
        }
        fputs("\r\n", f);
        i += chunk;
    }
    fprintf(f, "-----END %s-----\r\n", label);

    free(b64);

    if (fclose(f) != 0) {
        fprintf(stderr, "ERROR: cannot close '%s'\n", path);
        return 0;
    }

    return 1;
}

int main(int argc, char **argv)
{
    INPUT_DATA in;
    unsigned char *sig;
    size_t sig_len;
    unsigned char *new_der;
    size_t new_der_len;
    int ok;

    if (argc != 4) {
        fprintf(stderr, "Usage: %s input.pem|input.der signature.txt output.pem|output.der\n", argv[0]);
        return 1;
    }

    if (!load_input(argv[1], &in))
        return 1;

    sig = NULL;
    sig_len = 0;
    if (!load_signature_hex(argv[2], &sig, &sig_len)) {
        free_input(&in);
        return 1;
    }

    new_der = NULL;
    new_der_len = 0;
    if (!build_replaced_der(&in, sig, sig_len, &new_der, &new_der_len)) {
        free(sig);
        free_input(&in);
        return 1;
    }

    if (in.was_pem)
        ok = write_pem(argv[3], in.pem_label, new_der, new_der_len);
    else
        ok = write_entire_file(argv[3], new_der, new_der_len);

    if (ok) {
        printf("Signature replaced successfully.\n");
        printf("Output: %s\n", argv[3]);
    }

    free(new_der);
    free(sig);
    free_input(&in);
    return ok ? 0 : 1;
}
