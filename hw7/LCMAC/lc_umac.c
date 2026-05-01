#include <ctype.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int hex_val(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    return 10 + (c - 'A');
}

static void load_hex_buffer(const char *path, char **hex, size_t *hex_len, unsigned char **bytes, size_t *bit_len)
{
    FILE *f = fopen(path, "rb");
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *raw = (char *)malloc(fsize + 1);
    fread(raw, 1, fsize, f);
    raw[fsize] = '\0';
    fclose(f);

    char *h = (char *)malloc(fsize + 1);
    size_t j = 0;
    for (long i = 0; i < fsize; ++i)
        if (!isspace((unsigned char)raw[i])) h[j++] = raw[i];
    h[j] = '\0';
    free(raw);

    size_t byte_len = (j + 1) / 2;
    unsigned char *b = (unsigned char *)malloc(byte_len);
    size_t src = 0, dst = 0;
    if ((j % 2) != 0)
    {
        b[dst++] = (unsigned char)hex_val(h[0]);
        src = 1;
    }
    while (src < j)
    {
        b[dst++] = (unsigned char)((hex_val(h[src]) << 4) | hex_val(h[src + 1]));
        src += 2;
    }
    *hex = h;
    *hex_len = j;
    *bytes = b;
    *bit_len = j * 4;
}

static int get_bit(const unsigned char *bytes, size_t bit_index)
{
    return (bytes[bit_index / 8] >> (7 - (bit_index % 8))) & 1U;
}

static BIGNUM *bn_from_bits(const unsigned char *bytes, size_t start_bit, size_t bit_len)
{
    BIGNUM *bn = BN_new();
    BN_zero(bn);
    for (size_t i = 0; i < bit_len; ++i)
    {
        BN_lshift1(bn, bn);
        if (get_bit(bytes, start_bit + i)) BN_add_word(bn, 1);
    }
    return bn;
}

static int generate_chacha_keystream(const unsigned char *key32, size_t out_len, unsigned char **out)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char iv[16] = {0};
    unsigned char *zeros = (unsigned char *)calloc(1, out_len);
    unsigned char *stream = (unsigned char *)malloc(out_len);
    int outl1 = 0;
    int outl2 = 0;

    EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, key32, iv);
    EVP_EncryptUpdate(ctx, stream, &outl1, zeros, (int)out_len);
    EVP_EncryptFinal_ex(ctx, stream + outl1, &outl2);
    *out = stream;

    EVP_CIPHER_CTX_free(ctx);
    free(zeros);
    return 1;
}

int main(int argc, char **argv)
{
    char *q_hex, *seed_hex, *msg_hex;
    size_t q_hex_len, seed_hex_len, msg_hex_len;
    unsigned char *q_bytes, *seed_bytes, *msg_bytes;
    size_t q_bits, msg_bits, seed_bits;

    load_hex_buffer(argv[1], &q_hex, &q_hex_len, &q_bytes, &q_bits);
    load_hex_buffer(argv[2], &seed_hex, &seed_hex_len, &seed_bytes, &seed_bits);
    load_hex_buffer(argv[3], &msg_hex, &msg_hex_len, &msg_bytes, &msg_bits);

    BIGNUM *q = NULL;
    BN_hex2bn(&q, q_hex);
    q_bits = BN_num_bits(q);
    size_t n = msg_bits / q_bits;
    size_t prng_bytes = (2 * n * q_bits + 7) / 8;

    unsigned char *prng;
    generate_chacha_keystream(seed_bytes, prng_bytes, &prng);

    FILE *fa = fopen("a.txt", "w");
    FILE *fb = fopen("b.txt", "w");
    FILE *ftags = fopen("tags.txt", "w");
    FILE *fagg = fopen("aggtag.txt", "w");

    BN_CTX *bn_ctx = BN_CTX_new();
    BIGNUM *agg = BN_new();
    BIGNUM *m = BN_new();
    BIGNUM *a = BN_new();
    BIGNUM *b = BN_new();
    BIGNUM *sigma_i = BN_new();
    BIGNUM *tmp = BN_new();

    BN_zero(agg);

    for (size_t i = 0; i < n; ++i)
    {
        size_t m_start = i * q_bits;
        size_t a_start = 2 * i * q_bits;
        size_t b_start = (2 * i + 1) * q_bits;
        int is_last = (i + 1 == n);

        BN_free(m);
        m = bn_from_bits(msg_bytes, m_start, q_bits);
        BN_free(a);
        a = bn_from_bits(prng, a_start, q_bits);
        BN_free(b);
        b = bn_from_bits(prng, b_start, q_bits);

        BN_mod(a, a, q, bn_ctx);
        BN_mod(b, b, q, bn_ctx);
        BN_mod_mul(tmp, a, m, q, bn_ctx);
        BN_mod_add(sigma_i, tmp, b, q, bn_ctx);

        char *a_hex = BN_bn2hex(a);
        fputs(a_hex, fa);
        if (!is_last)
            fputc('\n', fa);
        OPENSSL_free(a_hex);

        char *b_hex = BN_bn2hex(b);
        fputs(b_hex, fb);
        if (!is_last)
            fputc('\n', fb);
        OPENSSL_free(b_hex);

        char *sigma_hex = BN_bn2hex(sigma_i);
        fputs(sigma_hex, ftags);
        if (!is_last)
            fputc('\n', ftags);
        OPENSSL_free(sigma_hex);

        BN_mod_add(agg, agg, sigma_i, q, bn_ctx);
    }

    char *agg_hex = BN_bn2hex(agg);
    fputs(agg_hex, fagg);
    OPENSSL_free(agg_hex);

    BN_free(m);
    BN_free(a);
    BN_free(b);
    BN_free(sigma_i);
    BN_free(tmp);
    BN_free(agg);
    BN_free(q);
    BN_CTX_free(bn_ctx);

    fclose(fa);
    fclose(fb);
    fclose(ftags);
    fclose(fagg);

    free(q_hex);
    free(seed_hex);
    free(msg_hex);
    free(q_bytes);
    free(seed_bytes);
    free(msg_bytes);
    free(prng);

    return 0;
}
