
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/sha.h>

#define BLOCK_SIZE 128   // each message block Mi is 128 bytes
#define HASH_SIZE  32    // SHA-256 produces 32 bytes
#define LINE_BUF   8192  // buffer

// Read one line of hex from file, strip newline, return malloc'd string 
static char *read_hex_line(FILE *fp) {
    char *buf = malloc(LINE_BUF);
    if (!buf) return NULL;
    if (!fgets(buf, LINE_BUF, fp)) {
        free(buf);
        return NULL;
    }
    // strip trailing newline / whitespace
    size_t len = strlen(buf);
    while (len > 0 && (buf[len-1] == '\n' || buf[len-1] == '\r' ||
                       buf[len-1] == ' '  || buf[len-1] == '\t')) {
        buf[--len] = '\0';
    }
    return buf;
}

// read hex string and convert to byte
static unsigned char *read_message_bytes(const char *path, size_t *out_len) {
    FILE *fp = fopen(path, "r");
    if (!fp) {
        fprintf(stderr, "Error");
        return NULL;
    }

    // determine file size 
    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    char *raw = malloc(fsize + 1);
    if (!raw) { fclose(fp); return NULL; }
    fread(raw, 1, fsize, fp);
    raw[fsize] = '\0';
    fclose(fp);

    // strip whitespace from hex string 
    size_t hex_len = 0;
    for (long i = 0; i < fsize; i++) {
        char c = raw[i];
        if (c != '\n' && c != '\r' && c != ' ' && c != '\t') {
            raw[hex_len++] = c;
        }
    }
    raw[hex_len] = '\0';

    if (hex_len % 2 != 0) {
        fprintf(stderr, "Error");
        free(raw);
        return NULL;
    }

    size_t byte_len = hex_len / 2;
    unsigned char *bytes = malloc(byte_len);
    if (!bytes) { free(raw); return NULL; }

    for (size_t i = 0; i < byte_len; i++) {
        unsigned int b;
        sscanf(raw + 2*i, "%2x", &b);
        bytes[i] = (unsigned char)b;
    }

    free(raw);
    *out_len = byte_len;
    return bytes;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Error");
        return 1;
    }

   // Load RSA parameters 
    FILE *fp_params = fopen(argv[1], "r");
    if (!fp_params) {
        fprintf(stderr, "Error");
        return 1;
    }

    char *e_hex = read_hex_line(fp_params);
    char *d_hex = read_hex_line(fp_params);
    char *n_hex = read_hex_line(fp_params);
    fclose(fp_params);

    if (!e_hex || !d_hex || !n_hex) {
        fprintf(stderr, "Error: could not read RSA params\n");
        return 1;
    }

    BIGNUM *e = NULL, *d = NULL, *n = NULL;
    BN_hex2bn(&e, e_hex);
    BN_hex2bn(&d, d_hex);
    BN_hex2bn(&n, n_hex);

    free(e_hex); free(d_hex); free(n_hex);

    /*  Read message bytes  */
    size_t msg_len = 0;
    unsigned char *msg = read_message_bytes(argv[2], &msg_len);
    if (!msg) return 1;

    if (msg_len % BLOCK_SIZE != 0) {
        fprintf(stderr, "Error");
        free(msg);
        return 1;
    }

    size_t num_blocks = msg_len / BLOCK_SIZE;

    /* Initialize aggregate signature */
    BIGNUM *sigma_agg = BN_new();
    BN_one(sigma_agg);

    BN_CTX *ctx = BN_CTX_new();

    /* Open output files */
    FILE *fp_indiv = fopen("individual_rsa.txt", "w");
    if (!fp_indiv) {
        fprintf(stderr, "Error");
        return 1;
    }

    /* For each block, hash, sign, and accumulate  */
    for (size_t i = 0; i < num_blocks; i++) {
        unsigned char *block = msg + i * BLOCK_SIZE;

        //  hi = SHA-256(Mi)
        unsigned char hash[HASH_SIZE];
        SHA256(block, BLOCK_SIZE, hash);

        //  Convert hash to BIGNUM
        BIGNUM *h_i = BN_bin2bn(hash, HASH_SIZE, NULL);

        // Individual signature: sigma_i = h_i^d mod n
        BIGNUM *sigma_i = BN_new();
        BN_mod_exp(sigma_i, h_i, d, n, ctx);

        // Write sigma_i to individual_rsa.txt
        char *sigma_i_hex = BN_bn2hex(sigma_i);
        if (i > 0) fprintf(fp_indiv, "\n");
        fprintf(fp_indiv, "%s", sigma_i_hex);
        OPENSSL_free(sigma_i_hex);

        // sigma_agg = sigma_agg * sigma_i mod n
        BN_mod_mul(sigma_agg, sigma_agg, sigma_i, n, ctx);

        BN_free(h_i);
        BN_free(sigma_i);
    }

    fclose(fp_indiv);

    /*  Write aggregate signature to condensed_rsa.txt */
    FILE *fp_agg = fopen("condensed_rsa.txt", "w");
    if (!fp_agg) {
        fprintf(stderr, "Error\n");
        return 1;
    }
    char *sigma_agg_hex = BN_bn2hex(sigma_agg);
    fprintf(fp_agg, "%s", sigma_agg_hex);
    OPENSSL_free(sigma_agg_hex);
    fclose(fp_agg);

    BN_free(e);
    BN_free(d);
    BN_free(n);
    BN_free(sigma_agg);
    BN_CTX_free(ctx);
    free(msg);


    return 0;
}