#include "RequiredFunctionsTGDH.c"
#include <openssl/bn.h>
#include <openssl/sha.h>

void build_tree(BIGNUM **secrets, int n, BN_CTX *ctx, BIGNUM *p, BIGNUM *g,
                BIGNUM **out_key, BIGNUM **out_bk,
                BIGNUM **all_bks, int *bk_count) {
    if (n == 1) {
        // Leaf node
        *out_key = BN_dup(secrets[0]);
        *out_bk  = BN_new();
        BN_mod_exp(*out_bk, g, *out_key, p, ctx);
        all_bks[(*bk_count)++] = BN_dup(*out_bk);
        return;
    }

    int left_n  = (n + 1) / 2;  // ceil(n/2)
    int right_n = n / 2;        // floor(n/2)

    BIGNUM *left_key, *left_bk, *right_key, *right_bk;

    build_tree(secrets,          left_n,  ctx, p, g, &left_key,  &left_bk,  all_bks, bk_count);
    build_tree(secrets + left_n, right_n, ctx, p, g, &right_key, &right_bk, all_bks, bk_count);

    // K_parent = BK_left ^ K_right mod p
    *out_key = BN_new();
    BN_mod_exp(*out_key, left_bk, right_key, p, ctx);

    // BK_parent = g ^ K_parent mod p
    *out_bk = BN_new();
    BN_mod_exp(*out_bk, g, *out_key, p, ctx);

    all_bks[(*bk_count)++] = BN_dup(*out_bk);

    BN_free(left_key); BN_free(left_bk);
    BN_free(right_key); BN_free(right_bk);
}

int main(int argc, char *argv[]) {
    // read p and g
    int len1, len2;
    char *paramsp = Read_File(argv[1], &len1);
    char *paramsg = Read_File(argv[2], &len2);

    BIGNUM *p = BN_new();
    BIGNUM *g = BN_new();
    BN_hex2bn(&p, paramsp);
    BN_hex2bn(&g, paramsg);
    free(paramsp);
    free(paramsg);

    // read secret files
    char **secret1;
    char **secret2;
    int n1 = Read_Lines(argv[3], &secret1);
    int n2 = Read_Lines(argv[4], &secret2);

    int total = n1 + n2;
    BIGNUM **secrets = malloc(total * sizeof(BIGNUM*));

    for (int i = 0; i < n1; i++) {
        secrets[i] = BN_new();
        BN_hex2bn(&secrets[i], secret1[i]);
        free(secret1[i]);
    }
    for (int i = 0; i < n2; i++) {
        secrets[n1 + i] = BN_new();
        BN_hex2bn(&secrets[n1 + i], secret2[i]);
        free(secret2[i]);
    }
    free(secret1);
    free(secret2);

    // build tree
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM **all_bks = malloc(2 * total * sizeof(BIGNUM*)); // enough space
    int bk_count = 0;

    BIGNUM *group_key, *root_bk;
    build_tree(secrets, total, ctx, p, g, &group_key, &root_bk, all_bks, &bk_count);

    // write group key
    char *gk_hex = BN_bn2hex(group_key);
    Write_File("group_key_merge.txt", gk_hex);
    OPENSSL_free(gk_hex);

    // write all blinded keys (leaf BKs first, then internal in post-order)
    FILE *bk_file = fopen("blinded_keys_merge.txt", "w");
    for (int i = 0; i < bk_count; i++) {
        char *bk_hex = BN_bn2hex(all_bks[i]);
        fprintf(bk_file, "%s\n", bk_hex);
        OPENSSL_free(bk_hex);
        BN_free(all_bks[i]);
    }
    fclose(bk_file);

    // cleanup
    BN_free(p); BN_free(g);
    BN_free(group_key); BN_free(root_bk);
    BN_CTX_free(ctx);
    free(all_bks);
    for (int i = 0; i < total; i++) BN_free(secrets[i]);
    free(secrets);

    return 0;
}