#include "RequiredFunctionsTGDH.c"
#include <openssl/bn.h>
#include <openssl/sha.h>

void build_tree(BIGNUM **secrets, int n, BN_CTX *ctx, BIGNUM *p, BIGNUM *g,
                BIGNUM **out_key, BIGNUM **out_bk,
                BIGNUM **all_bks, int *bk_count) {
    if (n == 1) {
        *out_key = BN_dup(secrets[0]);
        *out_bk  = BN_new();
        BN_mod_exp(*out_bk, g, *out_key, p, ctx);
        all_bks[(*bk_count)++] = BN_dup(*out_bk);
        return;
    }

    int left_n  = (n + 1) / 2;
    int right_n = n / 2;

    BIGNUM *left_key, *left_bk, *right_key, *right_bk;

    build_tree(secrets,          left_n,  ctx, p, g, &left_key,  &left_bk,  all_bks, bk_count);
    build_tree(secrets + left_n, right_n, ctx, p, g, &right_key, &right_bk, all_bks, bk_count);

    *out_key = BN_new();
    BN_mod_exp(*out_key, left_bk, right_key, p, ctx);

    *out_bk = BN_new();
    BN_mod_exp(*out_bk, g, *out_key, p, ctx);

    all_bks[(*bk_count)++] = BN_dup(*out_bk);

    BN_free(left_key); BN_free(left_bk);
    BN_free(right_key); BN_free(right_bk);
}

int main(int argc, char *argv[]) {
    // read p and g
    int len1, len2, len3;
    char *paramsp = Read_File(argv[1], &len1);
    char *paramsg = Read_File(argv[2], &len2);

    BIGNUM *p = BN_new();
    BIGNUM *g = BN_new();
    BN_hex2bn(&p, paramsp);
    BN_hex2bn(&g, paramsg);
    free(paramsp);
    free(paramsg);

    // read all member secrets
    char **lines;
    int n = Read_Lines(argv[3], &lines);

    // read refresh index
    int refresh_idx = Read_Int_From_File(argv[4]);

    // read new secret
    char *new_secret_hex = Read_File(argv[5], &len3);

    // convert to BIGNUM array
    BIGNUM **secrets = malloc(n * sizeof(BIGNUM*));
    for (int i = 0; i < n; i++) {
        secrets[i] = BN_new();
        BN_hex2bn(&secrets[i], lines[i]);
        free(lines[i]);
    }
    free(lines);

    // replace the refreshing member's secret
    BN_free(secrets[refresh_idx]);
    secrets[refresh_idx] = BN_new();
    BN_hex2bn(&secrets[refresh_idx], new_secret_hex);
    free(new_secret_hex);

    // build tree
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM **all_bks = malloc(2 * n * sizeof(BIGNUM*));
    int bk_count = 0;

    BIGNUM *group_key, *root_bk;
    build_tree(secrets, n, ctx, p, g, &group_key, &root_bk, all_bks, &bk_count);

    // write group key
    char *gk_hex = BN_bn2hex(group_key);
    Write_File("group_key_refresh.txt", gk_hex);
    OPENSSL_free(gk_hex);

    // write blinded keys
    FILE *bk_file = fopen("blinded_keys_refresh.txt", "w");
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
    for (int i = 0; i < n; i++) BN_free(secrets[i]);
    free(secrets);

    return 0;
}