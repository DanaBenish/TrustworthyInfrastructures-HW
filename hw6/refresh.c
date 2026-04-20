#include "RequiredFunctionsTGDH.c"
#include <openssl/bn.h>
#include <openssl/sha.h>

static void build_tree(BIGNUM **secrets, int n, BN_CTX *ctx,
                       BIGNUM *p, BIGNUM *g,
                       BIGNUM **out_key, BIGNUM **out_bk,
                       BIGNUM **leaf_bks, int *leaf_count,
                       BIGNUM **internal_bks, int *internal_count);

int main(int argc, char *argv[]) {
    int len1, len2, len3;
    char *paramsp = Read_File(argv[1], &len1);
    char *paramsg = Read_File(argv[2], &len2);

    BIGNUM *p = BN_new();
    BIGNUM *g = BN_new();
    BN_hex2bn(&p, paramsp);
    BN_hex2bn(&g, paramsg);
    free(paramsp);
    free(paramsg);

    char **lines;
    int n = Read_Lines(argv[3], &lines);

    int refresh_idx = Read_Int_From_File(argv[4]);

    char *new_secret_hex = Read_File(argv[5], &len3);

    BIGNUM **secrets = malloc(n * sizeof(BIGNUM*));
    for (int i = 0; i < n; i++) {
        secrets[i] = BN_new();
        BN_hex2bn(&secrets[i], lines[i]);
        free(lines[i]);
    }
    free(lines);

    BN_free(secrets[refresh_idx]);
    secrets[refresh_idx] = BN_new();
    BN_hex2bn(&secrets[refresh_idx], new_secret_hex);
    free(new_secret_hex);

    BN_CTX *ctx = BN_CTX_new();
    BIGNUM **leaf_bks     = malloc(n * sizeof(BIGNUM*));
    BIGNUM **internal_bks = malloc((n > 0 ? n - 1 : 0) * sizeof(BIGNUM*));
    int leaf_count     = 0;
    int internal_count = 0;

    BIGNUM *group_key      = NULL;
    BIGNUM *unused_root_bk = NULL;

    build_tree(secrets, n, ctx, p, g,
               &group_key, &unused_root_bk,
               leaf_bks, &leaf_count,
               internal_bks, &internal_count);

    char *gk_hex = BN_bn2hex(group_key);
    Write_File("group_key_refresh.txt", gk_hex);
    OPENSSL_free(gk_hex);

    FILE *bk_file = fopen("blinded_keys_refresh.txt", "w");
    for (int i = 0; i < leaf_count; i++) {
        char *hex = BN_bn2hex(leaf_bks[i]);
        fprintf(bk_file, "%s\n", hex);
        OPENSSL_free(hex);
    }
    for (int i = 0; i < internal_count; i++) {
        char *hex = BN_bn2hex(internal_bks[i]);
        fprintf(bk_file, "%s\n", hex);
        OPENSSL_free(hex);
    }
    fclose(bk_file);

    BN_free(group_key);
    BN_free(unused_root_bk);
    BN_CTX_free(ctx);

    for (int i = 0; i < leaf_count; i++)     BN_free(leaf_bks[i]);
    for (int i = 0; i < internal_count; i++) BN_free(internal_bks[i]);
    free(leaf_bks);
    free(internal_bks);

    for (int i = 0; i < n; i++) BN_free(secrets[i]);
    free(secrets);

    BN_free(p);
    BN_free(g);

    return 0;
}

static void build_tree(BIGNUM **secrets, int n, BN_CTX *ctx,
                       BIGNUM *p, BIGNUM *g,
                       BIGNUM **out_key, BIGNUM **out_bk,
                       BIGNUM **leaf_bks, int *leaf_count,
                       BIGNUM **internal_bks, int *internal_count)
{
    if (n == 1) {
        *out_key = BN_dup(secrets[0]);
        *out_bk  = BN_new();
        BN_mod_exp(*out_bk, g, *out_key, p, ctx);
        leaf_bks[(*leaf_count)++] = BN_dup(*out_bk);
        return;
    }

    int left_n  = (n + 1) / 2;
    int right_n = n / 2;

    BIGNUM *left_key  = NULL;
    BIGNUM *left_bk   = NULL;
    BIGNUM *right_key = NULL;
    BIGNUM *right_bk  = NULL;

    build_tree(secrets,          left_n,  ctx, p, g,
               &left_key,  &left_bk,
               leaf_bks, leaf_count,
               internal_bks, internal_count);
    build_tree(secrets + left_n, right_n, ctx, p, g,
               &right_key, &right_bk,
               leaf_bks, leaf_count,
               internal_bks, internal_count);

    *out_key = BN_new();
    BN_mod_exp(*out_key, left_bk, right_key, p, ctx);

    *out_bk = BN_new();
    BN_mod_exp(*out_bk, g, *out_key, p, ctx);

    internal_bks[(*internal_count)++] = BN_dup(*out_bk);

    BN_free(left_key);
    BN_free(left_bk);
    BN_free(right_key);
    BN_free(right_bk);
}