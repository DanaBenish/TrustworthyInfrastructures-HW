#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/sha.h>

// helper function
char *Read_File(const char *filename, int *length);
int Write_File(const char *filename, const char *data);
int Read_Int_From_File(const char *filename);
int Read_Lines(const char *filename, char ***lines_out);
static void write_bn_list(FILE *out, BIGNUM **values, int count);
static void build_tree(
    BIGNUM **secrets,
    int n,
    BN_CTX *ctx,
    const BIGNUM *p,
    const BIGNUM *g,
    BIGNUM **out_key,
    BIGNUM **out_bk,
    BIGNUM **leaf_bks,
    int *leaf_count,
    BIGNUM **internal_bks,
    int *internal_count);

int main(int argc, char *argv[])
{
    // part 1
    int tmp_len = 0;
    char *p_hex = Read_File(argv[1], &tmp_len);
    char *g_hex = Read_File(argv[2], &tmp_len);

    BIGNUM *p = NULL;
    BIGNUM *g = NULL;
    BN_hex2bn(&p, p_hex);
    BN_hex2bn(&g, g_hex);
    free(p_hex);
    free(g_hex);

    // part 2
    char **existing_lines;
    int existing_count = Read_Lines(argv[3], &existing_lines);
    char *new_secret_hex = Read_File(argv[4], &tmp_len);
    char *sponsor_new_secret_hex = Read_File(argv[5], &tmp_len);

    BIGNUM **secrets = malloc((size_t)(existing_count + 1) * sizeof(*secrets));

    for (int i = 0; i < existing_count; i++)
    {
        secrets[i] = BN_new();
        BN_hex2bn(&secrets[i], existing_lines[i]);
        free(existing_lines[i]);
    }
    free(existing_lines);

    // part 3
    BN_free(secrets[existing_count - 1]);
    secrets[existing_count - 1] = BN_new();
    BN_hex2bn(&secrets[existing_count - 1], sponsor_new_secret_hex);
    free(sponsor_new_secret_hex);

    secrets[existing_count] = BN_new();
    BN_hex2bn(&secrets[existing_count], new_secret_hex);
    free(new_secret_hex);

    // part 4
    int n = existing_count + 1;
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM **leaf_bks = malloc((size_t)n * sizeof(*leaf_bks));
    BIGNUM **internal_bks = malloc((size_t)(n > 0 ? n - 1 : 0) * sizeof(*internal_bks));

    int leaf_count = 0;
    int internal_count = 0;
    BIGNUM *group_key = NULL;
    BIGNUM *unused_root_bk = NULL;

    build_tree(secrets, n, ctx, p, g,
               &group_key, &unused_root_bk,
               leaf_bks, &leaf_count,
               internal_bks, &internal_count);

    // part 5
    char *group_key_hex = BN_bn2hex(group_key);
    Write_File("group_key_join.txt", group_key_hex);
    OPENSSL_free(group_key_hex);

    // part 6
    FILE *bk_file = fopen("blinded_keys_join.txt", "w");
    write_bn_list(bk_file, leaf_bks, leaf_count);
    write_bn_list(bk_file, internal_bks, internal_count);
    fclose(bk_file);

    BN_free(group_key);
    BN_free(unused_root_bk);
    BN_CTX_free(ctx);

    for (int i = 0; i < leaf_count; i++)
    {
        BN_free(leaf_bks[i]);
    }

    for (int i = 0; i < internal_count; i++)
    {
        BN_free(internal_bks[i]);
    }
    free(leaf_bks);
    free(internal_bks);

    for (int i = 0; i < n; i++)
    {
        BN_free(secrets[i]);
    }
    free(secrets);
    BN_free(p);
    BN_free(g);
    return 0;
}

// Helper Functions

/* Read entire file as string, strip trailing whitespace */
char *Read_File(const char *filename, int *length)
{
    FILE *file = fopen(filename, "r");
    if (!file)
    {
        fprintf(stderr, "Error: Cannot open file %s\n", filename);
        return NULL;
    }
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    char *buffer = (char *)malloc(file_size + 1);
    if (!buffer)
    {
        fclose(file);
        return NULL;
    }
    size_t read_size = fread(buffer, 1, file_size, file);
    buffer[read_size] = '\0';
    while (read_size > 0 && (buffer[read_size - 1] == '\n' ||
                             buffer[read_size - 1] == '\r' || buffer[read_size - 1] == ' '))
        buffer[--read_size] = '\0';
    *length = (int)read_size;
    fclose(file);
    return buffer;
}

/* Write string to file */
int Write_File(const char *filename, const char *data)
{
    FILE *file = fopen(filename, "w");
    if (!file)
    {
        fprintf(stderr, "Error: Cannot open file %s for writing\n", filename);
        return -1;
    }
    fprintf(file, "%s", data);
    fclose(file);
    return 0;
}

/* Read an integer from a file */
int Read_Int_From_File(const char *filename)
{
    int length;
    char *str = Read_File(filename, &length);
    if (!str)
        return -1;
    int value = atoi(str);
    free(str);
    return value;
}

/* Read multi-line file into array of strings (one per line). */
int Read_Lines(const char *filename, char ***lines_out)
{
    FILE *f = fopen(filename, "r");
    if (!f)
    {
        fprintf(stderr, "Error: Cannot open %s\n", filename);
        return 0;
    }

    char **lines = NULL;
    int count = 0;
    char buf[1024];

    while (fgets(buf, sizeof(buf), f))
    {
        int len = strlen(buf);
        while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r' || buf[len - 1] == ' '))
            buf[--len] = '\0';
        if (len == 0)
            continue;

        lines = realloc(lines, (count + 1) * sizeof(char *));
        lines[count] = strdup(buf);
        count++;
    }

    fclose(f);
    *lines_out = lines;
    return count;
}

static void write_bn_list(FILE *out, BIGNUM **values, int count)
{
    for (int i = 0; i < count; i++)
    {
        char *hex = BN_bn2hex(values[i]);
        fprintf(out, "%s\n", hex);
        OPENSSL_free(hex);
    }
}

static void build_tree(
    BIGNUM **secrets,
    int n,
    BN_CTX *ctx,
    const BIGNUM *p,
    const BIGNUM *g,
    BIGNUM **out_key,
    BIGNUM **out_bk,
    BIGNUM **leaf_bks,
    int *leaf_count,
    BIGNUM **internal_bks,
    int *internal_count)
{
    if (n == 1)
    {
        *out_key = BN_dup(secrets[0]);
        *out_bk = BN_new();
        BN_mod_exp(*out_bk, g, *out_key, p, ctx);

        leaf_bks[*leaf_count] = BN_dup(*out_bk);
        (*leaf_count)++;
        return;
    }

    int left_n = (n + 1) / 2;
    int right_n = n / 2;

    BIGNUM *left_key = NULL;
    BIGNUM *left_bk = NULL;
    BIGNUM *right_key = NULL;
    BIGNUM *right_bk = NULL;

    build_tree(secrets, left_n, ctx, p, g,
               &left_key, &left_bk,
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

    internal_bks[*internal_count] = BN_dup(*out_bk);
    (*internal_count)++;

    BN_free(left_key);
    BN_free(left_bk);
    BN_free(right_key);
    BN_free(right_bk);
}
