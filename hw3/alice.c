#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>

char *Read_File(const char *filename, int *length);
unsigned char *PRNG_chacha20(const unsigned char *seed, int seed_len, int out_len);
int Compute_SHA256(const unsigned char *data, int data_len, unsigned char *output);
unsigned char *aes_ctr_encrypt(const unsigned char *key, const unsigned char *pt, int pt_len, int *ct_len);
unsigned char *hmac_sha256(const unsigned char *key, int key_len, const unsigned char *data, int data_len);
int Bytes_to_Hex(const unsigned char *bytes, int byte_len, char *hex);

int main(int argc, char *argv[])
{
    int sharedseed_len;
    unsigned char *sharedseed = (unsigned char *)Read_File(argv[2], &sharedseed_len);
    if (!sharedseed || sharedseed_len != 32)
    {
        fprintf(stderr, "Error: Failed to read shared seed from file %s\n", argv[2]);
        return -1;
    }

    unsigned char *key = PRNG_chacha20(sharedseed, sharedseed_len, 32);
    int messages_len;
    char *messages_hex = Read_File(argv[1], &messages_len);
    if (!messages_hex)
    {
        fprintf(stderr, "Error: Failed to read messages from file %s or invalid format\n", argv[1]);
        free(key);
        return -1;
    }

    FILE *Keys = fopen("Keys.txt", "w");
    FILE *Ciphertexts = fopen("Ciphertexts.txt", "w");
    FILE *IndividualHMACs = fopen("IndividualHMACs.txt", "w");
    FILE *AggregatedHMACs = fopen("AggregatedHMAC.txt", "w");

    unsigned char *agg = NULL;

    char *ptr = NULL;
    char *line = strtok_r(messages_hex, "\n", &ptr);
    while (line)
    {
        int line_len = strlen(line);
        if (line_len > 0 && line[line_len - 1] == '\r')
        {
            line[line_len - 1] = '\0';
            line_len--;
        }
        if (line_len < 1)
        {
            fprintf(stderr, "Error: Invalid message length in file %s\n", argv[1]);
            free(key);
            free(messages_hex);
        }
        int ciphertext_len = 0;
        // Encrypt the message using AES-CTR func
        unsigned char *ciphertext = aes_ctr_encrypt(key, (unsigned char *)line, line_len, &ciphertext_len);

        unsigned char *si = hmac_sha256(key, 32, ciphertext, ciphertext_len);

        if (!agg)
        {
            agg = malloc(32);
            Compute_SHA256(si, 32, agg);
        }
        else
        {
            unsigned char concat[64];
            memcpy(concat, agg, 32);
            memcpy(concat + 32, si, 32);
            Compute_SHA256(concat, 64, agg);
        }

        char key_hex[65], hmac_hex[65];
        char cryptext_hex[ciphertext_len * 2 + 1];
        Bytes_to_Hex(si, 32, hmac_hex);
        Bytes_to_Hex(key, 32, key_hex);
        Bytes_to_Hex(ciphertext, ciphertext_len, cryptext_hex);

        fprintf(Keys, "%s\n", key_hex);
        fprintf(Ciphertexts, "%s\n", cryptext_hex);
        fprintf(IndividualHMACs, "%s\n", hmac_hex);

        free(ciphertext);
        free(si);

        unsigned char next_key[32];
        Compute_SHA256(key, 32, next_key);
        free(key);
        key = malloc(32);
        memcpy(key, next_key, 32);
        line = strtok_r(NULL, "\n", &ptr);
    }

    char agg_hex[65];
    Bytes_to_Hex(agg, 32, agg_hex);
    fprintf(AggregatedHMACs, "%s", agg_hex);

    fclose(Keys);
    fclose(IndividualHMACs);
    fclose(AggregatedHMACs);
    fclose(Ciphertexts);
    free(messages_hex);
    free(agg);
    return 0;
}

// Read File
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
                             buffer[read_size - 1] == '\r' ||
                             buffer[read_size - 1] == ' '))
    {
        buffer[--read_size] = '\0';
    }
    *length = read_size;
    fclose(file);
    return buffer;
}

unsigned char *PRNG_chacha20(const unsigned char *seed, int seed_len, int out_len)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char *out = malloc(out_len);
    unsigned char nonce[16] = {0};
    unsigned char *zeros = calloc(out_len, 1);

    EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, seed, nonce);
    int outl = 0;
    EVP_EncryptUpdate(ctx, out, &outl, zeros, out_len);
    EVP_EncryptFinal_ex(ctx, out + outl, &outl);

    free(zeros);
    EVP_CIPHER_CTX_free(ctx);
    return out;
}

int Compute_SHA256(const unsigned char *data, int data_len, unsigned char *output)
{

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx)
        return -1;
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1)
        return -1;

    if (EVP_DigestUpdate(ctx, data, data_len) != 1)
        return -1;

    if (EVP_DigestFinal_ex(ctx, output, NULL) != 1)
        return -1;

    EVP_MD_CTX_free(ctx);

    return 0;
}

unsigned char *aes_ctr_encrypt(const unsigned char *key, const unsigned char *pt, int pt_len, int *ct_len)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char iv[16] = "abcdefghijklmnop";

    unsigned char *ct = malloc(pt_len);
    int outl1 = 0, outl2 = 0;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, ct, &outl1, pt, pt_len);
    EVP_EncryptFinal_ex(ctx, ct + outl1, &outl2);

    *ct_len = outl1 + outl2;
    EVP_CIPHER_CTX_free(ctx);
    return ct;
}

unsigned char *hmac_sha256(const unsigned char *key, int key_len,
                           const unsigned char *data, int data_len)
{
    unsigned int len = 0;
    unsigned char *out = malloc(SHA256_DIGEST_LENGTH);
    HMAC(EVP_sha256(), key, key_len, data, data_len, out, &len);
    return out; // 32 bytes
}

int Bytes_to_Hex(const unsigned char *bytes, int byte_len, char *hex)
{
    for (int i = 0; i < byte_len; i++)
    {
        sprintf(hex + (i * 2), "%02x", bytes[i]);
    }
    hex[byte_len * 2] = '\0';
    return byte_len * 2;
}