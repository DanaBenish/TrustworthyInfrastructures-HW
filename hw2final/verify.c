#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

char *Read_File(const char *filename, int *length);
int Read_Int_From_File(const char *filename);
int Hex_to_Bytes(const char *hex, unsigned char *bytes, int hex_len);
int Compute_SHA256(const unsigned char *data, int data_len, unsigned char *output);
int Check_Leading_Zero_Bits(unsigned char *hash, int k);
int Write_File(const char *filename, const char *data);
int Write_Int_To_File(const char *filename, int value);

int main(int argc, char *argv[])
{
    int challenge_hex_len;
    char *puzzle_challenge_hex = Read_File(argv[1], &challenge_hex_len); // read the challege i generated in server
    int k = Read_Int_From_File(argv[2]);

    unsigned char challenge_bytes[32];
    int challenge_bytes_len = Hex_to_Bytes(puzzle_challenge_hex, challenge_bytes, challenge_hex_len);

    char *solution_nonce_hex = Read_File(argv[3], &challenge_hex_len);
    unsigned char solution_nonce_bytes[8];
    int nonce_bytes_len = Hex_to_Bytes(solution_nonce_hex, solution_nonce_bytes, challenge_hex_len);

    unsigned char *data = (unsigned char *)malloc(challenge_bytes_len + 8); // challenge + nonce (8 bytes)
    memcpy(data, challenge_bytes, challenge_bytes_len);
    memcpy(data + challenge_bytes_len, solution_nonce_bytes, nonce_bytes_len);

    unsigned char hash[32];
    Compute_SHA256(data, challenge_bytes_len + nonce_bytes_len, hash);

    free(puzzle_challenge_hex);
    free(solution_nonce_hex);
    free(data);

    if (Check_Leading_Zero_Bits(hash, k)){
        Write_File("verification_result.txt", "ACCEPT\n");
        exit(0);
    } else {
        Write_File("verification_result.txt", "REJECT\n");
        exit(1);
    }
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

    // Remove trailing whitespace
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

int Check_Leading_Zero_Bits(unsigned char *hash, int k)
{

    int full_bytes = k / 8;
    int remaining_bits = k % 8;

    // Check full zero bytes
    for (int i = 0; i < full_bytes; i++)
    {
        if (hash[i] != 0)
            return 0;
    }

    // Check remaining bits
    if (remaining_bits > 0)
    {
        unsigned char mask = 0xFF << (8 - remaining_bits);

        if ((hash[full_bytes] & mask) != 0)
            return 0;
    }

    return 1;
}

int Hex_to_Bytes(const char *hex, unsigned char *bytes, int hex_len)
{
    if (hex_len % 2 != 0)
    {
        fprintf(stderr, "Error: Hex string length must be even\n");
        return -1;
    }

    int byte_len = hex_len / 2;
    for (int i = 0; i < byte_len; i++)
    {
        unsigned int byte;
        if (sscanf(hex + (i * 2), "%2x", &byte) != 1)
        {
            fprintf(stderr, "Error: Invalid hex character at position %d\n", i * 2);
            return -1;
        }
        bytes[i] = (unsigned char)byte;
    }

    return byte_len;
}

// Write string to file
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

int Write_Int_To_File(const char *filename, int value)
{
    char buffer[32];
    sprintf(buffer, "%d", value);
    return Write_File(filename, buffer);
}
