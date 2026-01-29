#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/sha.h>

// Function prototypes from demo.c
unsigned char *Read_File(char fileName[], int *fileLen);
void Write_File(char fileName[], char input[], int input_length);
void Convert_to_Hex(char output[], unsigned char input[], int inputlength);
void Show_in_Hex(char name[], unsigned char hex[], int hexlen);
unsigned char *PRNG(unsigned char *seed, unsigned long seedlen, unsigned long prnglen);
unsigned char *Hash_SHA256(unsigned char *input, unsigned long inputlen);

int main()
{
    unsigned char *message = NULL;
    unsigned char *seed = NULL;
    int message_len = 0;
    int seed_len = 0;

    message = Read_File("Message.txt", &message_len);

    if (message_len < 32)
    {
        printf("Message is too short. Must be at least 32 bytes.\n");
        free(message);
        return 1;
    }

    seed = Read_File("SharedSeed.txt", &seed_len);
    if (seed_len != 32)
    {
        printf("Seed length is incorrect. Must be 32 bytes.\n");
        free(message);
        free(seed);
        return 1;
    }

    unsigned char *key = PRNG(seed, 32, message_len);
    printf("Generated key: %d bytes\n", message_len);
    Show_in_Hex("Key", key, message_len); // Key is correct according to CorrectKey1.txt

    char *key_hex = malloc(message_len * 2 + 1);
    Convert_to_Hex(key_hex, key, message_len);
    Write_File("Key.txt", key_hex, message_len * 2);
    free(key_hex);

    unsigned char *criphertext = malloc(message_len);
    for (int i = 0; i < message_len; i++){
        criphertext[i] = message[i] ^ key[i];
    }

    Show_in_Hex("Ciphertext", criphertext, message_len); // Ciphertext

    char *ciphertext_hex = malloc(message_len * 2 + 1);
    Convert_to_Hex(ciphertext_hex, criphertext, message_len);
    Write_File("Ciphertext.txt", ciphertext_hex, message_len * 2);

    unsigned char *alice_hash = Hash_SHA256(message, message_len);
    Show_in_Hex("SHA-256 Hash", alice_hash, SHA256_DIGEST_LENGTH);

    int bob_hash_len = 0;
    unsigned char *bob_hash = NULL;
    bob_hash = Read_File("Hash.txt", &bob_hash_len);
    if (bob_hash_len != SHA256_DIGEST_LENGTH * 2) // hex format
    {
        printf("Bob's hash length is incorrect. Must be %d hex characters.\n", SHA256_DIGEST_LENGTH * 2);
        free(message);
        free(seed);
        free(key);
        free(criphertext);
        free(alice_hash);
        free(bob_hash);
        return 1;
    }

    unsigned char bob_hash_binary[SHA256_DIGEST_LENGTH];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        sscanf((char *)&bob_hash[i * 2], "%2hhx", &bob_hash_binary[i]);
    }

    Show_in_Hex("Bob's SHA-256 Hash", bob_hash_binary, SHA256_DIGEST_LENGTH);

    int match = 1;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        if (alice_hash[i] != bob_hash_binary[i])
        {
            match = 0;
            break;
        }
    }

    if (match)
    {
        printf("Hashes match! Message integrity verified.\n");
    }
    else
    {
        printf("Hashes do not match! Message integrity compromised.\n");
    }

    free(message);
    free(seed);
    free(key);
    free(criphertext);
    free(alice_hash);
    free(bob_hash);
    return 0;
}