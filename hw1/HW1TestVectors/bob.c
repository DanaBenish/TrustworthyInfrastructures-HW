// Header files
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/sha.h>

// Include helper function implementations
#include "demo.c"

// Function prototypes from demo.c are provided by the include above

// Functions I created
unsigned char *Hex_to_Bytes(unsigned char *hex, int hexlen);
int Decimal_value(unsigned char c);

int main(int argc, char *argv[])
{

    const char *seed_file = (argc > 1) ? argv[1] : "SharedSeed.txt";
    const char *ciphertext_file = "Ciphertext.txt";

    // read ciphertext
    // convert from hex to byte array
    // a byte = 8 bits, hex = 4 bits, 8/4 = 2, need half as many slots
    int ctLen = 0;
    unsigned char *ctfile = Read_File((char *)ciphertext_file, &ctLen);
    unsigned char *bytes = Hex_to_Bytes(ctfile, ctLen);
    int bytesLen = ctLen / 2;

    // read sharedseed.txt
    int ssLen = 0;
    unsigned char *ssfile = Read_File((char *)seed_file, &ssLen);

    // use prng to create a key from shared.seed txt (equal size message)
    unsigned char *prng = PRNG(ssfile, ssLen, bytesLen);

    // compute the plaintext
    unsigned char *plaintext = malloc(bytesLen);
    for (int i = 0; i < bytesLen; i++)
    {
        plaintext[i] = bytes[i] ^ prng[i];
    } //  plain text = cyphertext XOR prngkey

    // write plain text in file
    Write_File("Plaintext.txt", (char *)plaintext, bytesLen);

    // use HASH_SHA256 of plain text and write the hash in a hex format
    unsigned char *Hash = Hash_SHA256(plaintext, bytesLen);
    unsigned char *Hex_Hash = (unsigned char *)malloc(SHA256_DIGEST_LENGTH * 2 + 1); // each byte = 8, hex = 4, need 2 times the place + null terminator
    Convert_to_Hex((char *)Hex_Hash, Hash, SHA256_DIGEST_LENGTH);
    Write_File("Hash.txt", (char *)Hex_Hash, SHA256_DIGEST_LENGTH * 2);

    // free all allocated memory
    free(ctfile);
    free(bytes);
    free(ssfile);
    free(prng);
    free(plaintext);
    free(Hash);
    free(Hex_Hash);

    return 0;
}

/*============================
        Hex to Bytes
==============================*/
unsigned char *Hex_to_Bytes(unsigned char *hex, int hexlen)
{
    int bytesLen = hexlen / 2;
    unsigned char *bytes = (unsigned char *)malloc(bytesLen);
    for (int i = 0; i < bytesLen; i++)
    {
        int high = Decimal_value(hex[2 * i]);
        int low = Decimal_value(hex[2 * i + 1]);
        if (high < 0)
            high = 0;
        if (low < 0)
            low = 0;
        bytes[i] = (unsigned char)((high << 4) | low);
    }
    return bytes;
}

/*============================
        Decimal Value
==============================*/
int Decimal_value(unsigned char c)
{
    if (c >= '0' && c <= '9')
    {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f')
    {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F')
    {
        return c - 'A' + 10;
    }
    return -1;
}