#include <stdlib.h>
#include <stdio.h>

#include <openssl/sha.h>

int main()
{
    unsigned char data[] = "Hello, World!";
    unsigned char hash[SHA256_DIGEST_LENGTH];

    SHA256(data, sizeof(data), hash);

    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        printf("%02x", hash[i]);
    }

    return 0;
}
