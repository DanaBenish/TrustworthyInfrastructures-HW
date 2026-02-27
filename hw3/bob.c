//Goal: Bob writes the decrypted plaintexts in "Plaintexts.txt"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
char* Read_File(const char *filename, int *length);
int Write_File(const char *filename, const char *data);
int Hex_to_Bytes(const char *hex, unsigned char *bytes, int hex_len);
int Bytes_to_Hex(const unsigned char *bytes, int byte_len, char *hex);
int Compute_SHA256(const unsigned char *data, int data_len, unsigned char *output);
int Read_Int_From_File(const char *filename);
int Write_Int_To_File(const char *filename, int value);
void Print_Hex(const char *label, const unsigned char *data, int len);


int main(int argc, char *argv[3]){
    //read files and get lengths 
    int seed_length = 0;
    char * shared_seed = Read_File(argv[1], &seed_length);
   
    //read cipher text for hmac matching 
    int cipher_length = 0;
    char * cipher_texts = Read_File(argv[2], &cipher_length);
   
    //read cipher text for decryption
    int cipher_length2 = 0;
    char * cipher_texts2 = Read_File(argv[2], &cipher_length2);
   
    //read hmac 
    int hmac_length = 0;
    char * aggregated_hmac = Read_File(argv[3], &hmac_length);
    
    //derive k1 using ChaCha20 PRNG (seed as key)
    unsigned char seedkey[32] = {0};
    //make sure it is 32 bytes or less
    memcpy(seedkey, shared_seed, seed_length > 32 ? 32 : seed_length);
    unsigned char current_key[32] = {0};
    unsigned char nonce[16] = {0};
    unsigned char input[32] = {0};
    int output_len = 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, seedkey, nonce);
    EVP_EncryptUpdate(ctx, current_key, &output_len, input, sizeof(input));
    EVP_CIPHER_CTX_free(ctx);

    unsigned char S_previous[32] = {0}; 
    unsigned char k1[32];
    memcpy(k1, current_key, 32);
    //echo print k1 
    //Print_Hex("k1", current_key, 32);

    //For every ciphertext Ci, i = 1, . . . , n, Bob computes:
    char *saveptr = NULL;
    char *line = strtok_r(cipher_texts, "\n", &saveptr);
    //iterartion in loop 
    int i = 0;

    while (line != NULL) {
        size_t line_len = strlen(line);
        
        unsigned char *ci_bytes = malloc(line_len / 2);
        int byte_len = Hex_to_Bytes(line, ci_bytes, (int)line_len);

        // 1) 1. Individual HMAC: Si = HMAC(ki, Ci).
        unsigned char Si[32];
        unsigned int Si_len = 0;
        HMAC(EVP_sha256(), current_key, 32, ci_bytes, byte_len, Si, &Si_len);
        //Print_Hex("Si", Si, Si_len);

        free(ci_bytes);

        // 2) Aggregate HMAC: S1,i= H(S1,i−1||Si)
        if (i == 0) {
            // S1,1 = H(S1)
            Compute_SHA256(Si, 32, S_previous);
        } else {
            // S1,i = H(S1,i-1 || Si)
            unsigned char S1_i[64];
            memcpy(S1_i, S_previous, 32);
            memcpy(S1_i + 32, Si, 32);
            Compute_SHA256(S1_i, 64, S_previous);
        }
        //Print_Hex("S_agg", S_previous, 32);

        // 3) Update ki+1 = H(ki) similar to step 4 above
        Compute_SHA256(current_key, 32, current_key);
        i++;
        line = strtok_r(NULL, "\n", &saveptr);
    }
    /*Then, Bob compares the computed aggregated HMAC with the received aggregated HMAC to verify the
    integrity of the ciphertexts. If the verification failed, your code should not do any decryption because the data
    has been tampered with! (We will test your code with a wrong aggregated HMAC and it shouldn’t do any
    decryption!)*/
    unsigned char bob_agg_hmac[32];
    Hex_to_Bytes(aggregated_hmac, bob_agg_hmac, hmac_length);
    int error = 0;

    //go one by one to find any difference
    for (int i = 0; i < 32; i++) {
        if (S_previous[i] != bob_agg_hmac[i]) {
            error = 1;
            break;
        }
    }

    if (error) {
        fprintf(stderr, "Verification Failed.\n");
        return 1;
    }
    
    /*If the final aggregate HMAC matches with the one that the client sent, then for every ciphertext Ci, i = 1, . . . , n, he computes:
    Recover plaintext Mi = Dec(ki, Ci). for i = 1, . . . , n. using the keys created in step 4 above.
    Equivalently, this step is the inverse of the encryption of Alice in step */
    // 0) Reset key to k1 before decryption
    char *saveptr2 = NULL;
    //get k1 for decryption
    memcpy(current_key, k1, 32);


    // open output file
    FILE *out = fopen("Plaintexts.txt", "w");

    // Loop ciphertexts 
    for (char *line2 = strtok_r(cipher_texts2, "\n", &saveptr2);
        line2 != NULL;
        line2 = strtok_r(NULL, "\n", &saveptr2)) {
        
        // skip empty lines 
        size_t line_len2 = strlen(line2);
        if (line_len2 == 0) continue;

        //turn into bytes half size of hex
        unsigned char *ci_bytes = malloc(line_len2 / 2);
        int byte_len = Hex_to_Bytes(line2, ci_bytes, (int)line_len2);
        
        //decryput using iv
        unsigned char iv[16] = "abcdefghijklmnop";

        unsigned char plaintext[1024] = {0};
        int pt_len = 0;
        int final_len = 0;
        
        //decrypt using AES-256-CTR mode with current key and IV
        EVP_CIPHER_CTX *dctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(dctx, EVP_aes_256_ctr(), NULL, current_key, iv);
        EVP_EncryptUpdate(dctx, plaintext, &pt_len, ci_bytes, byte_len);
        EVP_EncryptFinal_ex(dctx, plaintext + pt_len, &final_len);
        EVP_CIPHER_CTX_free(dctx);
        pt_len += final_len;
        
        //print to file
        fprintf(out, "%.*s\n", pt_len, plaintext);
        //increment ke
        Compute_SHA256(current_key, 32, current_key);
        free(ci_bytes);
            }

            fclose(out);


    free(shared_seed);
    free(cipher_texts);
    free(aggregated_hmac);  
    free(cipher_texts2);
    return 0; 
}





//Past Useful Functions 
/*
File I/O Functions
*/
// Read File
char* Read_File(const char *filename, int *length) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        fprintf(stderr, "Error: Cannot open file %s\n", filename);
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    char *buffer = (char*)malloc(file_size + 1);
    if (!buffer) {
        fclose(file);
        return NULL;
    }

    size_t read_size = fread(buffer, 1, file_size, file);
    buffer[read_size] = '\0';

    // Remove trailing whitespace
    while (read_size > 0 &&
          (buffer[read_size - 1] == '\n' ||
           buffer[read_size - 1] == '\r' ||
           buffer[read_size - 1] == ' ')) {
        buffer[--read_size] = '\0';
    }

    *length = read_size;
    fclose(file);
    return buffer;
}


// write string to file
int Write_File(const char *filename, const char *data) {
    FILE *file = fopen(filename, "w");
    if (!file) {
        fprintf(stderr, "Error: Cannot open file %s for writing\n", filename);
        return -1;
    }

    fprintf(file, "%s", data);
    fclose(file);
    return 0;
}


/*
Hex Conversion Functions
*/

// Convert hex string to byte array
int Hex_to_Bytes(const char *hex, unsigned char *bytes, int hex_len) {
    if (hex_len % 2 != 0) {
        fprintf(stderr, "Error: Hex string length must be even\n");
        return -1;
    }

    int byte_len = hex_len / 2;

    for (int i = 0; i < byte_len; i++) {
        unsigned int byte;

        if (sscanf(hex + (i * 2), "%2x", &byte) != 1) {
            fprintf(stderr, "Error: Invalid hex character at position %d\n", i * 2);
            return -1;
        }

        bytes[i] = (unsigned char)byte;
    }

    return byte_len;
}


// Convert byte array to hex string
int Bytes_to_Hex(const unsigned char *bytes, int byte_len, char *hex) {
    for (int i = 0; i < byte_len; i++) {
        sprintf(hex + (i * 2), "%02x", bytes[i]);
    }

    hex[byte_len * 2] = '\0';
    return byte_len * 2;
}


/*
Cryptographic Functions
*/

// SHA256 hash
int Compute_SHA256(const unsigned char *data,
                   int data_len,
                   unsigned char *output){

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();

    if (!ctx) {
        return -1;
    }

    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data, data_len);
    EVP_DigestFinal_ex(ctx, output, NULL);

    EVP_MD_CTX_free(ctx);
    return 0;
}


/*
Utility Functions
*/

int Read_Int_From_File(const char *filename){
    int length;
    char *str = Read_File(filename, &length);
    if (!str) return -1;

    int value = atoi(str);
    free(str);

    return value;
}


int Write_Int_To_File(const char *filename, int value){
    char buffer[32];
    sprintf(buffer, "%d", value);
    return Write_File(filename, buffer);
}


void Print_Hex(const char *label, const unsigned char *data, int len){
    printf("%s: ", label);
    for (int i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}