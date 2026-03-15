#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/ecdsa.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
/*
 * ============================================================
 * Kerberos Ticket Granting Server (TGS) — ASSIGNMENT TEMPLATE
 * ============================================================
 *
 * IMPORTANT:
 *  - You MUST read from and write to files using the EXACT
 *    filenames specified in this template.
 *  - Do NOT rename files, reorder lines, or alter formats.
 *  - Automated grading scripts depend on strict filenames
 *    and exact file structure.
 *
 * This program implements the Ticket Granting Server (TGS)
 * portion of a simplified, file-based Kerberos protocol.
 *
 * All long-term keys and all session keys are assumed to
 * already exist on disk. The TGS must NOT generate keys.
 *
 * ------------------------------------------------------------
 * OVERALL FLOW (TGS PHASE):
 *
 * 1) Receive and parse TGS_REQ
 * 2) Decrypt and validate the Ticket Granting Ticket (TGT)
 * 3) Verify the client authenticator
 * 4) Issue a service ticket (Ticket_App)
 * 5) Encrypt and return Key_Client_App
 *
 * Cryptographic primitives used conceptually:
 *  - AES-256 encryption/decryption (ECB mode in this demo)
 *
 * You are provided helper functions in:
 *      RequiredFunctions.c
 * Study them carefully before implementing this file.
 *
 * ============================================================
 */

#include "RequiredFunctions.c"

int main(int argc, char *argv[]) {

    if (argc != 6) {
        fprintf(stderr,
                "Usage: %s <TGS_REQ> <Key_AS_TGS> <Key_Client_TGS> <Key_Client_App> <Key_TGS_App>\n",
                argv[0]);
        return EXIT_FAILURE;
    }

    const char *tgs_req_path        = argv[1];
    const char *key_as_tgs_path     = argv[2];
    const char *key_client_tgs_path = argv[3];  
    const char *key_client_app_path = argv[4];
    const char *key_tgs_app_path    = argv[5];

   /* ------------------------------------------------------------
	 * STEP 0: Wait for TGS request
	 *
	 * If the TGS request file does not yet exist, print:
	 *
	 *      "TGS_REQ not created"
	 *
	 * and exit gracefully.
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Check existence of tgs_req_path
	 *  - If missing, print required message and exit
	 */
    if (file_exists(tgs_req_path) == 0) {
        printf("TGS_REQ not created");
        return 1;
    }
    printf("TGS_REQ received\n");

    /* ------------------------------------------------------------
	 * STEP 1: Read and decrypt the Ticket Granting Ticket (TGT)
	 *
	 * TGS_REQ.txt format:
	 *
	 *   line 1: TGT (hex)
	 *   line 2: Auth_Client_TGS (hex)
	 *   line 3: Service ID (plain text, ignored here)
	 *
	 * The TGT is encrypted under the AS–TGS shared key:
	 *      Key_AS_TGS.txt
	 *
	 * Decrypted TGT plaintext format:
	 *
	 *      clientID || Key_Client_TGS_hex
	 *
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Read line 1 from TGS_REQ.txt
	 *  - Read Key_AS_TGS.txt (32 bytes)
	 *  - AES-decrypt the TGT
	 *  - Treat the result as ASCII data
	 */
    char *tgs_line1  = read_line(tgs_req_path, 1);
    char *key_as_tgs = read_line(key_as_tgs_path, 1);

    /* Convert Key_AS_TGS hex -> raw bytes */
    unsigned char *key_bytes = NULL;
    size_t key_bytes_len = 0;
    if (!hex_to_bytes(key_as_tgs, &key_bytes, &key_bytes_len) || key_bytes_len != 32) {
        fprintf(stderr, "Bad Key_AS_TGS\n");
        free(key_as_tgs);
        free(tgs_line1);
        return EXIT_FAILURE;
    }
    free(key_as_tgs);

    /* Decrypt TGT using aes256_decrypt_hex_string_to_bytes */
    unsigned char *decrypted_tgt_bytes = NULL;
    size_t decrypted_tgt_len = 0;
    if (!aes256_decrypt_hex_string_to_bytes(key_bytes, tgs_line1, &decrypted_tgt_bytes, &decrypted_tgt_len)) {
        fprintf(stderr, "Failed to decrypt TGT\n");
        free(key_bytes);
        free(tgs_line1);
        return EXIT_FAILURE;
    }
    free(key_bytes);
    free(tgs_line1);

    /* Null-terminate so we can treat it as a string */
    decrypted_tgt_bytes = realloc(decrypted_tgt_bytes, decrypted_tgt_len + 1);
    decrypted_tgt_bytes[decrypted_tgt_len] = '\0';

    char *decrypted_tgt = (char *)decrypted_tgt_bytes;
    int plain_len = (int)decrypted_tgt_len;

    /* Strip trailing padding/control bytes */
    while (plain_len > 0 && (unsigned char)decrypted_tgt[plain_len - 1] < 32) {
        decrypted_tgt[plain_len - 1] = '\0';
        plain_len--;
    }

    /* ------------------------------------------------------------
	 * STEP 2: Parse client identity and Key_Client_TGS
	 *
	 * From decrypted TGT plaintext:
	 *  - The LAST 64 characters represent Key_Client_TGS in hex
	 *  - Everything before that is the client ID
	 *
	 * Validate:
	 *  - Key_Client_TGS is exactly 256 bits
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Split decrypted TGT plaintext
	 *  - Convert Key_Client_TGS hex → raw bytes
	 *  - Abort if parsing or conversion fails
	 */
    if (plain_len < 64) {
        fprintf(stderr, "Decrypted TGT too short\n");
        free(decrypted_tgt_bytes);
        return EXIT_FAILURE;
    }

    int client_id_len = plain_len - 64;

    char *client_id = (char *)malloc(client_id_len + 1);
    memcpy(client_id, decrypted_tgt, client_id_len);
    client_id[client_id_len] = '\0';

    char *key_client_tgs_hex = (char *)malloc(65);
    memcpy(key_client_tgs_hex, decrypted_tgt + client_id_len, 64);
    key_client_tgs_hex[64] = '\0';

    free(decrypted_tgt_bytes);

    /* Convert Key_Client_TGS hex raw bytes (needed for Step 3 and Step 6) */
    unsigned char *key_client_tgs_bytes = NULL;
    size_t key_client_tgs_len = 0;
    if (!hex_to_bytes(key_client_tgs_hex, &key_client_tgs_bytes, &key_client_tgs_len) || key_client_tgs_len != 32) {
        fprintf(stderr, "Failed to convert Key_Client_TGS hex to bytes\n");
        free(client_id);
        free(key_client_tgs_hex);
        return EXIT_FAILURE;
    }
    free(key_client_tgs_hex);

    
	/* ------------------------------------------------------------
	 * STEP 3: Verify client authenticator
	 *
	 * Auth_Client_TGS is found on line 2 of TGS_REQ.txt.
	 *
	 * It is encrypted using Key_Client_TGS and should
	 * decrypt to a value identifying the client.
	 *
	 * NOTE:
	 *  - For this demo, successful decryption is sufficient.
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Read line 2 from TGS_REQ.txt
	 *  - AES-decrypt using Key_Client_TGS
	 *  - Treat failure as authentication failure
	 */

    char *auth_hex = read_line(tgs_req_path, 2);

    unsigned char *auth_plain = NULL;
    size_t auth_plain_len = 0;
    if (!aes256_decrypt_hex_string_to_bytes(key_client_tgs_bytes, auth_hex, &auth_plain, &auth_plain_len)) {
        fprintf(stderr, "Failed to decrypt authenticator\n");
        free(auth_hex);
        free(key_client_tgs_bytes);
        free(client_id);
        return EXIT_FAILURE;
    }
    free(auth_hex);

    auth_plain = realloc(auth_plain, auth_plain_len + 1);
    auth_plain[auth_plain_len] = '\0';
    free(auth_plain);

    /* ------------------------------------------------------------
	 * STEP 4: Load pre-generated Key_Client_App
	 *
	 * The TGS does NOT generate a new application session key.
	 * Instead, it reads an existing one from:
	 *
	 *      Key_Client_App.txt
	 *
	 * This file must contain exactly 256 bits (32 bytes).
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Read Key_Client_App.txt (hex)
	 *  - Validate length
	 *  - Store raw bytes locally
	 */
    char *key_client_app_hex = read_line(key_client_app_path, 1);
    unsigned char *key_client_app_bytes = NULL;
    size_t key_client_app_len = 0;
    if (!hex_to_bytes(key_client_app_hex, &key_client_app_bytes, &key_client_app_len) || key_client_app_len != 32) {
        fprintf(stderr, "Bad Key_Client_App\n");
        free(key_client_app_hex);
        free(key_client_tgs_bytes);
        free(client_id);
        return EXIT_FAILURE;
    }

    /* ------------------------------------------------------------
	 * STEP 5: Build and encrypt Ticket_App
	 *
	 * Ticket_App plaintext format:
	 *
	 *      clientID || Key_Client_App_hex
	 *
	 * Ticket_App is encrypted under the TGS–App shared key:
	 *
	 *      Key_TGS_App.txt
	 *
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Read Key_TGS_App.txt (32 bytes)
	 *  - Concatenate client ID and Key_Client_App hex
	 *  - AES-encrypt using Key_TGS_App
	 *  - Hex-encode ciphertext → Ticket_App
	 */
	int ticket_plain_len = client_id_len + 64;
    unsigned char *ticket_plain = (unsigned char *)malloc(ticket_plain_len);
    memcpy(ticket_plain, client_id, client_id_len);
    memcpy(ticket_plain + client_id_len, key_client_app_hex, 64);

    /* Load Key_TGS_App */
    char *key_tgs_app_hex = read_line(key_tgs_app_path, 1);
    unsigned char *key_tgs_app_bytes = NULL;
    size_t key_tgs_app_len = 0;
    if (!hex_to_bytes(key_tgs_app_hex, &key_tgs_app_bytes, &key_tgs_app_len) || key_tgs_app_len != 32) {
        free(key_tgs_app_hex);
        free(ticket_plain);
        free(key_client_app_hex);
        free(key_client_app_bytes);
        free(key_client_tgs_bytes);
        free(client_id);
        return EXIT_FAILURE;
    }
    free(key_tgs_app_hex);

    /* Encrypt using aes256_encrypt_bytes_to_hex_string */
    char *ticket_app_hex = NULL;
    aes256_encrypt_bytes_to_hex_string(key_tgs_app_bytes, ticket_plain, ticket_plain_len, &ticket_app_hex);
        
    free(ticket_plain);
    free(key_tgs_app_bytes);

	/* ------------------------------------------------------------
	 * STEP 6: Encrypt Key_Client_App for the client
	 *
	 * Encrypt:
	 *
	 *      Key_Client_App_hex
	 *
	 * using:
	 *
	 *      Key_Client_TGS
	 *
	 * Result:
	 *  - enc_key_client_app (hex)
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - AES-encrypt Key_Client_App hex using Key_Client_TGS
	 *  - Hex-encode the ciphertext
	 */

   
    char *enc_key_client_app_hex = NULL;
    aes256_encrypt_bytes_to_hex_string(key_client_tgs_bytes, (unsigned char *)key_client_app_hex, 64, &enc_key_client_app_hex);
    free(key_client_tgs_bytes);
    free(key_client_app_hex);
    free(key_client_app_bytes);
/* ------------------------------------------------------------
	 * STEP 7: Write TGS_REP.txt
	 *
	 * Output file format (EXACT):
	 *
	 *   line 1: Ticket_App hex
	 *   line 2: enc_key_client_app hex
	 *
	 * Filename MUST be:
	 *      "TGS_REP.txt"
	 *
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Write exactly two lines to TGS_REP.txt
	 *  - Preserve order and formatting
	 */

    
    FILE *rep = fopen("TGS_REP.txt", "w");
    if (!rep) {
        return EXIT_FAILURE;
    }
    fprintf(rep, "%s\n", ticket_app_hex);
    fprintf(rep, "%s\n", enc_key_client_app_hex);
    fclose(rep);

    free(ticket_app_hex);
    free(enc_key_client_app_hex);
    free(client_id);

    return EXIT_SUCCESS;
}