#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/ecdsa.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/rand.h>

/*
 * ============================================================
 * Kerberos Client (File-Based Demo) — ASSIGNMENT TEMPLATE
 * ============================================================
 *
 * IMPORTANT:
 *  - You MUST read from and write to files using the EXACT
 *    filenames specified in this template.
 *  - Do NOT rename files or change their formats.
 *  - The grading scripts rely strictly on these filenames.
 *
 * This program implements the CLIENT SIDE of a simplified
 * Kerberos protocol using files for message passing.
 *
 * The client program is executed multiple times by an
 * external script and must correctly handle different
 * protocol phases depending on which files already exist.
 *
 * ------------------------------------------------------------
 * PROTOCOL PHASES IMPLEMENTED BY THIS CLIENT:
 *
 * 1) AS phase   (Authentication Server)
 * 2) TGS_REQ    (Ticket Granting Service Request)
 * 3) APP_REQ    (Application Server Request)
 *
 * Cryptographic primitives used conceptually:
 *  - ECDSA signatures
 *  - ECDH key agreement
 *  - SHA-256 key derivation
 *  - AES-256 encryption/decryption
 *
 * You are provided helper functions in:
 *      RequiredFunctions.c
 * Study them carefully before implementing this file.
 *
 * ============================================================
 */

#include "RequiredFunctions.c"

int main(int argc, char *argv[])
{

	/* ------------------------------------------------------------
	 * Command-line arguments:
	 *
	 * argv[1] : path to Client temporary private key file
	 * argv[2] : path to Client temporary public key file
	 * argv[3] : path to AS temporary public key file
	 *
	 * These files MUST already exist. Do NOT generate keys here.
	 * ------------------------------------------------------------
	 */
	if (argc != 4)
	{
		fprintf(stderr,
				"Usage: %s <Client_temp_SK> <Client_temp_PK> <AS_temp_PK>\n",
				argv[0]);
		return EXIT_FAILURE;
	}

	const char *client_temp_sk_path = argv[1];
	const char *client_temp_pk_path = argv[2];
	const char *as_temp_pk_path = argv[3];

	/* Buffers for symmetric keys derived during Kerberos */
	unsigned char key_client_as[32];
	unsigned char key_client_tgs[32];
	unsigned char key_client_app[32];

	/* ------------------------------------------------------------
	 * STEP 0: Verify required client temporary key files exist
	 *
	 * The client must already possess a temporary EC key pair.
	 * If either file is missing, abort immediately.
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Check existence of:
	 *        client_temp_sk_path
	 *        client_temp_pk_path
	 *  - Print an error and exit on failure
	 */

	if (!file_exists(client_temp_sk_path) || !file_exists(client_temp_pk_path))
	{
		fprintf(stderr, "Error: Required client temporary key files are missing.\n");
		return EXIT_FAILURE;
	}

	/* ------------------------------------------------------------
	 * STEP 1: Sign Client temporary public key
	 *
	 * The client authenticates itself to the AS by signing its
	 * temporary public key using its long-term private key.
	 *
	 * INPUT:
	 *  - Client_SK.txt          (long-term client private key)
	 *  - client_temp_pk_path    (temporary public key)
	 *
	 * OUTPUT (must always be regenerated):
	 *  - Client_Signature.txt   (hex-encoded ECDSA signature)
	 *
	 * NOTE:
	 *  - Even if the file already exists, regenerate it.
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Use an ECDSA signing helper
	 *  - Sign the CONTENTS of client_temp_pk_path
	 *  - Write the signature in hex format to:
	 *        "Client_Signature.txt"
	 */

	ecdsa_sign_file_to_hex("Client_SK.txt", client_temp_pk_path, "Client_Signature.txt");

	/* ------------------------------------------------------------
	 * STEP 2: Wait for AS response
	 *
	 * The Authentication Server writes AS_REP.txt when ready.
	 * If it does not yet exist, exit gracefully.
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Check if "AS_REP.txt" exists
	 *  - If not, print a status message and exit SUCCESSFULLY
	 */
	if (!file_exists("AS_REP.txt"))
	{
		printf("Waiting for AS response... (AS_REP.txt not found)\n");
		return EXIT_SUCCESS;
	}

	/* ------------------------------------------------------------
	 * STEP 3: Derive Key_Client_AS
	 *
	 * The client derives a shared secret with the AS using ECDH:
	 *
	 *      shared = ECDH(Client_temp_SK, AS_temp_PK)
	 *
	 * Then derives a symmetric key:
	 *
	 *      Key_Client_AS = SHA256(shared)
	 *
	 * This key MUST match the reference key stored in:
	 *      "Key_Client_AS.txt"
	 *
	 * Abort if the derived key does not match.
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Perform ECDH using the two key files
	 *  - Hash the shared secret using SHA-256
	 *  - Read "Key_Client_AS.txt" (hex)
	 *  - Compare values byte-for-byte
	 */
	unsigned char *shared_secret = NULL;
	size_t shared_secret_len = 0;
	ecdh_shared_secret_files(client_temp_sk_path, as_temp_pk_path, &shared_secret, &shared_secret_len);
	sha256_bytes(shared_secret, shared_secret_len, key_client_as);
	free(shared_secret);
	unsigned char expected_key_client_as[32];
	read_hex_file_bytes("Key_Client_AS.txt", &shared_secret, &shared_secret_len);
	if (shared_secret_len != 32 || memcmp(key_client_as, shared_secret, 32) != 0)
	{
		fprintf(stderr, "Error: Derived Key_Client_AS does not match expected value.\n");
		free(shared_secret);
		return EXIT_FAILURE;
	}
	memcpy(expected_key_client_as, shared_secret, 32);
	free(shared_secret);

	/* ------------------------------------------------------------
	 * STEP 4: Decrypt AS_REP
	 *
	 * AS_REP.txt is AES-256 encrypted using Key_Client_AS.
	 *
	 * After decryption, the plaintext contains:
	 *
	 *   [ 32 bytes Key_Client_TGS ] ||
	 *   [ ASCII hex string of TGT ]
	 *
	 * Extract BOTH values.
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - AES-decrypt AS_REP.txt using Key_Client_AS
	 *  - Copy first 32 bytes → key_client_tgs
	 *  - Remaining bytes → TGT (hex string)
	 */
	unsigned char *as_rep_plain = NULL;
	size_t as_rep_plain_len = 0;
	aes256_decrypt_hex_file_to_bytes(key_client_as, "AS_REP.txt", &as_rep_plain, &as_rep_plain_len);
	if (as_rep_plain_len < 32)
	{
		fprintf(stderr, "Error: Decrypted AS_REP plaintext is too short.\n");
		free(as_rep_plain);
		return EXIT_FAILURE;
	}
	memcpy(key_client_tgs, as_rep_plain, 32);
	size_t tgt_hex_len = as_rep_plain_len - 32;
	char *tgt_hex = malloc(tgt_hex_len + 1);
	memcpy(tgt_hex, as_rep_plain + 32, tgt_hex_len);
	tgt_hex[tgt_hex_len] = '\0';
	free(as_rep_plain);

	/* ------------------------------------------------------------
	 * STEP 5: Create TGS_REQ (only once)
	 *
	 * If TGS_REQ.txt does NOT already exist:
	 *
	 *   Auth_Client_TGS = AES(Key_Client_TGS, "Client")
	 *
	 * Write TGS_REQ.txt with EXACTLY THREE lines:
	 *
	 *   line 1: TGT hex
	 *   line 2: Auth_Client_TGS hex
	 *   line 3: Service ID string (plain text): "Service"
	 *
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Check existence of "TGS_REQ.txt"
	 *  - If missing:
	 *      - Encrypt string "Client" using Key_Client_TGS
	 *      - Write all three required lines in order
	 */

	char *auth_client_tgs_hex = NULL;
	if (!file_exists("TGS_REQ.txt"))
	{
		aes256_encrypt_bytes_to_hex_string(
			key_client_tgs,
			(const unsigned char *)"Client",
			strlen("Client"),
			&auth_client_tgs_hex);
		write_text_lines("TGS_REQ.txt", tgt_hex, auth_client_tgs_hex, "Service");
		free(auth_client_tgs_hex);
	}

	/* ------------------------------------------------------------
	 * STEP 6: Wait for TGS response
	 *
	 * TGS writes "TGS_REP.txt" when ready.
	 * If missing, exit gracefully.
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Check existence of "TGS_REP.txt"
	 *  - If not present, print status and exit SUCCESSFULLY
	 */
	if (!file_exists("TGS_REP.txt"))
	{
		printf("Waiting for TGS response... (TGS_REP.txt not found)\n");
		return EXIT_SUCCESS;
	}

	/* ------------------------------------------------------------
	 * STEP 7: Recover Key_Client_App
	 *
	 * TGS_REP.txt format:
	 *
	 *   line 1: Ticket_App (hex)
	 *   line 2: enc_key_client_app (hex, AES under Key_Client_TGS)
	 *
	 * Decrypt line 2 using Key_Client_TGS to recover:
	 *      Key_Client_App (hex → 32 bytes)
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Read second line of TGS_REP.txt
	 *  - AES-decrypt using Key_Client_TGS
	 *  - Convert hex string to raw bytes
	 *  - Store exactly 32 bytes in key_client_app
	 */
	char *tgs_rep_line2 = read_line("TGS_REP.txt", 2);
	unsigned char *key_client_app_plainhex = NULL;
	size_t key_client_app_plainhex_len = 0;
	aes256_decrypt_hex_string_to_bytes(
		key_client_tgs, 
		tgs_rep_line2, 
		&key_client_app_plainhex, 
		&key_client_app_plainhex_len);
	free(tgs_rep_line2);
	char *key_client_app_hex = malloc(key_client_app_plainhex_len + 1);
	memcpy(key_client_app_hex, key_client_app_plainhex, key_client_app_plainhex_len);
	key_client_app_hex[key_client_app_plainhex_len] = '\0';
	free(key_client_app_plainhex);
	unsigned char *key_client_app_bytes = NULL;
	size_t key_client_app_bytes_len = 0;
	hex_to_bytes(key_client_app_hex, &key_client_app_bytes, &key_client_app_bytes_len);
	if (key_client_app_bytes_len != 32)
	{
		fprintf(stderr, "Error: Decrypted Key_Client_App is not 32 bytes.\n");
		free(key_client_app_hex);
		free(key_client_app_bytes);
		return EXIT_FAILURE;
	}
	memcpy(key_client_app, key_client_app_bytes, 32);
	free(key_client_app_bytes);
	free(key_client_app_hex);


	/* ------------------------------------------------------------
	 * STEP 8: Create APP_REQ
	 *
	 *   Auth_Client_App = AES(Key_Client_App, "Client")
	 *
	 * Write APP_REQ.txt with EXACTLY TWO lines:
	 *
	 *   line 1: Ticket_App hex
	 *   line 2: Auth_Client_App hex
	 *
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Encrypt string "Client" using Key_Client_App
	 *  - Read Ticket_App from TGS_REP.txt (line 1)
	 *  - Write both values to "APP_REQ.txt"
	 */

	char *auth_client_app_hex = NULL;
	aes256_encrypt_bytes_to_hex_string(
		key_client_app,
		(const unsigned char *)"Client",
		strlen("Client"),
		&auth_client_app_hex);
	char *tgs_rep_line1 = read_line("TGS_REP.txt", 1);
	write_text_lines("APP_REQ.txt", tgs_rep_line1, auth_client_app_hex, NULL);
	free(auth_client_app_hex);
	free(tgs_rep_line1);
	return EXIT_SUCCESS;
}