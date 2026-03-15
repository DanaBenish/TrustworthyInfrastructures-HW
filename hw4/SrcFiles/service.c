#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/ecdsa.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/rand.h>

/*
 * ============================================================
 * Kerberos Service / Application Server — ASSIGNMENT TEMPLATE
 * ============================================================
 *
 * IMPORTANT:
 *  - You MUST read from and write to files using the EXACT
 *    filenames specified in this template.
 *  - Do NOT rename files, reorder lines, or alter formats.
 *  - Automated grading scripts rely strictly on filenames
 *    and file contents.
 *
 * This program implements the SERVICE side of a simplified,
 * file-based Kerberos protocol.
 *
 * The service validates an application request (APP_REQ)
 * sent by a client and produces an application response
 * (APP_REP.txt).
 *
 * All long-term keys and session keys are assumed to already
 * exist. The service must NOT generate any keys.
 *
 * ------------------------------------------------------------
 * OVERALL FLOW (SERVICE / APP PHASE):
 *
 * 1) Wait for APP_REQ from the client
 * 2) Decrypt Ticket_App using the TGS–service shared key
 * 3) Extract client identity and Key_Client_App
 * 4) Decrypt and verify the client authenticator
 * 5) Accept or reject the request
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

	/* ------------------------------------------------------------
	 * Command-line arguments:
	 *
	 * argv[1] : APP_REQ.txt
	 * argv[2] : Key_TGS_App.txt
	 *
	 * Both files MUST already exist.
	 * ------------------------------------------------------------
	 */
	if (argc != 3) {
		fprintf(stderr,
		        "Usage: %s <APP_REQ file> <Key_TGS_App file>\n",
		        argv[0]);
		return EXIT_FAILURE;
	}

	const char *app_req_path     = argv[1];
	const char *key_tgs_app_path = argv[2];

	/* ------------------------------------------------------------
	 * STEP 0: Wait for application request
	 *
	 * If APP_REQ.txt does not exist, print:
	 *
	 *      "Service not requested yet"
	 *
	 * and exit gracefully.
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Check existence of app_req_path
	 *  - If missing, print required message and exit
	 */
	if(file_exists(argv[1])== 0){
		printf("Service not requested yet");
		return 1;
	}

	printf("Service requested\n");

	/* ------------------------------------------------------------
	 * STEP 1: Load TGS–Service shared key
	 *
	 * Read the long-term key shared between the TGS
	 * and the service:
	 *
	 *      Key_TGS_App.txt
	 *
	 * This key MUST be exactly 256 bits (32 bytes).
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Read Key_TGS_App.txt (hex)
	 *  - Validate that it is exactly 32 bytes
	 *  - Abort on failure
	 */
	char *key_tgs_app_hex = read_line(key_tgs_app_path, 1);
	
 
	unsigned char *key_tgs_app_bytes = NULL;
	size_t key_tgs_app_len = 0;
	if (!hex_to_bytes(key_tgs_app_hex, &key_tgs_app_bytes, &key_tgs_app_len)) {
		fprintf(stderr, "Failed to convert Key_TGS_App to bytes\n");
		free(key_tgs_app_hex);
		return EXIT_FAILURE;
	}
	if (key_tgs_app_len != 32) {
		fprintf(stderr, "Key_TGS_App is not 32 bytes\n");
		free(key_tgs_app_hex);
		free(key_tgs_app_bytes);
		return EXIT_FAILURE;
	}
	free(key_tgs_app_hex);
 
 
	/* ------------------------------------------------------------
	 * STEP 2: Decrypt Ticket_App
	 *
	 * APP_REQ.txt format:
	 *
	 *   line 1: Ticket_App (hex)
	 *   line 2: Auth_Client_App (hex)
	 *
	 * Ticket_App was encrypted by the TGS under Key_TGS_App.
	 *
	 * Decrypted Ticket_App plaintext format:
	 *
	 *      clientID || Key_Client_App_hex
	 *
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Read line 1 from APP_REQ.txt
	 *  - AES-decrypt using Key_TGS_App
	 *  - Treat the result as ASCII data
	 */
	char *ticket_app_hex = read_line(app_req_path, 1);

	unsigned char *ticket_plain = NULL;
	size_t ticket_plain_len = 0;
	if (!aes256_decrypt_hex_string_to_bytes(key_tgs_app_bytes, ticket_app_hex, &ticket_plain, &ticket_plain_len)) {
		fprintf(stderr, "Failed to decrypt Ticket_App\n");
		free(ticket_app_hex);
		free(key_tgs_app_bytes);
		return EXIT_FAILURE;
	}
	free(ticket_app_hex);
	free(key_tgs_app_bytes);
 
	// Null-terminate so it can treat like as tring 
	ticket_plain = realloc(ticket_plain, ticket_plain_len + 1);
	ticket_plain[ticket_plain_len] = '\0';
 
	char *decrypted_ticket = (char*)ticket_plain;
	int plain_len = (int)ticket_plain_len;
 
	// Strip trailing padding
	while (plain_len > 0 && (unsigned char)decrypted_ticket[plain_len - 1] < 32) {
		decrypted_ticket[plain_len - 1] = '\0';
		plain_len--;
	}
 

 
	/* ------------------------------------------------------------
	 * STEP 3: Parse client identity and Key_Client_App
	 *
	 * From decrypted Ticket_App plaintext:
	 *  - The LAST 64 characters represent Key_Client_App (hex)
	 *  - Everything before that is clientID_1
	 *
	 * Validate:
	 *  - Key_Client_App is exactly 256 bits
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Split the plaintext into clientID_1 and key hex
	 *  - Convert Key_Client_App hex → raw bytes
	 *  - Abort on malformed data
	 */
	if (plain_len < 64) {
		fprintf(stderr, "Decrypted Ticket_App too short\n");
		free(ticket_plain);
		return EXIT_FAILURE;
	}
 
	int client_id_len = plain_len - 64;
	char *client_id_1 = (char*)malloc(client_id_len + 1);
	for (int i = 0; i < client_id_len; i++) {
		client_id_1[i] = decrypted_ticket[i];
	}
	client_id_1[client_id_len] = '\0';
 
	char *key_client_app_hex = (char*)malloc(65);
	for (int i = 0; i < 64; i++) {
		key_client_app_hex[i] = decrypted_ticket[client_id_len + i];
	}
	key_client_app_hex[64] = '\0';
 
 
	free(ticket_plain);
 
	unsigned char *key_client_app_bytes = NULL;
	size_t key_client_app_len = 0;
	if (!hex_to_bytes(key_client_app_hex, &key_client_app_bytes, &key_client_app_len)) {
		fprintf(stderr, "Failed to convert Key_Client_App to bytes\n");
		free(client_id_1);
		free(key_client_app_hex);
		return EXIT_FAILURE;
	}
	if (key_client_app_len != 32) {
		fprintf(stderr, "Key_Client_App is not 32 bytes\n");
		free(client_id_1);
		free(key_client_app_hex);
		free(key_client_app_bytes);
		return EXIT_FAILURE;
	}
	free(key_client_app_hex);
 
	/* ------------------------------------------------------------
	 * STEP 4: Decrypt and verify Auth_Client_App
	 *
	 * Auth_Client_App is found on line 2 of APP_REQ.txt.
	 *
	 * It is encrypted using Key_Client_App and should
	 * decrypt to a client identity string (clientID_2).
	 *
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Read line 2 from APP_REQ.txt
	 *  - AES-decrypt using Key_Client_App
	 *  - Interpret plaintext as clientID_2
	 */
	char *auth_client_app_hex = read_line(app_req_path, 2);
 
	unsigned char *auth_plain = NULL;
	size_t auth_plain_len = 0;
	if (!aes256_decrypt_hex_string_to_bytes(key_client_app_bytes, auth_client_app_hex, &auth_plain, &auth_plain_len)) {
		fprintf(stderr, "Failed to decrypt Auth_Client_App\n");
		free(auth_client_app_hex);
		free(key_client_app_bytes);
		free(client_id_1);
		return EXIT_FAILURE;
	}
	free(auth_client_app_hex);
	free(key_client_app_bytes);
 
	// Null-terminate
	auth_plain = realloc(auth_plain, auth_plain_len + 1);
	auth_plain[auth_plain_len] = '\0';
 
	char *client_id_2 = (char*)auth_plain;
	int auth_len = (int)auth_plain_len;
 
	// Strip trailing padding/control bytes
	while (auth_len > 0 && (unsigned char)client_id_2[auth_len - 1] < 32) {
		client_id_2[auth_len - 1] = '\0';
		auth_len--;
	}
 
	/* ------------------------------------------------------------
	 * STEP 5: Validate client identity
	 *
	 * Compare:
	 *
	 *      clientID_1 == clientID_2
	 *
	 * If they match:
	 *  - Accept the request
	 *
	 * Otherwise:
	 *  - Reject the request
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Compare the two client ID strings
	 *  - Treat mismatch as authentication failure
	 */
	if (strcmp(client_id_1, client_id_2) != 0) {
		fprintf(stderr, "Authentication failed\n");
		free(client_id_1);
		free(auth_plain);
		return EXIT_FAILURE;
	}
 
	free(client_id_1);
	free(auth_plain);
 
	/* ------------------------------------------------------------
	 * STEP 6: Write APP_REP.txt
	 *
	 * On SUCCESS:
	 *  - Write the string "OK" followed by a newline
	 *    to the file:
	 *
	 *      APP_REP.txt
	 *
	 * No other output is permitted.
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Create (or overwrite) APP_REP.txt
	 *  - Write exactly:
	 *        OK\n
	 */
	FILE *rep = fopen("APP_REP.txt", "w");
	if (!rep) {
		fprintf(stderr, "Cannot open APP_REP.txt for writing\n");
		return EXIT_FAILURE;
	}
	fprintf(rep, "OK\n");
	fclose(rep);
 
	return EXIT_SUCCESS;
}
