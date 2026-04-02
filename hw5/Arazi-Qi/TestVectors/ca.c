/*
 * ca.c — Certificate Authority for Arazi–Qi Key Exchange (ECDLP)
 *
 * ============================
 * ASSIGNMENT TEMPLATE VERSION
 * ============================
 *
 * STUDENT TASK:
 *   Implement the offline Certificate Authority (CA) phase of the
 *   Arazi–Qi identity-based key agreement protocol.
 *
 *   You MUST NOT change:
 *     - File names
 *     - Variable names
 *     - Identity strings
 *     - Overall control flow
 *
 *   You MUST replace the TODO sections with working code
 *   using the specified helper functions and OpenSSL APIs.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/rand.h>

#include "RequiredFunctions.h"

/* Public identity strings */
static const char *ID_A = "alice@example.com";
static const char *ID_B = "bob@example.com";

int main(int argc, char **argv)
{
	int ret = EXIT_FAILURE;

	/* === Cryptographic objects === */
	EC_GROUP *group = NULL;      /* Elliptic curve group */
	BIGNUM *q = NULL;            /* Group order */
	const EC_POINT *P = NULL;    /* Generator */
	BN_CTX *ctx = NULL;

	BIGNUM *d = NULL;            /* CA master secret */
	EC_POINT *D = NULL;          /* CA master public key */

	BIGNUM *b_a = NULL; //alice rand scalae
	BIGNUM *b_b = NULL; //bob rand scalar
	EC_POINT *U_a = NULL; //alice public identity
	EC_POINT *U_b = NULL; //bob public identity

	BIGNUM *h_a = NULL; //hash for alice
	BIGNUM *h_b = NULL; //hash for bob
	BIGNUM *x_a = NULL; //Alice final key
	BIGNUM *x_b = NULL; //Bob final key
	BIGNUM *tmp = NULL;

	unsigned char *U_bytes = NULL;
	size_t U_len = 0;
	unsigned char *buf = NULL; //full buffer
	size_t buf_len = 0;

	/* =====================================================
	 * 1. Command-line argument validation
	 * =====================================================
	 *
	 * REQUIRED invocation:
	 *
	 *   ./ca <d_file> <b_a_file> <b_b_file>
	 *
	 *   <d_file>   : hex-encoded master secret d
	 *   <b_a_file> : hex-encoded scalar b_a
	 *   <b_b_file> : hex-encoded scalar b_b
	 *
	 * ACTION:
	 *   - If argc != 4, print usage and EXIT_FAILURE.
	 */
	if (argc != 4)
	{
		fprintf(stderr, "Usage: %s <d_file> <b_a_file> <b_b_file>\n", argv[0]);
		return EXIT_FAILURE;
	}

	/* =====================================================
	 * 2. Initialize elliptic curve group
	 * =====================================================
	 *
	 * TASK:
	 *   - Initialize an EC_GROUP using a named curve
	 *   - Obtain the group order q
	 *
	 * FUNCTION TO USE:
	 *   init_group(&group, &q)
	 *
	 * EXIT if this function returns false.
	 */


	// TODO:
	// if (!init_group(&group, &q)) { print error and goto cleanup; }
	//innit & alloc
	if (!init_group(&group, &q)) {
    fprintf(stderr, "Failed Step 2.\n");
    goto cleanup;
}
	
	/* =====================================================
	 * 3. Obtain generator P
	 * =====================================================
	 *
	 * TASK:
	 *   - Retrieve generator P from the EC group
	 *
	 * FUNCTION TO USE:
	 *   EC_GROUP_get0_generator(group)
	 *
	 * EXIT if P == NULL.
	 */

	// TODO:
	//retrieve generator P

	P = EC_GROUP_get0_generator(group);
	if (P == NULL){
		fprintf(stderr, "Failed Step 3.\n");
		goto cleanup;
	}

	/* =====================================================
	 * 4. Allocate context and master key objects
	 * =====================================================
	 *
	 * TASK:
	 *   - Allocate BN_CTX using BN_CTX_new()
	 *   - Allocate BIGNUM d using BN_new()
	 *   - Allocate EC_POINT D using EC_POINT_new(group)
	 *
	 * EXIT if any allocation fails.
	 */

	// TODO: Allocate ctx, d, and D
	ctx = BN_CTX_new();
	d = BN_new();
	D = EC_POINT_new(group);
	//if any fails then error 
	if (ctx == NULL || d == NULL || D == NULL){
		fprintf(stderr, "Failed Step 4.\n");
		goto cleanup;
	}
	/* =====================================================
	 * 5. Load CA master secret d
	 * =====================================================
	 *
	 * INPUT FILE:
	 *   argv[1] — hex-encoded scalar
	 *
	 * FUNCTION TO USE:
	 *   read_bn_hex(argv[1], &d)
	 *
	 * EXIT if:
	 *   - File does not exist
	 *   - Parsing fails
	 */

	// TODO: Read d from argv[1]
	if (!read_bn_hex(argv[1], &d)){
		fprintf(stderr, "Failed Step 5.\n");
		goto cleanup;
	}
	

	/* =====================================================
	 * 6. Compute CA master public key D
	 * =====================================================
	 *
	 * FORMULA:
	 *   D = d * P
	 *
	 * FUNCTION TO USE:
	 *   EC_POINT_mul(group, D, NULL, P, d, ctx)
	 *
	 * EXIT on failure.
	 */

	// TODO: Compute D = d * P
	if (!EC_POINT_mul(group, D, NULL, P, d, ctx)){
		fprintf(stderr, "Failed Step 6.\n");
		goto cleanup;
	}

	/* =====================================================
	 * 7. Write CA master keys to disk
	 * =====================================================
	 *
	 * OUTPUT FILES (HEX):
	 *   - ca_master_secret_d.txt  (scalar)
	 *   - ca_master_public_D.txt  (EC point)
	 *
	 * FUNCTIONS TO USE:
	 *   write_bn_hex(...)
	 *   write_point_hex(...)
	 *
	 * EXIT if any write fails.
	 */

	// TODO: Write ca_master_secret_d.txt
	
	if (!write_bn_hex("ca_master_secret_d.txt", d)){
		fprintf(stderr, "Failed Step 7a.\n");
		goto cleanup;
	}

	// TODO: Write ca_master_public_D.txt
	if (!write_point_hex("ca_master_public_D.txt", group, D)){
		fprintf(stderr, "Failed Step 7b.\n");
		goto cleanup;
	}

	/* =====================================================
	 * 8. Allocate per-user objects
	 * =====================================================
	 *
	 * TASK:
	 *   Allocate the following using BN_new() / EC_POINT_new():
	 *     b_a, b_b, U_a, U_b, x_a, x_b, tmp
	 *
	 * EXIT if allocation fails.
	 */

	// TODO: Allocate per-user BIGNUMs and EC_POINTs
	b_a = BN_new();
	b_b = BN_new();
	U_a = EC_POINT_new(group);
	U_b = EC_POINT_new(group);
	x_a = BN_new();
	x_b = BN_new();
	tmp = BN_new();
	//check if any failed
	if (b_a == NULL || b_b == NULL || U_a == NULL || U_b == NULL || x_a == NULL || x_b == NULL || tmp == NULL){
		fprintf(stderr, "Failed Step 8.\n");
		goto cleanup;
	}

	/* =====================================================
	 * 9. Load per-user random scalars
	 * =====================================================
	 *
	 * INPUT FILES:
	 *   argv[2] → b_a
	 *   argv[3] → b_b
	 *
	 * FUNCTION TO USE:
	 *   read_bn_hex(file, &bn)
	 *
	 * EXIT if files do not exist or parsing fails.
	 */

	// TODO: Read b_a from argv[2]
	if (!read_bn_hex(argv[2], &b_a)){
		fprintf(stderr, "Failed Step 9.\n");
		goto cleanup;
	}
	// TODO: Read b_b from argv[3]
	if (!read_bn_hex(argv[3], &b_b)){
		fprintf(stderr, "Failed Step 9.\n");
		goto cleanup;
	}

	/* =====================================================
	 * 10. Alice offline key generation
	 * =====================================================
	 *
	 * STEPS:
	 *
	 * 1. Compute U_a = b_a * P
	 *    Function: EC_POINT_mul
	 *
	 * 2. Serialize U_a to bytes
	 *    Function: point_to_bytes
	 *
	 * 3. Compute h_a = H(ID_A || U_a) mod q
	 *    Function: sha256_to_scalar
	 *
	 * 4. Compute x_a = (h_a * b_a + d) mod q
	 *    Functions:
	 *      BN_mod_mul
	 *      BN_mod_add
	 *
	 * 5. Write outputs:
	 *    - alice_private_xa.txt (scalar)
	 *    - alice_public_Ua.txt  (EC point)
	 *
	 * EXIT immediately on any failure.
	 */

	// TODO: Compute U_a
	if (!EC_POINT_mul(group, U_a, NULL, P, b_a, ctx)){
		fprintf(stderr, "Failed Step 10.\n");
		goto cleanup;
	}
	// TODO: Serialize U_a to U_bytes
	if (!point_to_bytes(group, U_a, &U_bytes, &U_len)){
		fprintf(stderr, "Failed Step 10.\n");
		goto cleanup;
	}
	// TODO: Build buffer = ID_A || U_bytes
	buf_len = strlen(ID_A) + U_len;
	buf = malloc(buf_len);
	if (buf == NULL){
		fprintf(stderr, "Failed Step 10.\n");
		goto cleanup;
	}
	memcpy(buf, ID_A, strlen(ID_A));
	memcpy(buf + strlen(ID_A), U_bytes, U_len);
	// TODO: Compute h_a using sha256_to_scalar
	if (!sha256_to_scalar(buf, buf_len, q, &h_a)){
		fprintf(stderr, "Failed Step 10.\n");
		goto cleanup;
	}
	// TODO: Compute x_a
	if (!BN_mod_mul(tmp, h_a, b_a, q, ctx)){
		fprintf(stderr, "Failed Step 10.\n");
		goto cleanup;
	}
	if (!BN_mod_add(x_a, tmp, d, q, ctx)){
		fprintf(stderr, "Failed Step 10.\n");
		goto cleanup;
	}
	// TODO: Write alice_private_xa.txt
	if (!write_bn_hex("alice_private_xa.txt", x_a)){
		fprintf(stderr, "Failed Step 10.\n");
		goto cleanup;
	}
	// TODO: Write alice_public_Ua.txt
	if (!write_point_hex("alice_public_Ua.txt", group, U_a)){
		fprintf(stderr, "Failed Step 10.\n");
		goto cleanup;
	}

	/* =====================================================
	 * 11. Bob offline key generation
	 * =====================================================
	 *
	 * IDENTICAL to Alice, except:
	 *   ID_A → ID_B
	 *   b_a  → b_b
	 *   U_a  → U_b
	 *   h_a  → h_b
	 *   x_a  → x_b
	 *
	 * OUTPUT FILES:
	 *   - bob_private_xb.txt
	 *   - bob_public_Ub.txt
	 */

	// TODO: Repeat steps for Bob
	//TODO: Compute U_B
	if( !EC_POINT_mul(group, U_b, NULL, P, b_b, ctx)){
		fprintf(stderr, "Failed Step 11.\n");
		goto cleanup;
	}
	// TODO: Serialize U_B to U_bytes
	if (!point_to_bytes(group, U_b, &U_bytes, &U_len)){
		fprintf(stderr, "Failed Step 11.\n");
		goto cleanup;
	}
	// TODO: Build buffer = ID_B || U_bytes (realloc)
	buf_len = strlen(ID_B) + U_len;
	buf = realloc(buf, buf_len);
	if (buf == NULL){
		fprintf(stderr, "Failed Step 11.\n");
		goto cleanup;
	}
	memcpy(buf, ID_B, strlen(ID_B));
	memcpy(buf + strlen(ID_B), U_bytes, U_len);
	// TODO: Compute h_B using sha256_to_scalar
	if (!sha256_to_scalar(buf, buf_len, q, &h_b)){
		fprintf(stderr, "Failed Step 11.\n");
		goto cleanup;
	}
	// TODO: Compute x_B
	if (!BN_mod_mul(tmp, h_b, b_b, q, ctx)){
		fprintf(stderr, "Failed Step 11.\n");
		goto cleanup;
	}
	if (!BN_mod_add(x_b, tmp, d, q, ctx)){
		fprintf(stderr, "Failed Step 11.\n");
		goto cleanup;
	}
	// TODO: Write bob_private_xb.txt
	if (!write_bn_hex("bob_private_xb.txt", x_b)){
		fprintf(stderr, "Failed Step 11.\n");
		goto cleanup;
	}
	// TODO: Write bob_public_Ub.txt
	if (!write_point_hex("bob_public_Ub.txt",group, U_b)){
		fprintf(stderr, "Failed Step 11.\n");
		goto cleanup;
	}

	printf("Offline keys generated for both.\n");
	ret = EXIT_SUCCESS;

	/* =====================================================
	 * 12. Cleanup
	 * =====================================================
	 *
	 * TASK:
	 *   Free ALL allocated memory using:
	 *     BN_free
	 *     EC_POINT_free
	 *     EC_GROUP_free
	 *     BN_CTX_free
	 *
	 * No memory leaks are allowed.
	 */

cleanup:
	free(buf);
	free(U_bytes);
	BN_free(q);
	BN_free(d);
	BN_free(b_a);
	BN_free(b_b);
	BN_free(h_a);
	BN_free(h_b);
	BN_free(x_a);
	BN_free(x_b);
	BN_free(tmp);
	EC_POINT_free(D);
	EC_POINT_free(U_a);
	EC_POINT_free(U_b);
	EC_GROUP_free(group);
	BN_CTX_free(ctx);
	

	return ret;
}
