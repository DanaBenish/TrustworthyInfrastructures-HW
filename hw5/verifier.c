/*
 * verifier.c — Public Verifier for 2-Level Schnorr-HIBS
 *
 * ASSIGNMENT TEMPLATE
 *
 * ROLE:
 *   Implements HIBS.Verify for k = 2.
 *   Verifies a Schnorr-HIBS signature using only public information.
 *
 * INPUT FILES:
 *   - ID1.txt        : identity string for level 1
 *   - ID2.txt        : identity string for level 2
 *   - message.txt    : signed message
 *   - mpk.txt        : master public key
 *   - Q_ID1.txt      : level-1 public delegation point
 *   - Q_ID2.txt      : level-2 public delegation point
 *   - sig_s.txt      : signature scalar s
 *   - sig_h.txt      : signature hash h
 *
 * OUTPUT:
 *   - verification.txt : recomputed hash value (for debugging)
 *   - Console message indicating VALID or INVALID signature
 *
 * VERIFICATION EQUATION:
 *
 *   PK_eff =
 *     (c_ID1 * c_ID2) * mpk
 *     + (c_ID2 * Q_ID1)
 *     + Q_ID2
 *
 *   R' = s * P − h * PK_eff
 *
 *   Accept iff:
 *     h == H2(message || R')
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/ec.h>
#include <openssl/bn.h>

#include "RequiredFunctions.h"

static char ID_1[1024];
static char ID_2[1024];
static char MESSAGE[4096];

int main(int argc, char **argv)
{
    EC_GROUP *group = NULL;
    BIGNUM *q = NULL;
    const EC_POINT *P = NULL;

    EC_POINT *mpk = NULL;
    EC_POINT *Q_ID1 = NULL;
    EC_POINT *Q_ID2 = NULL;

    BIGNUM *s = NULL;
    BIGNUM *h = NULL;

    BIGNUM *c_ID1 = NULL;
    BIGNUM *c_ID2 = NULL;
    BIGNUM *c1c2 = NULL;

    EC_POINT *PK_eff = NULL;
    EC_POINT *term1 = NULL;
    EC_POINT *term2 = NULL;

    EC_POINT *Rprime = NULL;
    EC_POINT *hpke = NULL;

    BIGNUM *h_check = NULL;

    BN_CTX *ctx = NULL;

    unsigned char *qid1_bytes = NULL;
    unsigned char *qid2_bytes = NULL;
    unsigned char *buf1 = NULL;
    unsigned char *buf2 = NULL;
    unsigned char *Rprime_bytes = NULL;
    unsigned char *hbuf = NULL;

    size_t id1_len = 0;
    size_t id2_len = 0;
    size_t m_len = 0;

    const char *id1_path = NULL;
    const char *id2_path = NULL;
    const char *msg_path = NULL;
    const char *mpk_path = NULL;
    const char *qid1_path = NULL;
    const char *qid2_path = NULL;
    const char *sig_s_path = NULL;
    const char *sig_h_path = NULL;

    if (argc != 9)
    {
        fprintf(stderr,
                "Usage: %s <ID1.txt> <ID2.txt> <message.txt> <mpk.txt> "
                "<Q_ID1.txt> <Q_ID2.txt> <sig_s.txt> <sig_h.txt>\n",
                argv[0]);
        return EXIT_FAILURE;
    }

    id1_path = argv[1];
    id2_path = argv[2];
    msg_path = argv[3];
    mpk_path = argv[4];
    qid1_path = argv[5];
    qid2_path = argv[6];
    sig_s_path = argv[7];
    sig_h_path = argv[8];

    /* ------------------------------------------------------------ */
    /* Step 0: Initialize elliptic curve parameters                  */
    /* ------------------------------------------------------------ */
    /*
     * TODO:
     *   - Call init_group(&group, &q)
     *   - Retrieve generator P using EC_GROUP_get0_generator()
     */
    /* ------------------------------------------------------------ */
    init_group(&group, &q);
    P = EC_GROUP_get0_generator(group);

    /* ------------------------------------------------------------ */
    /* Step 1: Read public parameters and signature                  */
    /* ------------------------------------------------------------ */
    /*
     * TODO:
     *   - Read mpk from mpk.txt using read_point_hex()
     *   - Read Q_ID1 and Q_ID2 using read_point_hex()
     *   - Read signature scalars s and h using read_bn_hex()
     */
    /* ------------------------------------------------------------ */
    read_point_hex(mpk_path, group, &mpk);
    read_point_hex(qid1_path, group, &Q_ID1);
    read_point_hex(qid2_path, group, &Q_ID2);
    read_bn_hex(sig_s_path, &s);
    read_bn_hex(sig_h_path, &h);

    /* ------------------------------------------------------------ */
    /* Step 2: Read identities and message                            */
    /* ------------------------------------------------------------ */
    /*
     * TODO:
     *   - Read ID_1 from ID1.txt and compute id1_len
     *   - Read ID_2 from ID2.txt and compute id2_len
     *   - Read MESSAGE from message.txt and compute m_len
     */
    /* ------------------------------------------------------------ */
    FILE *id1_file = fopen(id1_path, "r");
    fgets(ID_1, sizeof(ID_1), id1_file);
    // Strip newline characters
    size_t len = strlen(ID_1);
    if (len > 0 && (ID_1[len - 1] == '\n' || ID_1[len - 1] == '\r'))
    {
        ID_1[len - 1] = '\0';
    }
    id1_len = strlen(ID_1);

    FILE *id2_file = fopen(id2_path, "r");
    fgets(ID_2, sizeof(ID_2), id2_file);
    // Strip newline characters
    size_t len2 = strlen(ID_2);
    if (len2 > 0 && (ID_2[len2 - 1] == '\n' || ID_2[len2 - 1] == '\r'))
    {
        ID_2[len2 - 1] = '\0';
    }
    id2_len = strlen(ID_2);

    FILE *msg_file = fopen(msg_path, "r");
    fgets(MESSAGE, sizeof(MESSAGE), msg_file);
    len = strlen(MESSAGE);
    if (len > 0 && (MESSAGE[len - 1] == '\n' || MESSAGE[len - 1] == '\r'))
    {
        MESSAGE[len - 1] = '\0';
    }
    m_len = strlen(MESSAGE);

    fclose(id1_file);
    fclose(id2_file);
    fclose(msg_file);

    /* ------------------------------------------------------------ */
    /* Step 3: Initialize BN context                                  */
    /* ------------------------------------------------------------ */
    /*
     * TODO:
     *   - Create BN_CTX using BN_CTX_new()
     */
    /* ------------------------------------------------------------ */
    ctx = BN_CTX_new();

    /* ------------------------------------------------------------ */
    /* Step 4: Compute c_ID1 = H1(ID_1 || Q_ID1)                      */
    /* ------------------------------------------------------------ */
    /*
     * TODO:
     *   - Serialize Q_ID1 using point_to_bytes()
     *   - Concatenate ID_1 || Q_ID1
     *   - Hash using H1_to_scalar() to obtain c_ID1
     */
    /* ------------------------------------------------------------ */
    size_t qid1_len = 0;
    point_to_bytes(group, Q_ID1, &qid1_bytes, &qid1_len);
    size_t buf1_len = id1_len + qid1_len;
    buf1 = malloc(buf1_len);
    memcpy(buf1, ID_1, id1_len);
    memcpy(buf1 + id1_len, qid1_bytes, qid1_len);
    H1_to_scalar(buf1, buf1_len, q, &c_ID1);

    /* ------------------------------------------------------------ */
    /* Step 5: Compute c_ID2 = H1(ID_2 || Q_ID1 || Q_ID2)             */
    /* ------------------------------------------------------------ */
    /*
     * TODO:
     *   - Serialize Q_ID1 and Q_ID2 using point_to_bytes()
     *   - Concatenate ID_2 || Q_ID1 || Q_ID2
     *   - Hash using H1_to_scalar() to obtain c_ID2
     */
    /* ------------------------------------------------------------ */
    size_t qid2_len = 0;
    point_to_bytes(group, Q_ID2, &qid2_bytes, &qid2_len);
    size_t buf2_len = id2_len + qid1_len + qid2_len;
    buf2 = malloc(buf2_len);
    memcpy(buf2, ID_2, id2_len);
    memcpy(buf2 + id2_len, qid1_bytes, qid1_len);
    memcpy(buf2 + id2_len + qid1_len, qid2_bytes, qid2_len);
    H1_to_scalar(buf2, buf2_len, q, &c_ID2);

    /* ------------------------------------------------------------ */
    /* Step 6: Reconstruct effective public key PK_eff                */
    /* ------------------------------------------------------------ */
    /*
     * TODO:
     *   - Compute c1c2 = c_ID1 * c_ID2 mod q using BN_mod_mul()
     *   - Compute term1 = (c1c2) * mpk using EC_POINT_mul()
     *   - Compute term2 = c_ID2 * Q_ID1 using EC_POINT_mul()
     *   - Compute PK_eff = term1 + term2 + Q_ID2 using EC_POINT_add()
     */
    /* ------------------------------------------------------------ */
    c1c2 = BN_new();
    BN_mod_mul(c1c2, c_ID1, c_ID2, q, ctx);
    term1 = EC_POINT_new(group);
    EC_POINT_mul(group, term1, NULL, mpk, c1c2, ctx);
    term2 = EC_POINT_new(group);
    EC_POINT_mul(group, term2, NULL, Q_ID1, c_ID2, ctx);
    PK_eff = EC_POINT_new(group);
    EC_POINT_add(group, PK_eff, term1, term2, ctx);
    EC_POINT_add(group, PK_eff, PK_eff, Q_ID2, ctx);

    /* ------------------------------------------------------------ */
    /* Step 7: Compute R' = s * P − h * PK_eff                         */
    /* ------------------------------------------------------------ */
    /*
     * TODO:
     *   - Compute hpke = h * PK_eff using EC_POINT_mul()
     *   - Invert hpke using EC_POINT_invert()
     *   - Compute s * P using EC_POINT_mul()
     *   - Add points to obtain R' using EC_POINT_add()
     */
    /* ------------------------------------------------------------ */
    hpke = EC_POINT_new(group);
    EC_POINT_mul(group, hpke, NULL, PK_eff, h, ctx);
    EC_POINT_invert(group, hpke, ctx);
    Rprime = EC_POINT_new(group);
    EC_POINT_mul(group, Rprime, NULL, P, s, ctx);
    EC_POINT_add(group, Rprime, Rprime, hpke, ctx);

    /* ------------------------------------------------------------ */
    /* Step 8: Verify hash consistency                                */
    /* ------------------------------------------------------------ */
    /*
     * TODO:
     *   - Serialize R' using point_to_bytes()
     *   - Concatenate MESSAGE || R'
     *   - Hash using H2_to_scalar() to obtain h_check
     *   - Compare h_check and h using BN_cmp()
     *   - Write h_check to verification.txt using write_bn_hex()
     */
    /* ------------------------------------------------------------ */
    size_t Rprime_len = 0;
    point_to_bytes(group, Rprime, &Rprime_bytes, &Rprime_len);
    size_t hbuf_len = m_len + Rprime_len;
    hbuf = malloc(hbuf_len);
    memcpy(hbuf, MESSAGE, m_len);
    memcpy(hbuf + m_len, Rprime_bytes, Rprime_len);
    H2_to_scalar(hbuf, hbuf_len, q, &h_check);
    write_bn_hex("verification.txt", h_check);

    /* ------------------------------------------------------------ */
    /* Step 9: Output verification result                             */
    /* ------------------------------------------------------------ */
    /*
     * TODO:
     *   - Print VALID if h == h_check
     *   - Print INVALID otherwise
     */
    /* ------------------------------------------------------------ */
    if (BN_cmp(h, h_check) == 0)
    {
        printf("[verifier] Signature is VALID.\n");
    }
    else
    {
        printf("[verifier] Signature is INVALID.\n");
    }

    printf("[verifier] Verification completed.\n");

    /* ------------------------------------------------------------ */
    /* Cleanup                                                       */
    /* ------------------------------------------------------------ */
    /*
     * TODO:
     *   - Free all allocated BIGNUMs, EC_POINTs, buffers, and contexts
     *   - Ensure no memory leaks
     */
    /* ------------------------------------------------------------ */
    EC_POINT_free(mpk);
    EC_POINT_free(Q_ID1);
    EC_POINT_free(Q_ID2);
    BN_free(s);
    BN_free(h);
    BN_free(c_ID1);
    BN_free(c_ID2);
    BN_free(c1c2);
    EC_POINT_free(PK_eff);
    EC_POINT_free(term1);
    EC_POINT_free(term2);
    EC_POINT_free(Rprime);
    EC_POINT_free(hpke);
    BN_free(h_check);
    BN_CTX_free(ctx);
    BN_free(q);
    EC_GROUP_free(group);

    return EXIT_SUCCESS;
}
