/*
 * signer2.c — Level 2 Signer (ID_2) for Schnorr-HIBS
 *
 * ASSIGNMENT TEMPLATE
 *
 * ROLE:
 *   Implements:
 *     (1) HIBS.Extract for hierarchy level k = 2
 *     (2) Schnorr signature generation
 *
 * INPUT FILES:
 *   - sk_ID1.txt          : level-1 private key (hex scalar)
 *   - signer2_b2.txt     : random delegation scalar b2 (hex)
 *   - signer2_r.txt      : signing randomness r (hex)
 *   - Q_ID1.txt          : level-1 public delegation point (hex EC point)
 *   - ID2.txt             : identity string for ID_2
 *   - message.txt         : message to be signed
 *
 * OUTPUT FILES:
 *   - Q_ID2.txt            : level-2 public delegation point
 *   - sig_s.txt            : Schnorr signature scalar s
 *   - sig_h.txt            : Schnorr signature hash h
 *
 * REQUIRED RELATIONS:
 *   Delegation:
 *     c_ID2 = H1(ID_2 || Q_ID1 || Q_ID2)
 *     sk_ID2 = sk_ID1 * c_ID2 + b2 mod q
 *
 *   Signing:
 *     R = r * P
 *     h = H2(message || R)
 *     s = r + h * sk_ID2 mod q
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/rand.h>

#include "RequiredFunctions.h"

static char ID_2[1024];
static char MESSAGE[4096];

int main(int argc, char **argv)
{
    EC_GROUP *group = NULL;
    BIGNUM *q = NULL;
    const EC_POINT *P = NULL;

    BIGNUM *sk_ID1 = NULL;
    EC_POINT *Q_ID1 = NULL;

    BIGNUM *b2 = NULL;
    EC_POINT *Q_ID2 = NULL;
    BIGNUM *c_ID2 = NULL;
    BIGNUM *sk_ID2 = NULL;

    BIGNUM *r = NULL;
    EC_POINT *R = NULL;
    BIGNUM *h = NULL;
    BIGNUM *s = NULL;

    BN_CTX *ctx = NULL;

    unsigned char *qid1_bytes = NULL;
    unsigned char *qid2_bytes = NULL;
    unsigned char *buf = NULL;
    unsigned char *R_bytes = NULL;
    unsigned char *hbuf = NULL;

    BIGNUM *tmp = NULL;
    BIGNUM *tmp2 = NULL;

    size_t id_len = 0;
    size_t m_len = 0;

    const char *sk_id1_path = NULL;
    const char *b2_path = NULL;
    const char *r_path = NULL;
    const char *q_id1_path = NULL;
    const char *id2_path = NULL;
    const char *msg_path = NULL;

    if (argc != 7)
    {
        fprintf(stderr,
                "Usage: %s <sk_ID1.txt> <signer2_b2.txt> <signer2_r.txt> "
                "<Q_ID1.txt> <ID2.txt> <message.txt>\n",
                argv[0]);
        return EXIT_FAILURE;
    }

    sk_id1_path = argv[1];
    b2_path = argv[2];
    r_path = argv[3];
    q_id1_path = argv[4];
    id2_path = argv[5];
    msg_path = argv[6];

    /* ------------------------------------------------------------ */
    /* Step 0: Initialize EC group and domain parameters             */
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
    /* Step 1: Read level-1 secret key and public delegation point   */
    /* ------------------------------------------------------------ */
    /*
     * TODO:
     *   - Read sk_ID1 from sk_ID1.txt using read_bn_hex()
     *   - Read Q_ID1 from Q_ID1.txt using read_point_hex()
     */
    /* ------------------------------------------------------------ */
    read_bn_hex(sk_id1_path, &sk_ID1);
    read_point_hex(q_id1_path, group, &Q_ID1);

    /* ------------------------------------------------------------ */
    /* Step 2: Read identity ID_2 and message                        */
    /* ------------------------------------------------------------ */
    /*
     * TODO:
     *   - Open ID2.txt and read identity string into ID_2
     *   - Strip newline characters and compute id_len
     *
     *   - Open message.txt and read message into MESSAGE
     *   - Strip newline characters and compute m_len
     */
    /* ------------------------------------------------------------ */
    FILE *id_file = fopen(id2_path, "r");
    fgets(ID_2, sizeof(ID_2), id_file);
    // Strip newline characters
    size_t len = strlen(ID_2);
    if (len > 0 && (ID_2[len - 1] == '\n' || ID_2[len - 1] == '\r'))
    {
        ID_2[len - 1] = '\0';
    }
    id_len = strlen(ID_2);

    FILE *msg_file = fopen(msg_path, "r");
    fgets(MESSAGE, sizeof(MESSAGE), msg_file);
    len = strlen(MESSAGE);
    if (len > 0 && (MESSAGE[len - 1] == '\n' || MESSAGE[len - 1] == '\r'))
    {
        MESSAGE[len - 1] = '\0';
    }
    m_len = strlen(MESSAGE);

    fclose(id_file);
    fclose(msg_file);

    /* ------------------------------------------------------------ */
    /* Step 3: Initialize BN context and allocate scalars            */
    /* ------------------------------------------------------------ */
    /*
     * TODO:
     *   - Create BN_CTX using BN_CTX_new()
     *   - Allocate b2, sk_ID2, r, and s using BN_new()
     */
    /* ------------------------------------------------------------ */
    ctx = BN_CTX_new();
    sk_ID2 = BN_new();
    s = BN_new();

    /* ------------------------------------------------------------ */
    /* Step 4: Delegation — read b2 and compute Q_ID2                */
    /* ------------------------------------------------------------ */
    /*
     * TODO:
     *   - Read b2 from signer2_b2.txt using read_bn_hex()
     *   - Allocate Q_ID2 using EC_POINT_new(group)
     *   - Compute Q_ID2 = b2 * P using EC_POINT_mul()
     */
    /* ------------------------------------------------------------ */
    read_bn_hex(b2_path, &b2);
    Q_ID2 = EC_POINT_new(group);
    EC_POINT_mul(group, Q_ID2, NULL, P, b2, ctx);

    /* ------------------------------------------------------------ */
    /* Step 5: Compute c_ID2 = H1(ID_2 || Q_ID1 || Q_ID2)             */
    /* ------------------------------------------------------------ */
    /*
     * TODO:
     *   - Serialize Q_ID1 and Q_ID2 using point_to_bytes()
     *   - Concatenate ID_2 || Q_ID1 || Q_ID2 into buffer
     *   - Hash buffer to scalar c_ID2 using H1_to_scalar()
     */
    /* ------------------------------------------------------------ */
    size_t qid1_len = 0;
    point_to_bytes(group, Q_ID1, &qid1_bytes, &qid1_len);
    size_t qid2_len = 0;
    point_to_bytes(group, Q_ID2, &qid2_bytes, &qid2_len);
    size_t buf_len = id_len + qid1_len + qid2_len;
    buf = malloc(buf_len);
    memcpy(buf, ID_2, id_len);
    memcpy(buf + id_len, qid1_bytes, qid1_len);
    memcpy(buf + id_len + qid1_len, qid2_bytes, qid2_len);
    H1_to_scalar(buf, buf_len, q, &c_ID2);

    /* ------------------------------------------------------------ */
    /* Step 6: Compute sk_ID2 = sk_ID1 * c_ID2 + b2 mod q             */
    /* ------------------------------------------------------------ */
    /*
     * TODO:
     *   - Allocate temporary BIGNUM tmp
     *   - Compute tmp = sk_ID1 * c_ID2 mod q using BN_mod_mul()
     *   - Compute sk_ID2 = tmp + b2 mod q using BN_mod_add()
     */
    /* ------------------------------------------------------------ */
    tmp = BN_new();
    BN_mod_mul(tmp, sk_ID1, c_ID2, q, ctx);
    BN_mod_add(sk_ID2, tmp, b2, q, ctx);

    /* ------------------------------------------------------------ */
    /* Step 7: Signing — read r and compute R                         */
    /* ------------------------------------------------------------ */
    /*
     * TODO:
     *   - Read r from signer2_r.txt using read_bn_hex()
     *   - Allocate EC_POINT R
     *   - Compute R = r * P using EC_POINT_mul()
     */
    /* ------------------------------------------------------------ */
    read_bn_hex(r_path, &r);
    R = EC_POINT_new(group);
    EC_POINT_mul(group, R, NULL, P, r, ctx);

    /* ------------------------------------------------------------ */
    /* Step 8: Compute h = H2(message || R)                           */
    /* ------------------------------------------------------------ */
    /*
     * TODO:
     *   - Serialize R using point_to_bytes()
     *   - Concatenate MESSAGE || R into buffer
     *   - Hash buffer to scalar h using H2_to_scalar()
     */
    /* ------------------------------------------------------------ */
    size_t R_len = 0;
    point_to_bytes(group, R, &R_bytes, &R_len);
    size_t hbuf_len = m_len + R_len;
    hbuf = malloc(hbuf_len);
    memcpy(hbuf, MESSAGE, m_len);
    memcpy(hbuf + m_len, R_bytes, R_len);
    H2_to_scalar(hbuf, hbuf_len, q, &h);

    /* ------------------------------------------------------------ */
    /* Step 9: Compute s = r + h * sk_ID2 mod q                       */
    /* ------------------------------------------------------------ */
    /*
     * TODO:
     *   - Allocate temporary BIGNUM tmp2
     *   - Compute tmp2 = h * sk_ID2 mod q using BN_mod_mul()
     *   - Compute s = r + tmp2 mod q using BN_mod_add()
     */
    /* ------------------------------------------------------------ */
    tmp2 = BN_new();
    BN_mod_mul(tmp2, h, sk_ID2, q, ctx);
    BN_mod_add(s, r, tmp2, q, ctx);

    /* ------------------------------------------------------------ */
    /* Step 10: Write output files                                   */
    /* ------------------------------------------------------------ */
    /*
     * TODO:
     *   - Write Q_ID2 to Q_ID2.txt using write_point_hex()
     *   - Write s to sig_s.txt using write_bn_hex()
     *   - Write h to sig_h.txt using write_bn_hex()
     */
    /* ------------------------------------------------------------ */
    write_point_hex("Q_ID2.txt", group, Q_ID2);
    write_bn_hex("sig_s.txt", s);
    write_bn_hex("sig_h.txt", h);

    printf("[signer2] Delegation and signing complete.\n");

    /* ------------------------------------------------------------ */
    /* Cleanup                                                       */
    /* ------------------------------------------------------------ */
    /*
     * TODO:
     *   - Free all allocated BIGNUMs, EC_POINTs, buffers, and contexts
     *   - Follow correct order and avoid memory leaks
     */
    /* ------------------------------------------------------------ */
    BN_free(sk_ID1);
    EC_POINT_free(Q_ID1);
    BN_free(b2);
    EC_POINT_free(Q_ID2);
    BN_free(c_ID2);
    BN_free(sk_ID2);
    BN_free(r);
    EC_POINT_free(R);
    BN_free(h);
    BN_free(s);

    BN_free(tmp);
    BN_free(tmp2);

    free(qid1_bytes);
    free(qid2_bytes);
    free(buf);
    free(R_bytes);
    free(hbuf);

    BN_CTX_free(ctx);
    BN_free(q);
    EC_GROUP_free(group);

    return EXIT_SUCCESS;
}
