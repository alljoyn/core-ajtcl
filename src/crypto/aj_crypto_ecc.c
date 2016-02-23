/**
 * @file aj_crypto_ecc.cc
 *
 * Class for Elliptic Curve Cryptography
 */

/******************************************************************************
 * Copyright AllSeen Alliance. All rights reserved.
 *
 *    Permission to use, copy, modify, and/or distribute this software for any
 *    purpose with or without fee is hereby granted, provided that the above
 *    copyright notice and this permission notice appear in all copies.
 *
 *    THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 *    WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 *    MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 *    ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 *    WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 *    ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 *    OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 ******************************************************************************/

#include <ajtcl/aj_crypto.h>
#include <ajtcl/aj_crypto_ecc.h>
#include <ajtcl/aj_crypto_sha2.h>
#include <ajtcl/aj_util.h>
#include <ajtcl/aj_crypto_fp.h>
#include <ajtcl/aj_crypto_ec_p256.h>

#define BIGLEN 9
/*
 * For P256 bigval_t types hold 288-bit 2's complement numbers (9
 * 32-bit words).  For P192 they hold 224-bit 2's complement numbers
 * (7 32-bit words).
 *
 * The representation is little endian by word and native endian
 * within each word.
 */

typedef struct {
    uint32_t data[BIGLEN];
} bigval_t;


typedef struct {
    bigval_t x;
    bigval_t y;
    uint32_t infinity;
} affine_point_t;

typedef struct {
    bigval_t r;
    bigval_t s;
} ECDSA_sig_t;

/* P256 is tested directly with known answer tests from example in
   ANSI X9.62 Annex L.4.2.  (See item in pt_mpy_testcases below.)
   Mathematica code, written in a non-curve-specific way, was also
   tested on the ANSI example, then used to generate both P192 and
   P256 test cases. */

/*
 * This file exports the functions ECDH_generate, ECDH_derive, and
 * optionally, ECDSA_sign and ECDSA_verify.
 */

/*
 * References:
 *
 * [KnuthV2] is D.E. Knuth, The Art of Computer Programming, Volume 2:
 * Seminumerical Algorithms, 1969.
 *
 * [HMV] is D. Hankerson, A. Menezes, and S. Vanstone, Guide to
 * Elliptic Curve Cryptography, 2004.
 *
 * [Wallace] is C.S. Wallace, "A suggestion for a Fast Multiplier",
 * IEEE Transactions on Electronic Computers, EC-13 no. 1, pp 14-17,
 * 1964.
 *
 * [ANSIX9.62] is ANSI X9.62-2005, "Public Key Cryptography for the Financial
 * Services Industry The Elliptic Curve Digital Signature Algorithm
 * (ECDSA)".
 */

/*
 * The vast majority of cycles in programs like this are spent in
 * modular multiplication.  The usual approach is Montgomery
 * multiplication, which effectively does two multiplications in place
 * of one multiplication and one reduction. However, this program is
 * dedicated to the NIST standard curves P256 and P192.  Most of the
 * NIST curves have the property that they can be expressed as a_i *
 * 2^(32*i), where a_i is -1, 0, or +1.  For example P192 is 2^(6*32)
 * - 2^(2*32) - 2^(0*32).  This allows easy word-oriented reduction
 * (32 bit words): The word at position 6 can just be subtracted from
 * word 6 (i.e. word 6 zeroed), and added to words 2 and 0.  This is
 * faster than Montgomery multiplication.
 *
 * Two problems with the naive implementation suggested above are carry
 * propagation and getting the reduction precise.
 *
 * Every time you do an add or subtract you have to propagate carries.
 * The result might come out between the modulus and 2^192 or 2^256,
 * in which case you subtract the modulus.  Most carry propagation is avoided
 * by using 64 bit words during computation, even though the radix is only
 * 2^32.  A carry propagation is done once in the multiplication
 * and once again after the reduction step.  (This idea comes from the carry
 * save adder used in hardware designs.)
 *
 * Exact reduction is required for only a few operations: comparisons,
 * and halving.  The multiplier for point multiplication must also be
 * exactly reduced.  So we do away with the requirement for exact
 * reduction in most operations.  Thus, any reduced value, X, can may
 * represented by X + k * modulus, for any integer k, as long as the
 * result is representable in the data structure.  Typically k is
 * between -1 and 1.  (A bigval_t has one more 32 bit word than is
 * required to hold the modulus, and is interpreted as 2's complement
 * binary, little endian by word, native endian within words.)
 *
 * An exact reduction function is supplied, and must be called as necessary.
 */

/*
 * CONFIGURATION STUFF
 *
 * All these values are undefined.  It seems better to set the
 * preprocessor variables in the makefile, and thus avoid
 * generating many different versions of the code.
 * This may not be practical with ECC_P192 and ECC_P256, but at
 * least that is only in the ecc.h file.
 */

/* define ECDSA to include ECDSA functions */
#define ECDSA
/* define ECC_TEST to rename the the exported symbols to avoid name collisions
   with openSSL, and a few other things necessary for linking with the
   test program ecctest.c */
/* define ARM7_ASM to use assembly code specially for the ARM7 processor */
// #define ARM7_ASM
/* define SMALL_CODE to skip unrolling loops */
// #define SMALL_CODE
/* define SPECIAL_SQUARE to generate a special case for squaring.
   Special squaring should just about halve the number of multiplies,
   but on Windows machines and if loops are unrolled (SMALL_CODE not
   defined) actually causes slight slowing. */
#define SPECIAL_SQUARE
/* define MPY2BITS to consume the multiplier two bits at a time. */
#define MPY2BITS


#ifdef ECC_TEST
/* rename to avoid conflicts with OpenSSL in ecctest.c code. */
#define ECDSA_sign TEST_ECDSA_sign
#define ECDSA_verify TEST_ECDSA_verify
#define COND_STATIC

#else /* ECC_TEST not defined */

#define COND_STATIC static

#endif /* ECC_TEST not defined */


typedef struct {
    int64_t data[2 * BIGLEN];
} dblbigval_t;


/* These values describe why the verify failed.  This simplifies testing. */
typedef enum {V_SUCCESS = 0, V_R_ZERO, V_R_BIG, V_S_ZERO, V_S_BIG,
              V_INFINITY, V_UNEQUAL, V_INTERNAL} verify_res_t;

typedef enum {MOD_MODULUS = 0, MOD_ORDER} modulus_val_t;


#define MSW (BIGLEN - 1)
static void big_adjustP(bigval_t* tgt, bigval_t const* a, int64_t k);
static void big_1wd_mpy(bigval_t* tgt, bigval_t const* a, int32_t k);
static void big_sub(bigval_t* tgt, bigval_t const* a, bigval_t const* b);
static void big_precise_reduce(bigval_t* tgt, bigval_t const* a,
                               bigval_t const* modulus);

#define big_is_negative(a) ((int32_t)(a)->data[MSW] < 0)

/*
 * Does approximate reduction.  Subtracts most significant word times
 * modulus from src.  The double cast is important to get sign
 * extension right.
 */
#define big_approx_reduceP(tgt, src)                \
    big_adjustP(tgt, src, -(int64_t)(int32_t)(src)->data[MSW])

/* if tgt is a modular value, it must be precisely reduced */
#define big_is_odd(tgt) ((tgt)->data[0] & 1)

// Squares, always modulo the modulus
#define big_sqrP(tgt, a) big_mpyP(tgt, a, a, MOD_MODULUS)


#define m1 0xffffffffU

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))

#define OVERFLOWCHECK(sum, a, b) ((((a) > 0) && ((b) > 0) && ((sum) <= 0)) || \
                                  (((a) < 0) && ((b) < 0) && ((sum) >= 0)))

/* NOTE WELL! The Z component must always be precisely reduced. */
typedef struct {
    bigval_t X;
    bigval_t Y;
    bigval_t Z;
} jacobian_point_t;

static bigval_t const big_zero = { { 0, 0, 0, 0, 0, 0, 0 } };
static bigval_t const big_one = { { 1, 0, 0, 0, 0, 0, 0 } };
static affine_point_t const affine_infinity = { { { 0, 0, 0, 0, 0, 0, 0 } },
                                                { { 0, 0, 0, 0, 0, 0, 0 } },
                                                B_TRUE };
static jacobian_point_t const jacobian_infinity = { { { 1, 0, 0, 0, 0, 0, 0 } },
                                                    { { 1, 0, 0, 0, 0, 0, 0 } },
                                                    { { 0, 0, 0, 0, 0, 0, 0 } } };
static bigval_t const modulusP256 = { { m1, m1, m1, 0, 0, 0, 1, m1, 0 } };
static bigval_t const b_P256 =
{ { 0x27d2604b, 0x3bce3c3e, 0xcc53b0f6, 0x651d06b0,
    0x769886bc, 0xb3ebbd55, 0xaa3a93e7, 0x5ac635d8, 0x00000000 } };
static bigval_t const orderP256 =
{ { 0xfc632551, 0xf3b9cac2, 0xa7179e84, 0xbce6faad,
    0xffffffff, 0xffffffff, 0x00000000, 0xffffffff,
    0x00000000 } };
#ifdef ECDSA
static dblbigval_t const orderDBL256 =
{ { 0xfc632551LL - 0x100000000LL,
    0xf3b9cac2LL - 0x100000000LL + 1LL,
    0xa7179e84LL - 0x100000000LL + 1LL,
    0xbce6faadLL - 0x100000000LL + 1LL,
    0xffffffffLL - 0x100000000LL + 1LL,
    0xffffffffLL - 0x100000000LL + 1LL,
    0x00000000LL + 0x1LL,
    0xffffffffLL - 0x100000000LL,
    0x00000000LL + 1LL } };
#endif /* ECDSA */


static affine_point_t const baseP256 = {
    { { 0xd898c296, 0xf4a13945, 0x2deb33a0, 0x77037d81,
        0x63a440f2, 0xf8bce6e5, 0xe12c4247, 0x6b17d1f2 } },
    { { 0x37bf51f5, 0xcbb64068, 0x6b315ece, 0x2bce3357,
        0x7c0f9e16, 0x8ee7eb4a, 0xfe1a7f9b, 0x4fe342e2 } },
    B_FALSE
};
#define modulusP modulusP256
#define orderP orderP256
#define orderDBL orderDBL256
#define base_point baseP256
#define curve_b b_P256



#ifdef ARM7_ASM
#define MULACC(a, b)                            \
    __asm                    \
    {                        \
        UMULL tmpr0, tmpr1, a, b;           \
        ADDS sum0, sum0, tmpr0;           \
        ADCS sum1, sum1, tmpr1;           \
        ADC cum_carry, cum_carry, 0x0;       \
    }
// cumcarry: 32-bit word that accumulates carries
// sum0: lower half 32-bit word of sum
// sum1: higher half 32-bit word of sum
// a   : 32-bit operand to be multiplied
// b   : 32-bit operand to be multiplied
// tmpr0, tmpr1: two temporary words
// sum = sum + A*B where cout may contain carry info from previous operations

#define MULACC_DOUBLE(a, b)                     \
    __asm                    \
    {                        \
        UMULL tmpr0, tmpr1, a, b;           \
        ADDS sum0, sum0, tmpr0;           \
        ADCS sum1, sum1, tmpr1;           \
        ADC cum_carry, cum_carry, 0x0;       \
        ADDS sum0, sum0, tmpr0;           \
        ADCS sum1, sum1, tmpr1;           \
        ADC cum_carry, cum_carry, 0x0;       \
    }

#define ACCUM(ap, bp) MULACC(*(ap), *(bp))
#define ACCUMDBL(ap, bp) MULACC_DOUBLE(*(ap), *(bp))

#else /* ARM7_ASM, below is platform independent */

/* (sum, carry) += a * b */
static void mpy_accum(int* cumcarry, uint64_t* sum, uint32_t a, uint32_t b)
{
    uint64_t product = (uint64_t)a * (uint64_t)b;
    uint64_t lsum = *sum;

    lsum += product;
    if (lsum < product) {
        *cumcarry += 1;
    }
    *sum = lsum;
}

#ifdef SPECIAL_SQUARE

/* (sum, carry += 2 * a * b.  Attempts to reduce writes to memory and
   branches caused slowdown on windows machines. */
static void mpy_accum_dbl(int* cumcarry, uint64_t* sum, uint32_t a, uint32_t b)
{
    uint64_t product = (uint64_t)a * (uint64_t)b;
    uint64_t lsum = *sum;
    lsum += product;
    if (lsum < product) {
        *cumcarry += 1;
    }
    lsum += product;
    if (lsum < product) {
        *cumcarry += 1;
    }
    *sum = lsum;
}

#endif /* SPECIAL_SQUARE */

/* ap and bp are pointers to the words to be multiplied and accumulated */
#define ACCUM(ap, bp) mpy_accum(&cum_carry, &u_accum, *(ap),  *(bp))
#define ACCUMDBL(ap, bp) mpy_accum_dbl(&cum_carry, &u_accum, *(ap),  *(bp))

#endif /* !ARM7_ASM, ie platform independent */


/*
 * The big_mpyP algorithm first multiplies the two arguments, with the
 * outer loop indexing over output words, and the inner "loop"
 * (unrolled unless SMALL_CODE is defined), collecting all the terms
 * that contribute to that output word.
 *
 * The impementation is inspired by the Wallace Tree often used in
 * hardware [Wallace], where (0, 1) terms of the same weight are
 * collected together into a sequence values each of which can be on
 * the order of the number of bits in a word, and then the sequence is
 * turned into a binary number with a carry save adder.  This is
 * generized from base 2 to base 2^32.
 *
 * The first part of the algorithm sums together products of equal
 * weight.  The outer loop does carry propagation and makes each value
 * at most 32 bits.
 *
 * Then corrections are applied for negative arguments.  (The first
 * part essentially does unsigned multiplication.)
 *
 * The reduction proceeds in 2 steps.  The first treats the 32 bit
 * values (in 64 bit words) from above as though they were
 * polynomials, and reduces by the paper and pencil method.  Carries
 * are propagated and the result collapsed to a sequence of 32 bit
 * words (in the target).  The second step subtracts MSW * modulus
 * from the result.  This usually (but not always) results in the MSW
 * being zero.  (And that makes subsequent mutliplications faster.)
 *
 * The modselect parameter chooses whether reduction is mod the modulus
 * or the order of the curve.  If ECDSA is not defined, this parameter
 * is ignored, and the curve modulus is used.
 */

/*
 * Computes a * b, approximately reduced mod modulusP or orderP,
 * depending on the modselect flag.
 */
static void big_mpyP(bigval_t* tgt, bigval_t const* a, bigval_t const* b,
                     modulus_val_t modselect)
{
    int64_t w[2 * BIGLEN];
    int64_t s_accum; /* signed */
    int i, minj, maxj, a_words, b_words, cum_carry;
#ifdef SMALL_CODE
    int j;
#else
    uint32_t const* ap;
    uint32_t const* bp;
#endif

#ifdef ARM7_ASM
    uint32_t tmpr0, tmpr1, sum0, sum1;
#else
    uint64_t u_accum;
#endif

#ifdef ECDSA
#define MODSELECT modselect
#else
#define MODSELECT MOD_MODULUS
#endif


    a_words = BIGLEN;
    while (a_words > 0 && a->data[a_words - 1] == 0) {
        --a_words;
    }

    /*
     * i is target index.  The j (in comments only) indexes
     * through the multiplier.
     */
#ifdef ARM7_ASM
    sum0 = 0;
    sum1 = 0;
    cum_carry = 0;
#else
    u_accum = 0;
    cum_carry = 0;
#endif

#ifndef SPECIAL_SQUARE
#define NO_SPECIAL_SQUARE 1
#else
#define NO_SPECIAL_SQUARE 0
#endif


    if (NO_SPECIAL_SQUARE || a != b) {

        /* normal multiply */

        /* compute length of b */
        b_words = BIGLEN;
        while (b_words > 0 && b->data[b_words - 1] == 0) {
            --b_words;
        }

        /* iterate over words of output */
        for (i = 0; i < a_words + b_words - 1; ++i) {
            /* Run j over all possible values such that
               0 <= j < b_words && 0 <= i-j < a_words.
               Hence
               j >= 0 and j > i - a_words and
               j < b_words and j <= i

               (j exists only in the mind of the reader.)
             */
            maxj = MIN(b_words - 1, i);
            minj = MAX(0, i - a_words + 1);

            /* ACCUM accumlates into <cum_carry, u_accum>. */
#ifdef SMALL_CODE
            for (j = minj; j <= maxj; ++j) {
                ACCUM(a->data + i - j, b->data + j);
            }
#else /* SMALL_CODE not defined */
      /*
       * The inner loop (over j, running from minj to maxj) is
       * unrolled.  Sequentially increasing case values in the code
       * are intended to coax the compiler into emitting a jump
       * table. Here j runs from maxj to minj, but addition is
       * commutative, so it doesn't matter.
       */

            ap = &a->data[i - minj];
            bp = &b->data[minj];

            /* the order is opposite the loop, but addition is commutative */
            switch (8 - (maxj - minj)) {
            case 0: ACCUM(ap - 8, bp + 8); /* j = 8 */

            case 1: ACCUM(ap - 7, bp + 7);

            case 2: ACCUM(ap - 6, bp + 6);

            case 3: ACCUM(ap - 5, bp + 5);

            case 4: ACCUM(ap - 4, bp + 4);

            case 5: ACCUM(ap - 3, bp + 3);

            case 6: ACCUM(ap - 2, bp + 2);

            case 7: ACCUM(ap - 1, bp + 1);

            case 8: ACCUM(ap - 0, bp + 0); /* j = 0 */
            }
#endif /* SMALL_CODE not defined */


            /* The total value is
               w + u_accum << (32 *i) + cum_carry << (32 * i + 64).
               The steps from here to the end of the i-loop (not counting
               squaring branch) and the increment of i by the loop
               maintain the invariant that the value is constant.
               (Assume w had been initialized to zero, even though we
               really didn't.) */

#ifdef ARM7_ASM
            w[i] = sum0;
            sum0 = sum1;
            sum1 = cum_carry;
            cum_carry = 0;
#else
            w[i] = u_accum & 0xffffffffULL;
            u_accum = (u_accum >> 32) + ((uint64_t)cum_carry << 32);
            cum_carry = 0;
#endif
        }
    } else {
        /* squaring */

#ifdef SPECIAL_SQUARE

        /* a[i] * a[j] + a[j] * a[i] == 2 * (a[i] * a[j]), so
           we can cut the number of multiplies nearly in half. */
        for (i = 0; i < 2 * a_words - 1; ++i) {

            /* Run j over all possible values such that
               0 <= j < a_words && 0 <= i-j < a_words && j < i-j
               Hence
               j >= 0 and j > i - a_words and
               j < a_words and 2*j < i
             */
            maxj = MIN(a_words - 1, i);
            /* Only go half way.  Must use (i-1)>> 1, not (i-1)/ 2 */
            maxj = MIN(maxj, (i - 1) >> 1);
            minj = MAX(0, i - a_words + 1);
#ifdef SMALL_CODE
            for (j = minj; j <= maxj; ++j) {
                ACCUMDBL(a->data + i - j, a->data + j);
            }
            /* j live */
            if ((i & 1) == 0) {
                ACCUM(a->data + j, a->data + j);
            }
#else /* SMALL_CODE not defined */
            ap = &a->data[i - minj];
            bp = &a->data[minj];
            switch (8 - (maxj - minj)) {
            case 0: ACCUMDBL(ap - 8, bp + 8); /* j = 8 */

            case 1: ACCUMDBL(ap - 7, bp + 7);

            case 2: ACCUMDBL(ap - 6, bp + 6);

            case 3: ACCUMDBL(ap - 5, bp + 5);

            case 4: ACCUMDBL(ap - 4, bp + 4);

            case 5: ACCUMDBL(ap - 3, bp + 3);

            case 6: ACCUMDBL(ap - 2, bp + 2);

            case 7: ACCUMDBL(ap - 1, bp + 1);

            case 8: ACCUMDBL(ap - 0, bp + 0); /* j = 0 */
            }

            /* Even numbered columns (zero based) have a middle element. */
            if ((i & 1) == 0) {
                ACCUM(a->data + maxj + 1, a->data + maxj + 1);
            }
#endif /* SMALL_CODE not defined */

            /* The total value is
               w + u_accum << (32 *i) + cum_carry << (32 * i + 64).
               The steps from here to the end of i-loop and
               the increment of i by the loop maintain the invariant
               that the total value is unchanged.
               (Assume w had been initialized to zero, even though we
               really didn't.) */
#ifdef ARM7_ASM
            w[i] = sum0;
            sum0 = sum1;
            sum1 = cum_carry;
            cum_carry = 0;
#else /* ARM7_ASM not defined */
            w[i] = u_accum & 0xffffffffULL;
            u_accum = (u_accum >> 32) + ((uint64_t)cum_carry << 32);
            cum_carry = 0;
#endif /* ARM7_ASM not defined */
        }
#endif /* SPECIAL_SQUARE */
    } /* false branch of NO_SPECIAL_SQUARE || (a != b)  */

    /* The total value as indicated above is maintained invariant
       down to the approximate reduction code below. */

    /* propagate any residual to next to end of array */
    for (; i < 2 * BIGLEN - 1; ++i) {
#ifdef ARM7_ASM
        w[i] = sum0;
        sum0 = sum1;
        sum1 = 0;
#else
        w[i] = u_accum & 0xffffffffULL;
        u_accum >>= 32;
#endif
    }
    /* i is still live */
    /* from here on, think of w as containing signed values */

    /* Last value of the array, still using i.  We store the entire 64
       bits.  There are two reasons for this.  The pedantic one is that
       this clearly maintains our invariant that the value has not
       changed.  The other one is that this makes w[BIGNUM-1] negative
       if the result was negative, and reduction depends on this. */

#ifdef ARM7_ASM
    w[i] = ((uint64_t)sum1 << 32) | sum0;
    /* sum1 = sum0 = 0;  maintain invariant */
#else
    w[i] = u_accum;
    /* u_accum = 0; maintain invariant */
#endif

    /*
     * Apply correction if a or b are negative.  It would be nice to
     * put this inside the i-loop to reduce memory bandwidth.  Later...
     *
     * signvedval(a) = unsignedval(a) - 2^(32*BIGLEN)*isneg(a).
     *
     * so signval(a) * signedval(b) = unsignedval(a) * unsignedval[b] -
     *   isneg(a) * unsignedval(b) * 2^(32*BIGLEN) -
     *   isneg(b) * unsingedval(a) * 2^ (32*BIGLEN) +
     *   isneg(a) * isneg(b) * 2 ^(2 * 32 * BIGLEN)
     *
     * If one arg is zero and the other is negative, obviously no
     * correction is needed, but we do not make a special case, since
     * the "correction" only adds in zero.
     */

    if (big_is_negative(a)) {
        for (i = 0; i < BIGLEN; ++i) {
            w[i + BIGLEN] -= b->data[i];
        }
    }
    if (big_is_negative(b)) {
        for (i = 0; i < BIGLEN; ++i) {
            w[i + BIGLEN] -= a->data[i];
        }
        if (big_is_negative(a)) {
            /* both negative */
            w[2 * BIGLEN - 1] += 1ULL << 32;
        }
    }

    /*
     * The code from here to the end of the function maintains w mod
     * modulusP constant, even though it changes the value of w.
     */

    /* reduce (approximate) */
    if (MODSELECT == MOD_MODULUS) {
        for (i = 2 * BIGLEN - 1; i >= MSW; --i) {
            int64_t v;
            v = w[i];
            if (v != 0) {
                w[i] = 0;
                w[i - 1] += v;
                w[i - 2] -= v;
                w[i - 5] -= v;
                w[i - 8] += v;
            }
        }
    } else {
        /* modulo order.  Not performance critical */
#ifdef ECDSA

        int64_t carry;

        /* convert to 32 bit values, except for most signifiant word */
        carry = 0;
        for (i = 0; i < 2 * BIGLEN - 1; ++i) {
            w[i] += carry;
            carry =  w[i] >> 32;
            w[i] -= carry << 32;
        }
        /* i is live */
        w[i] += carry;

        /* each iteration knocks off word i */
        for (i = 2 * BIGLEN - 1; i >= MSW; --i) { /* most to least significant */
            int64_t v;
            int64_t tmp;
            int64_t tmp2;
            int j;
            int k;

            for (k = 0; w[i] != 0 && k < 3; ++k) {
                v = w[i];
                carry = 0;
                for (j = i - MSW; j < 2 * BIGLEN; ++j) {
                    if (j <= i) {
                        tmp2 = -(v * orderDBL.data[j - i + MSW]);
                        tmp = w[j] + tmp2 + carry;
                    } else {
                        tmp = w[j] + carry;
                    }
                    if (j < 2 * BIGLEN - 1) {
                        carry = tmp >> 32;
                        tmp -= carry << 32;
                    } else {
                        carry = 0;
                    }
                    w[j] = tmp;
                }
            }
        }
#endif /* ECDSA */
    }

    /* propagate carries and copy out to tgt in 32 bit chunks. */
    s_accum = 0;
    for (i = 0; i < BIGLEN; ++i) {
        s_accum += w[i];
        tgt->data[i] = (uint32_t)s_accum;
        s_accum >>= 32; /* signed, so sign bit propagates */
    }

    /* final approximate reduction */

    if (MODSELECT == MOD_MODULUS) {
        big_approx_reduceP(tgt, tgt);
    } else {
#ifdef ECDSA
        if (tgt->data[MSW]) {
            /* Keep it simple! At one time all this was done in place,
               and was totally unobvious. */
            bigval_t tmp;
            /* The most significant word is signed, even though the
               whole array has declared uint32_t.  */
            big_1wd_mpy(&tmp, &orderP, (int32_t)tgt->data[MSW]);
            big_sub(tgt, tgt, &tmp);
        }
#endif /* ECDSA */
    }
}

/*
 * Adds k * modulusP to a and stores into target.  -2^62 <= k <= 2^62 .
 * (This is conservative.)
 */
static void big_adjustP(bigval_t* tgt, bigval_t const* a, int64_t k)
{


#define RDCSTEP(i, adj)                         \
    w += a->data[i];             \
    w += (adj);                  \
    tgt->data[i] = (uint32_t)(int32_t)w;     \
    w >>= 32;

    /* add k * modulus */

    if (k != 0) {
        int64_t w = 0;
        RDCSTEP(0, -k);
        RDCSTEP(1, 0);
        RDCSTEP(2, 0);
        RDCSTEP(3, k);
        RDCSTEP(4, 0);
        RDCSTEP(5, 0);
        RDCSTEP(6, k);
        RDCSTEP(7, -k);
        RDCSTEP(8, k);
    } else if (tgt != a) {
        *tgt = *a;
    }
}

/*
 * Computes k * a and stores into target.  Conditions: product must
 * be representable in bigval_t.
 */
static void big_1wd_mpy(bigval_t* tgt, bigval_t const* a, int32_t k)
{
    int64_t w = 0;
    int64_t tmp;
    int64_t prod;
    int j;

    for (j = 0; j <= MSW; ++j) {
        prod = (int64_t)k * (int64_t)a->data[j];
        tmp = w + prod;
        w = tmp;
        tgt->data[j] = (uint32_t)w;
        w -= tgt->data[j];
        w >>= 32;
    }
}


/*
 * Adds a to b as signed (2's complement) numbers.  Ok to use for
 * modular values if you don't let the sum overflow.
 */
COND_STATIC void big_add(bigval_t* tgt, bigval_t const* a, bigval_t const* b)
{
    uint64_t v;
    int i;

    v = 0;
    for (i = 0; i < BIGLEN; ++i) {
        v += a->data[i];
        v += b->data[i];
        tgt->data[i] = (uint32_t)v;
        v >>= 32;
    }
}

/* 2's complement subtraction */
static void big_sub(bigval_t* tgt, bigval_t const* a, bigval_t const* b)
{
    uint64_t v;
    int i;
    /* negation is equivalent to 1's complement and increment */

    v = 1; /* increment */
    for (i = 0; i < BIGLEN; ++i) {
        v += a->data[i];
        v += ~b->data[i]; /* 1's complement */
        tgt->data[i] = (uint32_t)v;
        v >>= 32;
    }
}


/* returns 1 if a > b, -1 if a < b, and 0 if a == b.
   a and b are 2's complement.  When applied to modular values,
   args must be precisely reduced. */
static int big_cmp(bigval_t const* a, bigval_t const* b)
{
    int i;

    /* most significant word is treated as 2's complement */
    if ((int32_t)a->data[MSW] > (int32_t)b->data[MSW]) {
        return (1);
    } else if ((int32_t)a->data[MSW] < (int32_t)b->data[MSW]) {
        return (-1);
    }
    /* remainder treated as unsigned */
    for (i = MSW - 1; i >= 0; --i) {
        if (a->data[i] > b->data[i]) {
            return (1);
        } else if (a->data[i] < b->data[i]) {
            return (-1);
        }
    }
    return (0);
}


/*
 * Computes tgt = a mod modulus.  Only works with modluii slightly
 * less than 2**(32*(BIGLEN-1)).  Both modulusP and orderP qualify.
 */
static void big_precise_reduce(bigval_t* tgt, bigval_t const* a, bigval_t const* modulus)
{
    /*
     * src is a trick to avoid an extra copy of a to arg a to a
     * temporary.  Every statement uses src as the src and tgt as the
     * destination, and it executes src = tgt, so all subsequent
     * operations affect the modified data, not the original.  There is
     * a case to handle the situation of no modifications having been
     * made.
     */
    bigval_t const* src = a;

    /* If tgt < 0, a positive value gets added in, so eventually tgt
       will be >= 0.  If tgt > 0 and the MSW is non-zero, a non-zero
       value smaller than tgt gets subtracted, so eventually target
       becomes < 1 * 2**(32*MSW), but not negative, i.e. tgt->data[MSW]
       == 0, and thus loop termination is guaranteed. */


    while ((int32_t)src->data[MSW] != 0) {
        if (modulus != &modulusP) {
            /* General case.  Keep it simple! */
            bigval_t tmp;

            /* The most significant word is signed, even though the
               whole array has been declared uint32_t.  */
            big_1wd_mpy(&tmp, modulus, (int32_t)src->data[MSW]);
            big_sub(tgt, src, &tmp);
        } else {
            /* just an optimization.  The other branch would work, but slower. */
            big_adjustP(tgt, src, -(int64_t)(int32_t)src->data[MSW]);
        }
        src = tgt;
    }

    while (big_cmp(src, modulus) >= 0) {
        big_sub(tgt, src, modulus);
        src = tgt;
    }
    while ((int32_t)src->data[MSW] < 0) {
        big_add(tgt, src, modulus);
        src = tgt;
    }

    /* copy src to tgt if not already done */

    if (src != tgt) {
        *tgt = *src;
    }
}

/* computes floor(a / 2), 2's complement. */
static void big_halve(bigval_t* tgt, bigval_t const* a)
{
    uint32_t shiftval;
    uint32_t new_shiftval;
    int i;

    /* most significant word is 2's complement.  Do it separately. */
    shiftval = a->data[MSW] & 1;
    tgt->data[MSW] = (uint32_t)((int32_t)a->data[MSW] >> 1);

    for (i = MSW - 1; i >= 0; --i) {
        new_shiftval = a->data[i] & 1;
        tgt->data[i] = (a->data[i] >> 1) | (shiftval << 31);
        shiftval = new_shiftval;
    }
}

/* returns B_TRUE if a is zero */
boolean_t big_is_zero(bigval_t const* a)
{
    int i;

    for (i = 0; i < BIGLEN; ++i) {
        if (a->data[i] != 0) {
            return (B_FALSE);
        }
    }
    return (B_TRUE);
}

/* returns B_TRUE if a is one */
static boolean_t big_is_one(bigval_t const* a)
{
    int i;

    if (a->data[0] != 1) {
        return (B_FALSE);
    }
    for (i = 1; i < BIGLEN; ++i) {
        if (a->data[i] != 0) {
            return (B_FALSE);
        }
    }
    return (B_TRUE);
}


/*
 * This uses the extended binary GCD (Greatest Common Divisor)
 * algorithm.  The binary GCD algorithm is presented in [KnuthV2] as
 * Algorithm X.  The extension to do division is presented in Homework
 * Problem 15 and its solution in the back of the book.
 *
 * The implementation here follows the presentation in [HMV] Algorithm
 * 2.22.
 *
 * If the denominator is zero, it will loop forever.  Be careful!
 * Modulus must be odd.  num and den must be positive.
 */
static void big_divide(bigval_t* tgt, bigval_t const* num, bigval_t const* den,
                       bigval_t const* modulus)
{
    bigval_t u, v, x1, x2;

    u = *den;
    v = *modulus;
    x1 = *num;
    x2 = big_zero;

    while (!big_is_one(&u) && !big_is_one(&v)) {
        while (!big_is_odd(&u)) {
            big_halve(&u, &u);
            if (big_is_odd(&x1)) {
                big_add(&x1, &x1, modulus);
            }
            big_halve(&x1, &x1);
        }
        while (!big_is_odd(&v)) {
            big_halve(&v, &v);
            if (big_is_odd(&x2)) {
                big_add(&x2, &x2, modulus);
            }
            big_halve(&x2, &x2);
        }
        if (big_cmp(&u, &v) >= 0) {
            big_sub(&u, &u, &v);
            big_sub(&x1, &x1, &x2);
        } else {
            big_sub(&v, &v, &u);
            big_sub(&x2, &x2, &x1);
        }
    }

    if (big_is_one(&u)) {
        big_precise_reduce(tgt, &x1, modulus);
    } else {
        big_precise_reduce(tgt, &x2, modulus);
    }
}

/*
 * Convert a digit256_t (internal representation of field elements) to a
 * bigval_t. Note: dst must have space for sizeof(digit256_t) + 4 bytes.
 */
void digit256_to_bigval(digit256_tc src, bigval_t* dst)
{
    AJ_ASSERT((BIGLEN - 1) * sizeof(uint32_t) == sizeof(digit256_t));

    memcpy(dst->data, src, sizeof(digit256_t));
    dst->data[BIGLEN - 1] = 0;

#if HOST_IS_BIG_ENDIAN
    int i;
    for (i = 0; i < (BIGLEN - 1); i += 2) {    /* Swap adjacent 32-bit words */
        SWAP(dst->data[i], dst->data[i + 1]);
    }
#endif

}

/*
 * Convert a bigval_t to a digit256_t.  Return TRUE if src was
 * successfully converted, FALSE otherwise.
 */
boolean_t bigval_to_digit256(const bigval_t* src, digit256_t dst)
{
    AJ_ASSERT((BIGLEN - 1) * sizeof(uint32_t) == sizeof(digit256_t));

    /* Fail on negative inputs, since any negative value received in the
     * bigval_t format is invalid. */
    if (big_is_negative(src)) {
        return B_FALSE;
    }

    memcpy(dst, src->data, sizeof(digit256_t));

#if HOST_IS_BIG_ENDIAN
    int i;
    uint32_t* data = (uint32_t*)dst;
    for (i = 0; i < (BIGLEN - 1); i += 2) {    /* Swap adjacent 32-bit words */
        SWAP(data[i], data[i + 1]);
    }
#endif

    return B_TRUE;
}

COND_STATIC boolean_t in_curveP(affine_point_t const* P)
{
    ecpoint_t Pt;
    ec_t curve;

    boolean_t fInfinity;
    boolean_t fValid;

    AJ_Status status;

    status = ec_getcurve(&curve, NISTP256r1);
    if (status != AJ_OK) {
        return B_FALSE;
    }

    fInfinity = P->infinity;

    bigval_to_digit256(&P->x, Pt.x);
    bigval_to_digit256(&P->y, Pt.y);

    fValid = (boolean_t)ecpoint_validation(&Pt, &curve);

    ec_freecurve(&curve);
    return(fInfinity | fValid);

}

int ECDH_generate(affine_point_t* P1, bigval_t* k)
{
    /* Compute a key pair (r, Q) then re-encode and ouput as (k, P1). */
    digit256_t r;
    ecpoint_t g, Q;
    ec_t curve;
    AJ_Status status;

    status = ec_getcurve(&curve, NISTP256r1);
    if (status != AJ_OK) {
        goto Exit;
    }

    /* Choose random r in [0, curve order - 1]*/
    do {
        AJ_RandBytes((uint8_t*)r, sizeof(digit256_t));
    } while (!validate_256(r, curve.order));

    ec_get_generator(&g, &curve);
    ec_scalarmul(&g, r, &Q, &curve);        /* Q = g^r */

    /* Convert out of internal representation. */
    digit256_to_bigval(r, k);
    digit256_to_bigval(Q.x, &(P1->x));
    digit256_to_bigval(Q.y, &(P1->y));
    P1->infinity = B_FALSE;

Exit:
    fpzero_p256(r);
    fpzero_p256(Q.x);
    fpzero_p256(Q.y);
    ec_freecurve(&curve);
    return status;
}

/* Compute tgt = Q^k.  Q is validated. */
COND_STATIC boolean_t ECDH_derive_pt(affine_point_t* tgt, bigval_t const* k, affine_point_t const* Q)
{
    boolean_t status;
    AJ_Status ajstatus;
    ecpoint_t theirPublic;      /* internal representation of Q */
    ecpoint_t sharedSecret;
    digit256_t ourPrivate;      /* internal representation of k */
    ec_t curve;

    ajstatus = ec_getcurve(&curve, NISTP256r1);
    if (ajstatus != AJ_OK) {
        status = B_FALSE;
        goto Exit;
    }

    /* Convert to internal representation */
    status = bigval_to_digit256(k, ourPrivate);
    status = status && bigval_to_digit256(&(Q->x), theirPublic.x);
    status = status && bigval_to_digit256(&(Q->y), theirPublic.y);
    if (!status) {
        goto Exit;
    }

    if (!ecpoint_validation(&theirPublic, &curve)) {
        status = B_FALSE;
        goto Exit;
    }

    /* Compute sharedSecret = theirPublic^ourPrivate */
    ec_scalarmul(&theirPublic, ourPrivate, &sharedSecret, &curve);

    /* Copy sharedSecret to tgt */
    digit256_to_bigval(sharedSecret.x, &(tgt->x));
    digit256_to_bigval(sharedSecret.y, &(tgt->y));

Exit:
    /* Clean up local copies. */
    fpzero_p256(sharedSecret.x);
    fpzero_p256(sharedSecret.y);
    fpzero_p256(ourPrivate);
    ec_freecurve(&curve);
    return status;
}

static void BigvalEncode(const bigval_t* src, uint8_t* tgt, size_t tgtlen)
{
    size_t i;
    uint8_t v;
    uint8_t highbytes = big_is_negative(src) ? 0xff : 0;

    /* LSbyte to MS_byte */
    for (i = 0; i < 4 * BIGLEN; ++i) {
        if (i < tgtlen) {
            v = src->data[i / 4] >> (8 * (i % 4));
            ((uint8_t*)tgt)[tgtlen - 1 - i] = v;
        }
    }
    /* i is live */
    for (; i < tgtlen; ++i) {
        ((uint8_t*)tgt)[tgtlen - 1 - i] = highbytes;
    }
}

static void BigvalDecode(const uint8_t* src, bigval_t* tgt, size_t srclen)
{
    size_t i;
    uint8_t v;

    /* zero the bigval_t */
    memset((uint8_t*) tgt, 0, sizeof (bigval_t));
    /* scan from LSbyte to MSbyte */
    for (i = 0; i < srclen && i < 4 * BIGLEN; ++i) {
        v = ((uint8_t*)src)[srclen - 1 - i];
        tgt->data[i / 4] |= (uint32_t)v << (8 * (i % 4));
    }
}

#ifdef ECDSA
/*
 * This function sets the r and s fields of sig.  The implementation
 * follows HMV Algorithm 4.29.
 */
static int ECDSA_sign(bigval_t const* msgdgst,
                      bigval_t const* privkey,
                      ECDSA_sig_t* sig)
{
    int rv;
    affine_point_t P1;
    bigval_t k;
    bigval_t t;

startpoint:

    rv = ECDH_generate(&P1, &k);
    if (rv) {
        return (rv);
    }

    big_precise_reduce(&sig->r, &P1.x, &orderP);
    if (big_is_zero(&sig->r)) {
        goto startpoint;
    }

    big_mpyP(&t, privkey, &sig->r, MOD_ORDER);
    big_add(&t, &t, msgdgst);
    big_precise_reduce(&t, &t, &orderP); /* may not be necessary */
    big_divide(&sig->s, &t, &k, &orderP);
    if (big_is_zero(&sig->s)) {
        goto startpoint;
    }

    return (0);
}

/*
 * Returns B_TRUE if the signature is valid.
 * The implementation follow HMV Algorithm 4.30.
 */
static verify_res_t ECDSA_verify_inner(bigval_t const* msgdgst,
                                       affine_point_t const* pubkey,
                                       ECDSA_sig_t const* sig)
{

    /* We could reuse variables and save stack space.  If stack space
       is tight, u1 and u2 could be the same variable by interleaving
       the big multiplies and the point multiplies. P2 and X could be
       the same variable.  X.x could be reduced in place, eliminating
       v. And if you really wanted to get tricky, I think one could use
       unions between the affine and jacobian versions of points. But
       check that out before doing it. */


    verify_res_t res;
    bigval_t v;
    bigval_t w;
    bigval_t u1;
    bigval_t u2;
    digit256_t digU1;
    digit256_t digU2;
    ecpoint_t Q;
    ecpoint_t P1;
    ecpoint_t P2;
    ecpoint_t G;
    ecpoint_t X;
    ec_t curve;

    boolean_t status;
    AJ_Status ajstatus;

    ajstatus = ec_getcurve(&curve, NISTP256r1);
    if (ajstatus != AJ_OK) {
        /* curve has already been free'd */
        return (V_INTERNAL);
    }

    ec_get_generator(&G, &curve);

    status = bigval_to_digit256(&(pubkey->x), Q.x);
    status = status && bigval_to_digit256(&(pubkey->y), Q.y);
    status = status && ecpoint_validation(&Q, &curve);
    if (!status) {
        res = (V_INTERNAL);
        goto Exit;
    }

    if (big_cmp(&sig->r, &big_one) < 0) {
        res = (V_R_ZERO);
        goto Exit;
    }
    if (big_cmp(&sig->r, &orderP) >= 0) {
        res = (V_R_BIG);
        goto Exit;
    }
    if (big_cmp(&sig->s, &big_one) < 0) {
        res = (V_S_ZERO);
        goto Exit;
    }
    if (big_cmp(&sig->s, &orderP) >= 0) {
        res = (V_S_BIG);
        goto Exit;
    }

    big_divide(&w, &big_one, &sig->s, &orderP);
    big_mpyP(&u1, msgdgst, &w, MOD_ORDER);
    big_precise_reduce(&u1, &u1, &orderP);
    big_mpyP(&u2, &sig->r, &w, MOD_ORDER);
    big_precise_reduce(&u2, &u2, &orderP);

    status = bigval_to_digit256(&u1, digU1);
    status = status && bigval_to_digit256(&u2, digU2);
    if (!status) {
        res = (V_INTERNAL);
        goto Exit;
    }

    ec_scalarmul(&(curve.generator), digU1, &P1, &curve);
    ec_scalarmul(&Q, digU2, &P2, &curve);

    // copy P1 point over
    memcpy(X.x, P1.x, sizeof(digit256_t));
    memcpy(X.y, P1.y, sizeof(digit256_t));

    ec_add(&X, &P2, &curve);

    if (ec_is_infinity(&X, &curve)) {
        res = (V_INFINITY);
        goto Exit;
    }

    digit256_to_bigval(X.x, &v);
    if (big_cmp(&v, &sig->r) != 0) {
        res = (V_UNEQUAL);
        goto Exit;
    }
    res = (V_SUCCESS);

Exit:
    ec_freecurve(&curve);
    return res;
}

boolean_t ECDSA_verify(bigval_t const* msgdgst,
                       affine_point_t const* pubkey,
                       ECDSA_sig_t const* sig)
{
    if (ECDSA_verify_inner(msgdgst, pubkey, sig) == V_SUCCESS) {
        return B_TRUE;
    }
    return B_FALSE;
}



/*
 * Converts a hash value to a bigval_t.  The rules for this in
 * ANSIX9.62 are strange.  Let b be the number of octets necessary to
 * represent the modulus.  If the size of the hash is less than or
 * equal to b, the hash is interpreted directly as a number.
 * Otherwise the left most b octets of the hash are converted to a
 * number. The hash must be big-endian by byte. There is no alignment
 * requirement on hashp.
 */
void ECC_hash_to_bigval(bigval_t* tgt, void const* hashp, unsigned int hashlen)
{
    unsigned int i;

    /* The "4"s in the rest of this function are the number of bytes in
       a uint32_t (what bigval_t's are made of).  The "8" is the number
       of bits in a byte. */

    /* reduce hashlen to modulus size, if necessary */

    if (hashlen > 4 * (BIGLEN - 1)) {
        hashlen = 4 * (BIGLEN - 1);
    }

    *tgt = big_zero;
    /* move one byte at a time starting with least significant byte */
    for (i = 0; i < hashlen; ++i) {
        tgt->data[i / 4] |=
            ((uint8_t*)hashp)[hashlen - 1 - i] << (8 * (i % 4));
    }
}
#endif /* ECDSA */

#ifdef ECC_TEST
char* ECC_feature_list(void)
{
    return ("ECC_P256"
#ifdef ECDSA
            " ECDSA"
#endif
#ifdef SPECIAL_SQUARE
            " SPECIAL_SQUARE"
#endif
#ifdef SMALL_CODE
            " SMALL_CODE"
#endif
#ifdef MPY2BITS
            " MPY2BITS"
#endif
#ifdef ARM7_ASM
            " ARM7_ASM"
#endif
            );
}
#endif /* ECC_TEST */

typedef bigval_t ecc_privatekey;
typedef affine_point_t ecc_publickey;
typedef affine_point_t ecc_secret;
typedef ECDSA_sig_t ecc_signature;

AJ_Status AJ_GenerateECCKeyPair(AJ_ECCPublicKey* pub, AJ_ECCPrivateKey* prv)
{
    ecc_publickey publickey;
    ecc_privatekey privatekey;

    if (0 != ECDH_generate(&publickey, &privatekey)) {
        return AJ_ERR_SECURITY;
    }

    /* Encode native to big-endian structures */
    pub->alg = KEY_ALG_ECDSA_SHA256;
    pub->crv = KEY_CRV_NISTP256;
    prv->alg = KEY_ALG_ECDSA_SHA256;
    prv->crv = KEY_CRV_NISTP256;
    BigvalEncode(&publickey.x, pub->x, KEY_ECC_SZ);
    BigvalEncode(&publickey.y, pub->y, KEY_ECC_SZ);
    BigvalEncode(&privatekey, prv->x, KEY_ECC_SZ);

    return AJ_OK;
}

AJ_Status AJ_GenerateShareSecret(AJ_ECCPublicKey* pub, AJ_ECCPrivateKey* prv, AJ_ECCSecret* sec)
{
    boolean_t derive_rv;
    ecc_publickey publickey;
    ecc_privatekey privatekey;
    ecc_secret secret;

    /* Decode big-endian structures to native */
    publickey.infinity = B_FALSE;
    BigvalDecode(pub->x, &publickey.x, KEY_ECC_SZ);
    BigvalDecode(pub->y, &publickey.y, KEY_ECC_SZ);
    BigvalDecode(prv->x, &privatekey, KEY_ECC_SZ);

    derive_rv = ECDH_derive_pt(&secret, &privatekey, &publickey);
    if (!derive_rv) {
        return AJ_ERR_SECURITY;  /* bad */
    } else if (!in_curveP(&secret)) {
        return AJ_ERR_SECURITY;  /* bad */
    }

    /* Encode native to big-endian structures */
    sec->crv = KEY_CRV_NISTP256;
    BigvalEncode(&secret.x, sec->x, KEY_ECC_SZ);

    return AJ_OK;
}

AJ_Status AJ_ECDSASignDigest(const uint8_t* digest, const AJ_ECCPrivateKey* prv, AJ_ECCSignature* sig)
{
    bigval_t source;
    ecc_privatekey privatekey;
    ecc_signature signature;

    /* Decode big-endian structures to native */
    BigvalDecode(prv->x, &privatekey, KEY_ECC_SZ);

    ECC_hash_to_bigval(&source, digest, AJ_SHA256_DIGEST_LENGTH);
    if (0 != ECDSA_sign(&source, &privatekey, &signature)) {
        return AJ_ERR_SECURITY;
    }

    /* Encode native to big-endian structures */
    sig->alg = KEY_ALG_ECDSA_SHA256;
    sig->crv = KEY_CRV_NISTP256;
    BigvalEncode(&signature.r, sig->r, KEY_ECC_SZ);
    BigvalEncode(&signature.s, sig->s, KEY_ECC_SZ);

    return AJ_OK;
}

AJ_Status AJ_ECDSASign(const uint8_t* buf, uint16_t len, const AJ_ECCPrivateKey* prv, AJ_ECCSignature* sig)
{
    AJ_SHA256_Context* ctx;
    uint8_t digest[AJ_SHA256_DIGEST_LENGTH];
    AJ_Status status;

    ctx = AJ_SHA256_Init();
    if (!ctx) {
        return AJ_ERR_RESOURCES;
    }
    AJ_SHA256_Update(ctx, buf, (size_t) len);
    status = AJ_SHA256_Final(ctx, digest);
    if (status != AJ_OK) {
        return status;
    }

    return AJ_ECDSASignDigest(digest, prv, sig);
}

AJ_Status AJ_ECDSAVerifyDigest(const uint8_t* digest, const AJ_ECCSignature* sig, const AJ_ECCPublicKey* pub)
{
    bigval_t source;
    ecc_publickey publickey;
    ecc_signature signature;

    /* Decode big-endian structures to native */
    publickey.infinity = B_FALSE;
    BigvalDecode(pub->x, &publickey.x, KEY_ECC_SZ);
    BigvalDecode(pub->y, &publickey.y, KEY_ECC_SZ);
    BigvalDecode(sig->r, &signature.r, KEY_ECC_SZ);
    BigvalDecode(sig->s, &signature.s, KEY_ECC_SZ);

    ECC_hash_to_bigval(&source, digest, AJ_SHA256_DIGEST_LENGTH);
    if (ECDSA_verify(&source, &publickey, &signature) == B_TRUE) {
        return AJ_OK;
    }

    return AJ_ERR_SECURITY;
}

AJ_Status AJ_ECDSAVerify(const uint8_t* buf, uint16_t len, const AJ_ECCSignature* sig, const AJ_ECCPublicKey* pub)
{
    AJ_SHA256_Context* ctx;
    uint8_t digest[AJ_SHA256_DIGEST_LENGTH];
    AJ_Status status;

    ctx = AJ_SHA256_Init();
    if (!ctx) {
        return AJ_ERR_RESOURCES;
    }
    AJ_SHA256_Update(ctx, (const uint8_t*) buf, (size_t) len);
    status = AJ_SHA256_Final(ctx, digest);
    if (status != AJ_OK) {
        return status;
    }

    return AJ_ECDSAVerifyDigest(digest, sig, pub);
}

void AJ_BigEndianEncodePublicKey(AJ_ECCPublicKey* pub, uint8_t* b8)
{
    ecc_publickey publickey;
    publickey.infinity = B_FALSE;
    BigvalDecode(pub->x, &publickey.x, KEY_ECC_SZ);
    BigvalDecode(pub->y, &publickey.y, KEY_ECC_SZ);
    HostU32ToBigEndianU8((uint32_t*) &publickey, sizeof (ecc_publickey), b8);
}

void AJ_BigEndianDecodePublicKey(AJ_ECCPublicKey* pub, uint8_t* b8)
{
    ecc_publickey publickey;
    BigEndianU8ToHostU32(b8, (uint32_t*) &publickey, sizeof (ecc_publickey));
    BigvalEncode(&publickey.x, pub->x, KEY_ECC_SZ);
    BigvalEncode(&publickey.y, pub->y, KEY_ECC_SZ);
}

AJ_Status AJ_GenerateShareSecretOld(AJ_ECCPublicKey* pub, AJ_ECCPrivateKey* prv, AJ_ECCPublicKey* sec)
{
    boolean_t derive_rv;
    ecc_publickey publickey;
    ecc_privatekey privatekey;
    ecc_secret secret;

    /* Decode big-endian structures to native */
    publickey.infinity = B_FALSE;
    BigvalDecode(pub->x, &publickey.x, KEY_ECC_SZ);
    BigvalDecode(pub->y, &publickey.y, KEY_ECC_SZ);
    BigvalDecode(prv->x, &privatekey, KEY_ECC_SZ);

    derive_rv = ECDH_derive_pt(&secret, &privatekey, &publickey);
    if (!derive_rv) {
        return AJ_ERR_SECURITY;  /* bad */
    } else if (!in_curveP(&secret)) {
        return AJ_ERR_SECURITY;  /* bad */
    }

    /* Encode native to big-endian structures */
    sec->crv = KEY_CRV_NISTP256;
    BigvalEncode(&secret.x, sec->x, KEY_ECC_SZ);
    BigvalEncode(&secret.y, sec->y, KEY_ECC_SZ);

    return AJ_OK;
}

/*
 * Not a general-purpose implementation of REDP-1 from IEEE 1363.
 * Only used in AllJoyn to derive two basepoints, from the fixed constants
 * "ALLJOYN-ECSPEKE-1" and "ALLJOYN-ECSPEKE-2"
 * pi is not treated as a secret value.
 * This function is not constant-time.
 */
AJ_Status ec_REDP1(const uint8_t* pi, size_t len, ecpoint_t* Q, ec_t* curve)
{
    AJ_Status status = AJ_OK;
    AJ_SHA256_Context* ctx;
    uint8_t digest_i1[AJ_SHA256_DIGEST_LENGTH];
    uint8_t bytes_O3[AJ_SHA256_DIGEST_LENGTH];
    digit256_t x, alpha, beta;
    digit256_t tmp;
    digit_t temps[P256_TEMPS];
    int mu, carry, i;
    digit256_tc P256_A = { 0xFFFFFFFFFFFFFFFCULL, 0x00000000FFFFFFFFULL, 0x0000000000000000ULL, 0xFFFFFFFF00000001ULL };
    digit256_tc P256_B = { 0x3BCE3C3E27D2604BULL, 0x651D06B0CC53B0F6ULL, 0xB3EBBD55769886BCULL, 0x5AC635D8AA3A93E7ULL };

    /* Steps and notation follow IEEE 1363.2 Section 8.2.17 "[EC]REDP-1" */

    /* Hash pi to an octet string --  Step (a)*/
    ctx = AJ_SHA256_Init();
    if (!ctx) {
        return AJ_ERR_RESOURCES;
    }
    AJ_SHA256_Update(ctx, pi, len);
    AJ_SHA256_Final(ctx, digest_i1);

    while (1) {
        /* mu is rightmost bit of digest_i1 */
        mu = digest_i1[sizeof(digest_i1) - 1] % 2;

        /* Hash the hash -- Steps (b), (c), (d). */
        ctx = AJ_SHA256_Init();
        if (!ctx) {
            return AJ_ERR_RESOURCES;
        }
        AJ_SHA256_Update(ctx, digest_i1, sizeof(digest_i1));
        AJ_SHA256_Final(ctx, bytes_O3);

        /* Convert octets O3 to the field element x -- Step (e) */
        fpimport_p256(bytes_O3, x, temps, TRUE);

        /* Compute alpha = x^3 + a*x + b (mod p)  */
        fpmul_p256(x, x, alpha, temps);             /* alpha = x^2 */
        fpmul_p256(alpha, x, alpha, temps);         /* alpha = x^3 */
        fpmul_p256(x, P256_A, tmp, temps);          /* tmp = a*x */
        fpadd_p256(alpha, tmp, alpha);              /* alpha = x^3 + a*x */
        fpadd_p256(alpha, P256_B, alpha);           /* alpha = x^3 + a*x + b */

        /* Compute beta = a sqrt of alpha, if possible, if not begin a new iteration. */
        if (fpissquare_p256(alpha, temps)) {
            fpsqrt_p256(alpha, beta, temps);
        } else {
            /* Increment digest_i1 (as a big endian integer) then start a new iteration */
            carry = 1;
            for (i = sizeof(digest_i1) - 1; i >= 0; i--) {
                digest_i1[i] += carry;
                carry = (digest_i1[i] == 0);
            }

            if (carry) {
                /* It's overflown sizeof(digest_i1), fail. The probability of
                 * this occuring is negligible.
                 */
                status = AJ_ERR_FAILURE;
                goto Exit;
            }
            continue;
        }

        if (mu) {
            fpneg_p256(beta);
        }

        /* Output (x,beta) */
        memcpy(Q->x, x, sizeof(digit256_t));
        memcpy(Q->y, beta, sizeof(digit256_t));
        break;
    }

    /* Make sure the point is valid, and is not the identity. */
    if (!ecpoint_validation(Q, curve)) {
        status = AJ_ERR_FAILURE;
        goto Exit;
    }

Exit:
    /* Nothing to zero since inputs are public. */
    return status;
}

/* Computes R = Q1*Q2^pi */
AJ_Status ec_REDP2(const uint8_t pi[sizeof(digit256_t)], const ecpoint_t* Q1, const ecpoint_t* Q2, ecpoint_t* R, ec_t* curve)
{
    digit256_t t;
    digit_t temps[P256_TEMPS];
    AJ_Status status = AJ_OK;

    fpimport_p256(pi, t, temps, TRUE);
    status = ec_scalarmul(Q2, t, R, curve);         /* R = Q2^t*/
    ec_add(R, Q1, curve);                           /* R = Q1*Q2^t*/

    fpzero_p256(t);
    AJ_MemZeroSecure(temps, P256_TEMPS * sizeof(digit_t));

    return status;
}

/*
 * Get the two precomputed points
 * Q1 = REDP-1(ALLJOYN-ECSPEKE-1), Q2 = REDP-1(ALLJOYN-ECSPEKE-2).
 */
void ec_get_REDP_basepoints(ecpoint_t* Q1, ecpoint_t* Q2, curveid_t curveid)
{
    digit256_tc x1 = { 0x9F011EB0E927BBB7ULL, 0xDCD485337A6C1035ULL, 0x0AF630115AA734C0ULL, 0xE7F425D4C27D2BA1ULL };
    digit256_tc y1 = { 0xDD836A9DF0702B55ULL, 0x8A4AE230F7C50D50ULL, 0x4115DB75D35208F6ULL, 0x8B4ADF4EBD690598ULL };
    digit256_tc x2 = { 0x4CEC1D03497217AAULL, 0x966C293CD3634462ULL, 0xE4E36BBB81CD843DULL, 0xF9F2EF394FCB375EULL };
    digit256_tc y2 = { 0x40D6ACB2274CCFC2ULL, 0x5EAAF49A32B58CFAULL, 0x77999C42D8DDAB41ULL, 0xF5EFE6B53FF34102ULL };

    AJ_ASSERT(curveid == NISTP256r1);

    fpcopy_p256(x1, Q1->x);
    fpcopy_p256(y1, Q1->y);

    fpcopy_p256(x2, Q2->x);
    fpcopy_p256(y2, Q2->y);
}

static AJ_Status GenerateSPEKEKeyPair_inner(const uint8_t* pw, size_t pwLen, const AJ_GUID* clientGUID, const AJ_GUID* serviceGUID, ecpoint_t* publicKey, digit256_t privateKey)
{
    AJ_Status status;
    AJ_SHA256_Context* ctx = NULL;
    uint8_t digest[AJ_SHA256_DIGEST_LENGTH];
    digit_t temps[P256_TEMPS];
    ecpoint_t Q1, Q2;           /* Base points for REDP-2. */
    ecpoint_t B;                /* Base point for ECDH, derived from pw. */
    ec_t curve;

    if (clientGUID == NULL || serviceGUID == NULL || pw == NULL || pwLen == 0) {
        return AJ_ERR_NULL;
    }

    status = ec_getcurve(&curve, NISTP256r1);
    if (status != AJ_OK) {
        goto Exit;
    }

    /* Compute digest = SHA-256(pw||clientGUID||serviceGUID) */
    ctx = AJ_SHA256_Init();
    if (!ctx) {
        status = AJ_ERR_RESOURCES;
        goto Exit;
    }
    AJ_SHA256_Update(ctx, pw, pwLen);
    AJ_SHA256_Update(ctx, clientGUID->val, sizeof(AJ_GUID));
    AJ_SHA256_Update(ctx, serviceGUID->val, sizeof(AJ_GUID));
    AJ_SHA256_Final(ctx, digest);

    /* Compute basepoint B for keypair. */
    ec_get_REDP_basepoints(&Q1, &Q2, curve.curveid);
    status = ec_REDP2(digest, &Q1, &Q2, &B, &curve);
    if (status != AJ_OK) {
        goto Exit;
    }

    /* Compute private key. */
    do {
        AJ_RandBytes((uint8_t*)privateKey, sizeof(digit256_t));
    } while (!validate_256(privateKey, curve.order));

    status = ec_scalarmul(&B, privateKey, publicKey, &curve);            /* Public key publicKey = B^r */

Exit:
    fpzero_p256(B.x);
    fpzero_p256(B.y);
    AJ_MemZeroSecure(temps, P256_TEMPS * sizeof(digit_t));
    AJ_MemZeroSecure(digest, AJ_SHA256_DIGEST_LENGTH);
    ec_freecurve(&curve);
    /* The hash context was either not initialized, or securely zeroed and freed by AJ_SHA256_Final*/

    return status;
}

AJ_Status AJ_GenerateSPEKEKeyPair(const uint8_t* pw, size_t pwLen, const AJ_GUID* clientGUID, const AJ_GUID* serviceGUID, AJ_ECCPublicKey* publicKey, AJ_ECCPrivateKey* privateKey)
{
    AJ_Status status;
    ecpoint_t pub;
    digit256_t priv;
    ecc_publickey pubTemp;
    ecc_privatekey privTemp;

    status = GenerateSPEKEKeyPair_inner(pw, pwLen, clientGUID, serviceGUID, &pub, priv);
    if (status != AJ_OK) {
        return status;
    }

    /* Convert pub to ecc_publickey then AJ_ECCPublicKey */
    digit256_to_bigval(pub.x, &(pubTemp.x));
    digit256_to_bigval(pub.y, &(pubTemp.y));
    BigvalEncode(&pubTemp.x, publicKey->x, KEY_ECC_SZ);
    BigvalEncode(&pubTemp.y, publicKey->y, KEY_ECC_SZ);

    /* Convert priv to ecc_privatekey then AJ_ECCPrivateKey */
    digit256_to_bigval(priv, &privTemp);
    BigvalEncode(&privTemp, privateKey->x, KEY_ECC_SZ);

    privateKey->alg = KEY_ALG_ECSPEKE;
    privateKey->crv = KEY_CRV_NISTP256;

    AJ_MemZeroSecure(&privTemp, KEY_ECC_SZ);
    return AJ_OK;
}