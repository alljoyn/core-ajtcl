/**
 * @file  ecctest.c ECC (elliptic curve cryptography) tests
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
#include <stdio.h>
#include <ajtcl/alljoyn.h>
#include <ajtcl/aj_util.h>
#include <ajtcl/aj_status.h>
#include <ajtcl/aj_debug.h>
#include <ajtcl/aj_crypto_ecc.h>
#include <ajtcl/aj_crypto_fp.h>
#include <ajtcl/aj_crypto_ec_p256.h>
#include <ajtcl/aj_crypto.h>      /* for the RNG */
#include <ajtcl/aj_crypto_ecc.h>  /* ECDH/ECDSA APIs */
#include <ajtcl/aj_crypto_sha2.h>


/*
 * Set this variable to print out the standard EC-SPEKE basepoints used in
 * AllJoyn for ECDHE_SPEKE.
 */
static const int g_print_speke_basepoints = 0;

/* Benchmark support code */
/* Note: For a given processor, more precise timing methods often exist.
 *       Since currently the build system does not tell us the processor, we
 *       use these less precise, but more generic ways to get timing information.
 */
#define ITERS 100 /* Number of iterations for benchmarks. */
#if __linux
    #include <time.h>
#endif

typedef struct {
    uint32_t data[9];
} bigval_t;

/* Access system counter for benchmarking. */
uint64_t benchmark_time(void)
{
#if defined _WIN32
    return __rdtsc();
#elif defined __linux
    struct timespec time;
    clock_gettime(CLOCK_REALTIME, &time);
    return (int64_t)(time.tv_sec * 1e9 + time.tv_nsec);
#endif
}

/* Print benchmarking result with the corresponding unit */
void bench_print(const char* label, unsigned long long count, unsigned long long num_runs)
{
    const char* unit;
    unsigned long long result = count / num_runs;

#if __linux
    if (result >= 1e7) {
        unit = "msec";
        result = result / 1e6;
    } else if (result >= 1e4) {
        unit = "usec";
        result = result / 1e3;
    } else {
        unit = "nsec";
    }
#else
    unit = "cycles";
#endif

    AJ_Printf("  %s runs in %*s %10lld %s\n", label, (int)(50 - strlen(label)), " ", result, unit);
}


/* Field Arithmetic Tests */

int test_fpmul_p256_kat(digit256_tc a, digit256_tc b, digit256_tc c_known, int i)
{
    digit256_t c = { 0, 0, 0, 0 };
    digit_t temps[P256_TEMPS];

    memset(temps, 0x00, sizeof(temps));

    fpmul_p256(a, b, c, temps);
    if (memcmp(c, c_known, sizeof(c)) == 0) {
        return 1;
    } else {
        AJ_Printf("fpmul test %d failed -- wrong answer.\n", i);
        return 0;
    }
}

int run_fpmul_p256_kats()
{
    int passed = 0;
    int run = 0;

    // Known answer tests.  c1_known = a*b (mod p256).  The product a*b before modular reduction is included for debugging.
    digit256_tc a1 = { 17719206558549681838UL, 6431396540947310048UL, 11612935573663628158UL, 8718051496037544076UL };
    digit256_tc b1 = { 4921253721701162537UL, 17209563459544305479UL, 1017636069198536828UL, 5517976548754532891UL };
    digit256_tc c1_known = { 961789641737072625UL, 10225457115821151364UL, 4102039298977734239UL, 1404790894956925208UL };
    // a*b = [14274785008760427998UL, 6946299620016575489UL, 13709194129124787162UL, 17909878623608041999UL, 419040080746784108UL, 5344702675657996016UL, 14552306481969204026UL, 2607831686380395122]

    digit256_tc a2 = { 8844934698490770636UL, 9829389649759050548UL, 15580190479849132290UL, 17766681537739872130UL };
    digit256_tc b2 = { 14500914995729698198UL, 6422638149855794201UL, 15664328861594059002UL, 6404777437367841893UL };
    digit256_tc c2_known = { 2097716429123545365UL, 17656009607115261235UL, 9344564188714855756UL, 5082079834809801308UL };
    // a*b = [1300317245404892040UL, 6008198196536125206UL, 16022114046911353928UL, 5876577119790533637UL, 14048949065398320954UL, 15111932852584245813UL, 1471281526380311976UL, 6168657221845067557]

    digit256_tc a3 = { 15939615155660301108UL, 7143350094927966522UL, 3883951360218364098UL, 15133662551349039251UL };
    digit256_tc b3 = { 18150268098113480338UL, 11312047171767748001UL, 6186193757377372050UL, 8019375174056696995UL };
    digit256_tc c3_known = { 11452255603278212989UL, 12257383617576985661UL, 11163574383076909462UL, 1558810016341072940UL };
    // a*b = [5776732926367550376UL, 1772296329390911596UL, 9566540135247392647UL, 4895202992860378391UL, 17996356884603099097UL, 9232508218673844893UL, 5182695418892870641UL, 6579075270513827835]

    digit256_tc a4 = { 14318944385485372598UL, 883375215920048957UL, 13803891150075560442UL, 6611050328294776182UL };
    digit256_tc b4 = { 13788568089797780523UL, 14427058084629806332UL, 14551108227132870340UL, 612024294718074594UL };
    digit256_tc c4_known = { 4847932808027178217UL, 16808312094030226880UL, 378517564788830623UL, 327361809514739816UL };
    // a*b = [4169236071965493906UL, 2577223082178085076UL, 8612931833157935979UL, 17698379716881045988UL, 8647078201883724018UL, 17217140294649640218UL, 14905457703337800644UL, 219340789808369142]

    digit256_tc a5 = { 6907620683598084025UL, 10652677734757169213UL, 12111960731393070133UL, 18325545720791423845UL };
    digit256_tc b5 = { 16421853107984745044UL, 7149540827219402707UL, 7591632485150638734UL, 11078530975399126193UL };
    digit256_tc c5_known = { 813005960448587351UL, 15100031179218961217UL, 296293684846639486UL, 5443020030248087442UL };
    // a*b = [7766518664827697844UL, 1761751396603640420UL, 4677571217510298465UL, 11145029642123640723UL, 2694824567421187998UL, 4143170301981517467UL, 17398917319244501262UL, 11005743078434454794]

    digit256_tc a6 = { 10, 0, 0, 0 };
    digit256_tc b6 = { 17, 0, 0, 0 };
    digit256_tc c6_known = { 170, 0, 0, 0 };
    // a*b = 170 = c6_known.  product smaller than p256

    passed += test_fpmul_p256_kat(a1, b1, c1_known, 1);
    run++;

    passed += test_fpmul_p256_kat(a2, b2, c2_known, 2);
    run++;

    passed += test_fpmul_p256_kat(a3, b3, c3_known, 3);
    run++;

    passed += test_fpmul_p256_kat(a4, b4, c4_known, 4);
    run++;

    passed += test_fpmul_p256_kat(a5, b5, c5_known, 5);
    run++;

    passed += test_fpmul_p256_kat(a6, b6, c6_known, 6);
    run++;

    return (passed == run);

}

int test_fpadd_p256_kat(digit256_tc a, digit256_tc b, digit256_tc c_known, int i)
{
    digit256_t c;

    fpadd_p256(a, b, c);
    if (memcmp(c, c_known, sizeof(c)) == 0) {
        return 1;
    } else {
        AJ_Printf("fpadd test %d failed -- wrong answer.\n", i);
        return 0;
    }

}

int run_fpadd_p256_kats()
{
    int run = 0;
    int passed = 0;

    digit256_tc a1 = { 13389093525700345293UL, 9786536739768428856UL, 2828400845031766471UL, 14419212017040060345UL };
    digit256_tc b1 = { 14294722422393585579UL, 17460355475368744786UL, 3501978364702603477UL, 3400043727025504347UL };
    digit256_tc c1_known = { 9237071874384379256UL, 8800148141427622027UL, 6330379209734369949UL, 17819255744065564692UL };

    digit256_tc a2 = { 9046118443709457292UL, 13349558207210907587UL, 7658398902856321151UL, 3862605742198849968UL };
    digit256_tc b2 = { 13188724448030810238UL, 8350995109368408207UL, 875478512590890457UL, 16363082593212770616UL };
    digit256_tc c2_known = { 3788098818030715915UL, 3253809238574796883UL, 8533877415447211609UL, 1778944265997036263UL };

    digit256_tc a3 = { 13389093525700345293UL, 9786536739768428856UL, 2828400845031766471UL, 14419212017040060345UL };
    digit256_tc b3 = { 14294722422393585579UL, 17460355475368744786UL, 3501978364702603477UL, 3400043727025504347UL };
    digit256_tc c3_known = { 9237071874384379256UL, 8800148141427622027UL, 6330379209734369949UL, 17819255744065564692UL };

    digit256_tc a4 = { 10, 0, 0, 0 };
    digit256_tc b4 = { 7, 0, 0, 0 };
    digit256_tc c4_known = { 17, 0, 0, 0 };

    passed += test_fpadd_p256_kat(a1, b1, c1_known, 1);
    run++;

    passed += test_fpadd_p256_kat(a2, b2, c2_known, 2);
    run++;

    passed += test_fpadd_p256_kat(a3, b3, c3_known, 3);
    run++;

    passed += test_fpadd_p256_kat(a4, b4, c4_known, 4);
    run++;

    return (run == passed);
}

int test_fpsub_p256_kat(digit256_tc a, digit256_tc b, digit256_tc c_known, int i)
{
    digit256_t c;

    fpsub_p256(a, b, c);
    if (memcmp(c, c_known, sizeof(c)) == 0) {
        return 1;
    } else {
        AJ_Printf("fpsub test %d failed -- wrong answer.\n", i);
        return 0;
    }
}

int run_fpsub_p256_kats()
{
    int run = 0;
    int passed = 0;

    digit256_tc a1 = { 11700990786256262891UL, 5637983711336958193UL, 5959611888226728961UL, 11869998447973167452UL };
    digit256_tc b1 = { 4819216106114708977UL, 14863724383416041616UL, 12346602459755209691UL, 15988320929136601693UL };
    digit256_tc c1_known = { 6881774680141553913UL, 9221003405925435489UL, 12059753502181070885UL, 14328421588251150079UL };

    digit256_tc a2 = { 17719206558549681838UL, 6431396540947310048UL, 11612935573663628158UL, 8718051496037544076UL };
    digit256_tc b2 = { 4921253721701162537UL, 17209563459544305479UL, 1017636069198536828UL, 5517976548754532891UL };
    digit256_tc c2_known = { 12797952836848519301UL, 7668577155112556185UL, 10595299504465091329UL, 3200074947283011185UL };

    digit256_tc a3 = { 8844934698490770636UL, 9829389649759050548UL, 15580190479849132290UL, 17766681537739872130UL };
    digit256_tc b3 = { 14500914995729698198UL, 6422638149855794201UL, 15664328861594059002UL, 6404777437367841893UL };
    digit256_tc c3_known = { 12790763776470624054UL, 3406751499903256346UL, 18362605691964624904UL, 11361904100372030236UL };

    digit256_tc a4 = { 17, 0, 0, 0 };
    digit256_tc b4 = { 7, 0, 0, 0 };
    digit256_tc c4_known = { 10, 0, 0, 0 };

    passed += test_fpsub_p256_kat(a1, b1, c1_known, 1);
    run++;

    passed += test_fpsub_p256_kat(a2, b2, c2_known, 2);
    run++;

    passed += test_fpsub_p256_kat(a3, b3, c3_known, 3);
    run++;

    passed += test_fpsub_p256_kat(a4, b4, c4_known, 4);
    run++;

    return (run == passed);
}

int test_fpneg_p256_kat(digit256_tc a, digit256_tc b_known, int i)
{
    boolean_t status = B_FALSE;
    digit256_t b;

    memcpy(b, a, sizeof(digit256_t));

    status = fpneg_p256(b);
    if (status == B_TRUE) {
        if (memcmp(b, b_known, sizeof(b)) == 0) {
            return 1;
        } else {
            AJ_Printf("fpneg test %d failed -- wrong answer.\n", i);
            return 0;
        }
    } else {
        AJ_Printf("fpneg test %d failed -- function failed.\n", i);
        return 0;
    }
}

int run_fpneg_p256_kats()
{
    int run = 0;
    int passed = 0;

    digit256_tc a1 = { 15939615155660301108UL, 7143350094927966522UL, 3883951360218364098UL, 15133662551349039251UL };
    digit256_tc b1_known = { 2507128918049250507UL, 11303393983076552389UL, 14562792713491187517UL, 3313081518065545069UL };

    digit256_tc a2 = { 18150268098113480338UL, 11312047171767748001UL, 6186193757377372050UL, 8019375174056696995UL };
    digit256_tc b2_known = { 296475975596071277UL, 7134696906236770910UL, 12260550316332179565UL, 10427368895357887325UL };

    digit256_tc a3 = { 14318944385485372598UL, 883375215920048957UL, 13803891150075560442UL, 6611050328294776182UL };
    digit256_tc b3_known = { 4127799688224179017UL, 17563368862084469954UL, 4642852923633991173UL, 11835693741119808138UL };

    passed += test_fpneg_p256_kat(a1, b1_known, 1);
    run++;

    passed += test_fpneg_p256_kat(a2, b2_known, 2);
    run++;

    passed += test_fpneg_p256_kat(a3, b3_known, 3);
    run++;

    return (run == passed);
}

int test_fpequal_p256_kat(digit256_tc a, digit256_tc b, boolean_t are_equal_known, int i)
{
    boolean_t status = B_FALSE;

    status = fpequal_p256(a, b);
    if (status == are_equal_known) {
        return 1;
    } else {
        AJ_Printf("fpequal test %d failed -- wrong answer.\n", i);
        return 0;
    }
}

int run_fpequal_p256_kats()
{
    int run = 0;
    int passed = 0;

    digit256_tc a1 = { 15939615155660301108UL, 7143350094927966522UL, 3883951360218364098UL, 15133662551349039251UL };
    digit256_tc b1 = { 15939615155660301108UL, 7143350094927966522UL, 3883951360218364098UL, 15133662551349039251UL };
    boolean_t c1 = B_TRUE;

    digit256_tc a2 = { 15939615155660301108UL, 7143350094927966522UL, 3883951360218364098UL, 15133662551349039251UL };
    digit256_tc b2 = { 15939615155660301108UL, 7143350094927966522UL, 3883951360218364098UL, 15133662551349039252UL };
    boolean_t c2 = B_FALSE;

    digit256_tc a3 = { 0, 4294967296UL, 0, 18446744069414584321UL, }; // p + 1
    digit256_tc b3 = { 1, 0, 0, 0 };  // 1
    boolean_t c3 = B_FALSE;    // Note that fpequal requires inputs be reduced mod p, so these will not be considered equal.


    passed += test_fpequal_p256_kat(a1, b1, c1, 1);
    run++;

    passed += test_fpequal_p256_kat(a2, b2, c2, 2);
    run++;

    passed += test_fpequal_p256_kat(a3, b3, c3, 3);
    run++;

    return (passed == run);
}

int test_fpinv_p256_kat(digit256_tc a, digit256_tc b_known, int i)
{
    digit_t temps[P256_TEMPS];
    digit256_t b;

    fpinv_p256(a, b, temps);
    if (memcmp(b, b_known, sizeof(b)) == 0) {
        return 1;
    } else {
        AJ_Printf("fpinv test %d failed -- wrong answer.\n", i);
        return 0;
    }
}

int run_fpinv_p256_kats()
{
    int run = 0;
    int passed = 0;

    digit256_tc a1 = { 6907620683598084025UL, 10652677734757169213UL, 12111960731393070133UL, 18325545720791423845UL };
    digit256_tc b1 = { 14025966668329367848UL, 3595156072241463650UL, 15456073631280180716UL, 14150861440201384475UL };

    digit256_tc a2 = { 16421853107984745044UL, 7149540827219402707UL, 7591632485150638734UL, 11078530975399126193UL };
    digit256_tc b2 = { 5524053351190660477UL, 14052510857214807129UL, 17409895116542148161UL, 5055399665644516158UL };

    digit256_tc a3 = { 9046118443709457292UL, 13349558207210907587UL, 7658398902856321151UL, 3862605742198849968UL };
    digit256_tc b3 = { 17723950800386319926UL, 12284076655406226634UL, 17109263073168979093UL, 71817302339060736UL };

    passed += test_fpinv_p256_kat(a1, b1, 1);
    run++;

    passed += test_fpinv_p256_kat(a2, b2, 2);
    run++;

    passed += test_fpinv_p256_kat(a3, b3, 3);
    run++;

    return (passed == run);
}

int test_fpdiv2_p256_kat(digit256_tc a, digit256_tc b_known, int i)
{
    digit256_t b;
    digit_t temps[P256_TEMPS];

    fpdiv2_p256(a, b, temps);
    if (memcmp(b, b_known, sizeof(b)) == 0) {
        return 1;
    } else {
        AJ_Printf("fpdiv2 test %d failed -- wrong answer.\n", i);
        return 0;
    }
}

int run_fpdiv2_p256_kats()
{
    int run = 0;
    int passed = 0;

    digit256_tc a1 = { 13188724448030810238UL, 8350995109368408207UL, 875478512590890457UL, 16363082593212770616UL };
    digit256_tc b1 = { 15817734260870180927UL, 13398869591538979911UL, 437739256295445228UL, 8181541296606385308UL };

    digit256_tc a2 = { 13389093525700345293UL, 9786536739768428856UL, 2828400845031766471UL, 14419212017040060345UL };
    digit256_tc b2 = { 6694546762850172646UL, 14116640408886473884UL, 1414200422515883235UL, 16432978043227322333UL };

    digit256_tc a3 = { 14294722422393585579UL, 17460355475368744786UL, 3501978364702603477UL, 3400043727025504347UL };
    digit256_tc b3 = { 7147361211196792789UL, 17953549776686631849UL, 1750989182351301738UL, 10923393898220044334UL };

    passed += test_fpdiv2_p256_kat(a1, b1, 1);
    run++;

    passed += test_fpdiv2_p256_kat(a2, b2, 2);
    run++;

    passed += test_fpdiv2_p256_kat(a3, b3, 3);
    run++;

    return (passed == run);
}

int run_fp256_tests()
{
    int run = 0;
    int passed = 0;

    passed += run_fpmul_p256_kats();
    run++;

    passed += run_fpadd_p256_kats();
    run++;

    passed += run_fpsub_p256_kats();
    run++;

    passed += run_fpneg_p256_kats();
    run++;

    passed += run_fpequal_p256_kats();
    run++;

    passed += run_fpinv_p256_kats();
    run++;

    passed += run_fpdiv2_p256_kats();
    run++;

    if (run != passed) {
        AJ_Printf("Ran %d Fp tests, %d passed\n", run, passed);
    }

    return (run == passed);
}

/* Curve tests */

int test_curve_basics()
{
    ec_t curve = { 0 };
    ecpoint_t P = { 0 };
    ecpoint_t P2 = { 0 };
    ecpoint_jacobian_t Pj = { 0 };
    AJ_Status status;

    status = ec_getcurve(&curve, NISTP256r1);
    if (status != AJ_OK) {
        AJ_Printf("ec_getcurve failed\n");
        goto Exit;
    }
    ec_get_generator(&P, &curve);

    if (ec_is_infinity(&P, &curve)) {
        AJ_Printf("ec_is_infinity reports true for output of ec_get_generator\n");
        status = AJ_ERR_UNKNOWN;
        goto Exit;
    }

    ec_affine_tojacobian(&P, &Pj);

    if (ec_is_infinity_jacobian(&Pj, &curve)) {
        AJ_Printf("ec_is_infinity_jacobian reports true unexpectedly\n");
        status = AJ_ERR_UNKNOWN;
        goto Exit;
    }

    ec_toaffine(&Pj, &P2, &curve);

    if (!fpequal_p256(P.x, P2.x) ||
        !fpequal_p256(P.y, P2.y)) {
        AJ_Printf("unknown error with point type conversion\n");
        status = AJ_ERR_UNKNOWN;
        goto Exit;
    }

Exit:

    ec_freecurve(&curve);

    return (status == AJ_OK);
}

int ecpoint_jacobian_areequal(ecpoint_jacobian_t* A, ecpoint_jacobian_t* B, ec_t* curve)
{
    ecpoint_t a = { 0 };
    ecpoint_t b = { 0 };

    ec_toaffine(A, &a, curve);
    ec_toaffine(B, &b, curve);

    // Convert to affine & compare

    if (fpequal_p256(a.x, b.x) &&
        fpequal_p256(a.y, b.y)) {
        return 1;
    }

    return 0;
}

int ecpoint_areequal(ecpoint_t* A, ecpoint_t* B, ec_t* curve)
{
    if (fpequal_p256(A->x, B->x) &&
        fpequal_p256(A->y, B->y)) {
        return 1;
    }

    return 0;
}

int test_curve_arith_basics()
{
    ec_t curve = { 0 };
    ecpoint_t g = { 0 };
    ecpoint_jacobian_t G = { 0 };
    ecpoint_jacobian_t anotherG = { 0 };
    AJ_Status status;
    ecpoint_t R2_known = { { 11964737083406719352UL, 13873736548487404341UL, 9967090510939364035UL, 9003393950442278782UL },
                           { 11386427643415524305UL, 13438088067519447593UL, 2971701507003789531UL, 537992211385471040UL } };       // 2*G
    ecpoint_t R3_known = { { 18104864246493347180UL, 16629180030495074693UL, 14481306550553801061UL, 6830804848925149764UL },
                           { 11131122737810853938UL, 15576456008133752893UL, 3984285777615168236UL, 9742521897846374270UL } };   // 3*G
    ecpoint_jacobian_t R2 = { 0 };
    ecpoint_jacobian_t R3 = { 0 };

    status = ec_getcurve(&curve, NISTP256r1);
    if (status != AJ_OK) {
        goto Exit;
    }

    /* Test point validation */
    ec_get_generator(&g, &curve);
    if (!ecpoint_validation(&g, &curve)) {
        AJ_Printf("ec_oncurve failed\n");
        status = AJ_ERR_UNKNOWN;
        goto Exit;
    }

    /* Test ec_double_jacobian */
    ec_get_generator(&g, &curve);
    ec_affine_tojacobian(&g, &G);
    ec_affine_tojacobian(&R2_known, &R2);
    ec_double_jacobian(&G);             // G = 2*G
    if (!ecpoint_jacobian_areequal(&G, &R2, &curve)) {
        AJ_Printf("ec_double_jacobian is incorrect\n");
        status = AJ_ERR_UNKNOWN;
        goto Exit;
    }

    /* Test ec_add_jacobian with same inputs. */
    ec_get_generator(&g, &curve);
    ec_affine_tojacobian(&g, &G);      // G = G
    ec_affine_tojacobian(&g, &anotherG);      // G = G
    ec_affine_tojacobian(&R2_known, &R2);
    ec_add_jacobian(&anotherG, &G, &curve);  // G = 2*G this add should work properly when the inputs are the same.
    if (!ecpoint_jacobian_areequal(&G, &R2, &curve)) {
        AJ_Printf("ec_add_jacobian is incorrect (tested with the same input)\n");
        status = AJ_ERR_UNKNOWN;
        goto Exit;
    }

    /* Test ec_add_jacobian with different inputs. */
    ec_get_generator(&g, &curve);
    ec_affine_tojacobian(&g, &G);      // G = G
    ec_affine_tojacobian(&R2_known, &R2);
    ec_affine_tojacobian(&R3_known, &R3);
    ec_add_jacobian(&R2, &G, &curve);  // G = G + 2*G = 3*G this add works properly when the inputs are the same.
    if (!ecpoint_jacobian_areequal(&G, &R3, &curve)) {
        AJ_Printf("ec_add_jacobian is incorrect (tested with different inputs)\n");
        status = AJ_ERR_UNKNOWN;
        goto Exit;
    }

Exit:

    ec_freecurve(&curve);

    return (status == AJ_OK);
}

int test_scalarmul_kat(digit256_t k, digit256_t x, digit256_t y, int i)
{
    ec_t curve = { 0 };
    ecpoint_t P = { 0 };
    ecpoint_t Q;
    AJ_Status status;

    status = ec_getcurve(&curve, NISTP256r1);
    if (status != AJ_OK) {
        AJ_Printf("ec_getcurve failed %d\n", i);
        goto Exit;
    }
    ec_get_generator(&P, &curve);

    if (ec_is_infinity(&P, &curve)) {
        AJ_Printf("invalid generator %d\n", i);
        status = AJ_ERR_UNKNOWN;
        goto Exit;
    }

    status = ec_scalarmul(&P, k, &Q, &curve);
    if (status != AJ_OK) {
        AJ_Printf("ec_scalarmul test %d failed (the function failed)\n", i);
        goto Exit;
    }

    if (!fpequal_p256(x, Q.x) || !fpequal_p256(y, Q.y)) {
        AJ_Printf("ec_scalarmul test %d returned an incorrect result\n", i);
        status = AJ_ERR_UNKNOWN;
        goto Exit;
    }

Exit:

    ec_freecurve(&curve);

    return (status == AJ_OK);
}

int run_scalarmul_kats()
{
    int passed = 0;
    int run = 0;

    // Test vectors: (x, y) = k*G (where G is the basepoint)
    // From http://point-at-infinity.org/ecc/nisttv

    digit256_t k1 = { 17562291160714782032UL, 13611842547513532036UL, 18446744073709551615UL, 18446744069414584320UL };
    digit256_t x1 = { 17627433388654248598UL, 8575836109218198432UL, 17923454489921339634UL, 7716867327612699207UL };
    digit256_t y1 = { 3767753221892779530UL, 15290227238617653553UL, 8149286295562117609UL, 12690225778011766885UL };

    digit256_t k2 = { 8234495237290528275UL, 6084187275451764UL, 0, 0 };
    digit256_t x2 = { 13013376741987594852UL, 7335293150882016018UL, 7890206492658706934UL, 1981025739527209566UL };
    digit256_t y2 = { 5672504522216064379UL, 8327131327894173024UL, 4446911187859987120UL, 13828999463473408775UL };

    passed += test_scalarmul_kat(k1, x1, y1, 1);
    run++;

    passed += test_scalarmul_kat(k2, x2, y2, 2);
    run++;

    return (passed == run);
}

int run_scalarmul_randomized()
{
    digit256_t k1, k2;
    ecpoint_t g, Q1, Q2, Z1, Z2;
    int i = 0;
    int iters = 10;
    ec_t curve;
    AJ_Status status;

    status = ec_getcurve(&curve, NISTP256r1);
    if (status != AJ_OK) {
        goto Exit;
    }

    ec_get_generator(&g, &curve);

    for (i = 0; i < iters; i++) {
        /* Choose random k1 in [0, curve order - 1]*/
        do {
            AJ_RandBytes((uint8_t*)k1, sizeof(digit256_t));
        } while (!validate_256(k1, curve.order));

        /* Choose random k2 in [0, curve order - 1]*/
        do {
            AJ_RandBytes((uint8_t*)k2, sizeof(digit256_t));
        } while (!validate_256(k2, curve.order));

        /* Compute public keys */
        ec_scalarmul(&g, k1, &Q1, &curve);
        ec_scalarmul(&g, k2, &Q2, &curve);

        /* Compute shared secret points */
        ec_scalarmul(&Q2, k1, &Z1, &curve);
        ec_scalarmul(&Q1, k2, &Z2, &curve);

        if (!ecpoint_areequal(&Z1, &Z2, &curve)) {
            AJ_Printf("Randomized scalarmul test failed\n");
            status = AJ_ERR_UNKNOWN;
            goto Exit;
        }
    }

Exit:
    ec_freecurve(&curve);
    return (status == AJ_OK);
}

void scalarmul_benchmark()
{
    digit256_t k[ITERS];
    ecpoint_t g, Q;
    int i = 0;
    ec_t curve;
    AJ_Status status;
    uint64_t cycles_start, cycles_end, cycles_total;
    uint64_t asdf = 0;

    status = ec_getcurve(&curve, NISTP256r1);
    if (AJ_OK != status) {
        goto Exit;
    }

    ec_get_generator(&g, &curve);

    for (i = 0; i < ITERS; i++) {
        /* Choose random scalars in [0, curve order - 1]*/
        do {
            AJ_RandBytes((uint8_t*)k[i], sizeof(digit256_t));
        } while (!validate_256(k[i], curve.order));
    }

    cycles_total = 0;
    for (i = 0; i < ITERS; i++) {
        cycles_start = benchmark_time();
        ec_scalarmul(&g, k[i], &Q, &curve);
        cycles_end = benchmark_time();
        cycles_total += cycles_end - cycles_start;
        asdf += Q.x[0];
    }

    if (asdf == 42) {
        AJ_Printf("Ignore this message.\n");  /* Prevents the above from being optimized out.*/
    }

    bench_print("newecc scalarmul", cycles_total, ITERS);

Exit:
    ec_freecurve(&curve);
}

void print_digits(char* label, digit256_t a)
{
    size_t i;

    AJ_Printf("%s{", label);
    for (i = 0; i < P256_DIGITS; i++) {
        AJ_Printf("%llu, ", a[i]);
    }
    AJ_Printf("\b\b}\n");
}

int test_ecdh()
{
    AJ_ECCPublicKey ecpubkeyAlice;
    AJ_ECCPrivateKey ecprvkeyAlice;
    AJ_ECCPublicKey ecpubkeyBob;
    AJ_ECCPrivateKey ecprvkeyBob;
    AJ_ECCSecret agreedSecret1;
    AJ_ECCSecret agreedSecret2;

    AJ_Status status;

    status = AJ_GenerateECCKeyPair(&ecpubkeyAlice,
                                   &ecprvkeyAlice);
    if (AJ_OK != status) {
        AJ_Printf("AJ_GenerateECCKeyPair(...) failed with status 0x%08x for Alice's key.\n", (uint32_t)status);
        goto Exit;
    }

    status = AJ_GenerateECCKeyPair(&ecpubkeyBob,
                                   &ecprvkeyBob);
    if (AJ_OK != status) {
        AJ_Printf("AJ_GenerateECCKeyPair(...) failed with status 0x%08x for Bob's key.\n", (uint32_t)status);
        goto Exit;
    }

    status = AJ_GenerateShareSecret(&ecpubkeyAlice,
                                    &ecprvkeyBob,
                                    &agreedSecret1);
    if (AJ_OK != status) {
        AJ_Printf("AJ_GenerateShareSecret(...) failed with status 0x%08x using Alice's public and Bob's private.\n", (uint32_t)status);
        goto Exit;
    }

    status = AJ_GenerateShareSecret(&ecpubkeyBob,
                                    &ecprvkeyAlice,
                                    &agreedSecret2);
    if (AJ_OK != status) {
        AJ_Printf("AJ_GenerateShareSecret(...) failed with status 0x%08x using Bob's public and Alice's private.\n", (uint32_t)status);
        goto Exit;
    }

    if (0 != memcmp(&agreedSecret1.x, &agreedSecret2.x, KEY_ECC_SZ)) {
        AJ_Printf("agreed secrets didn't match!\n");
        status = AJ_ERR_NO_MATCH;
        goto Exit;
    }

    status = AJ_OK;

Exit:
    return (status == AJ_OK);
}

void tweak_buffer(uint8_t*pb, size_t cb)
{
    size_t i;

    for (i = 0; i < cb; i++) {
        pb[i] ^= (uint8_t)i;
    }
}

int test_ecdsa()
{
    AJ_ECCPublicKey ecpubkey;
    AJ_ECCPrivateKey ecprvkey;

    AJ_SHA256_Context* sha256ctx;

    uint8_t rgDataToHash[AJ_SHA256_DIGEST_LENGTH];
    uint8_t rgHash[AJ_SHA256_DIGEST_LENGTH];

    AJ_ECCSignature ecsig1;
    AJ_ECCSignature ecsig2;

    AJ_ECCPublicKey ecpubkey2;
    AJ_ECCPrivateKey ecprvkey2;

    AJ_Status status;

    status = AJ_GenerateECCKeyPair(&ecpubkey, &ecprvkey);
    if (AJ_OK != status) {
        AJ_Printf("AJ_GenerateECCKeyPair(...) failed with status 0x%08x.\n", (uint32_t)status);
        goto Exit;
    }

    AJ_RandBytes(rgDataToHash, sizeof(rgDataToHash));

    sha256ctx = AJ_SHA256_Init();
    AJ_SHA256_Update(sha256ctx, rgDataToHash, sizeof(rgDataToHash));
    AJ_SHA256_Final(sha256ctx, rgHash);

    status = AJ_ECDSASignDigest(rgHash, &ecprvkey, &ecsig1);
    if (AJ_OK != status) {
        AJ_Printf("AJ_ECDSASignDigest(...) failed with status 0x%08x.\n", (uint32_t)status);
        goto Exit;
    }

    status = AJ_ECDSASign(rgDataToHash, sizeof(rgDataToHash), &ecprvkey, &ecsig2);
    if (AJ_OK != status) {
        AJ_Printf("AJ_ECDSASign(...) failed with status 0x%08x.\n", (uint32_t)status);
        goto Exit;
    }

    status = AJ_ECDSAVerifyDigest(rgHash, &ecsig1, &ecpubkey);
    if (AJ_OK != status) {
        AJ_Printf("AJ_ECDSAVerifyDigest(...) failed with status 0x%08x verify digest with signature generated by sign digest.\n", (uint32_t)status);
        goto Exit;
    }

    status = AJ_ECDSAVerify(rgDataToHash, sizeof(rgDataToHash), &ecsig1, &ecpubkey);
    if (AJ_OK != status) {
        AJ_Printf("AJ_ECDSAVerify(...) failed with status 0x%08x verify data with signature generated by sign digest.\n", (uint32_t)status);
        goto Exit;
    }

    status = AJ_ECDSAVerifyDigest(rgHash, &ecsig2, &ecpubkey);
    if (AJ_OK != status) {
        AJ_Printf("AJ_ECDSAVerifyDigest(...) failed with status 0x%08x verify digest with signature generated by sign data.\n", (uint32_t)status);
        goto Exit;
    }

    status = AJ_ECDSAVerify(rgDataToHash, sizeof(rgDataToHash), &ecsig2, &ecpubkey);
    if (AJ_OK != status) {
        AJ_Printf("AJ_ECDSAVerify(...) failed with status 0x%08x verify data with signature generated by sign data.\n", (uint32_t)status);
        goto Exit;
    }

    /* Check and make sure that the the verify code correctly rejects bad signatures. */

    status = AJ_GenerateECCKeyPair(&ecpubkey2, &ecprvkey2);
    if (AJ_OK != status) {
        AJ_Printf("AJ_GenerateECCKeyPair(...) failed with status 0x%08x.\n", (uint32_t)status);
        goto Exit;
    }

    /* Verify with the wrong public key (should fail). */
    status = AJ_ECDSAVerifyDigest(rgHash, &ecsig1, &ecpubkey2);
    if (AJ_OK == status) {
        AJ_Printf("AJ_ECDSAVerifyDigest(...) failed with status 0x%08x.\n", (uint32_t)status);
        status = AJ_ERR_UNKNOWN;
        goto Exit;
    }

    tweak_buffer(rgHash, sizeof(rgHash));

    tweak_buffer((uint8_t*)&ecsig2, sizeof(AJ_ECCSignature));

    /* Verify with the wrong hash. */
    status = AJ_ECDSAVerifyDigest(rgHash, &ecsig1, &ecpubkey);
    if (AJ_OK == status) {
        AJ_Printf("AJ_ECDSAVerifyDigest(...) correctly accepted the incorrect hash.\n");
        status = AJ_ERR_UNKNOWN;
        goto Exit;
    }

    /* Verify with a corrupted signature. */
    status = AJ_ECDSAVerify(rgDataToHash, sizeof(rgDataToHash), &ecsig2, &ecpubkey);
    if (AJ_OK == status) {
        AJ_Printf("AJ_ECDSAVerify(...) correctly accepted a tweaked signature.\n");
        status = AJ_ERR_UNKNOWN;
        goto Exit;
    }

    status = AJ_OK;

Exit:
    return (status == AJ_OK);
}

/* These two internal conversion fucntions are here for unit testing. */
void digit256_to_bigval(digit256_tc src, bigval_t* dst);
boolean_t bigval_to_digit256(const bigval_t* src, digit256_t dst);

int test_conversion()
{
    bigval_t a;
    digit256_t A;
    digit256_t B;

    fpset_p256(1, A);
    fpset_p256(2, B);

    digit256_to_bigval(A, &a);
    a.data[0]++;
    bigval_to_digit256(&a, A);
    if (!fpequal_p256(A, B)) {
        AJ_Printf("Conversion test 1 failed\n");
        AJ_Printf("A: %llu %llu %llu %llu\n", A[0], A[1], A[2], A[3]);
        AJ_Printf("a: %u %u %u %u\n", a.data[0], a.data[1], a.data[2], a.data[3]);
        AJ_Printf("B: %llu %llu %llu %llu\n", B[0], B[1], B[2], B[3]);
        return 0;
    }

    /* Test with a random value */
    AJ_RandBytes((uint8_t*)A, sizeof(digit256_t));
    fpset_p256(1, B);
    fpadd_p256(A, B, B);


    digit256_to_bigval(A, &a);
    a.data[0]++;
    if (a.data[0] == 0) {
        AJ_Printf("Conversion test will fail, it's OK (problem with test code)\n"); /* happens with very low (2^(-32) probability) */
    }
    bigval_to_digit256(&a, A);

    if (!fpequal_p256(A, B)) {
        AJ_Printf("Conversion test 2 failed\n");
        AJ_Printf("A: %llu %llu %llu %llu\n", A[0], A[1], A[2], A[3]);
        AJ_Printf("a: %u %u %u %u\n", a.data[0], a.data[1], a.data[2], a.data[3]);
        AJ_Printf("B: %llu %llu %llu %llu\n", B[0], B[1], B[2], B[3]);
        return 0;
    }

    return 1;
}

int test_redp()
{
    ec_t curve = { 0 };
    ecpoint_t Q1 = { 0 };
    ecpoint_t Q2 = { 0 };
    ecpoint_t P1 = { 0 };
    ecpoint_t P2 = { 0 };
    ecpoint_t R = { 0 };
    AJ_Status status;
    unsigned char point1[18] = "ALLJOYN-ECSPEKE-1";
    unsigned char point2[18] = "ALLJOYN-ECSPEKE-2";
    unsigned char password[11] = "mypassword";

    status = ec_getcurve(&curve, NISTP256r1);
    if (status != AJ_OK) {
        goto Exit;
    }

    status = ec_REDP1(point1, sizeof(point1), &Q1, &curve);
    if (status != AJ_OK) {
        AJ_Printf("REDP-1 failed with pi1, did not return AJ_OK.");
        goto Exit;
    }

    status = ec_REDP1(point2, sizeof(point2), &Q2, &curve);
    if (status != AJ_OK) {
        AJ_Printf("REDP-1 failed with pi2, did not return AJ_OK.");
        goto Exit;
    }

    if (g_print_speke_basepoints) {
        /* Print the standard EC-SPEKE basepoints used in AllJoyn for ECDHE_SPEKE. */
        AJ_Printf("REDP-1(ALLJOYN-ECSPEKE-1)\n");
        print_digits("x = ", Q1.x);
        print_digits("y = ", Q1.y);
        AJ_Printf("REDP-1(ALLJOYN-ECSPEKE-2)\n");
        print_digits("x = ", Q2.x);
        print_digits("y = ", Q2.y);
    }

    status = ec_REDP2(password, &Q1, &Q2, &R, &curve);
    if (status != AJ_OK) {
        AJ_Printf("REDP-2 failed, did not return AJ_OK.");
        goto Exit;
    }

    /* Make sure precomputed basepoints equal those we computed just now from the two constants. */
    ec_get_REDP_basepoints(&P1, &P2, curve.curveid);
    if (!ecpoint_areequal(&P1, &Q1, &curve)) {
        status = AJ_ERR_UNKNOWN;
        AJ_Printf("REDP precomputed basepoints incorrect, point 1 does not match REDP-1(%s).", point1);
        goto Exit;
    }
    if (!ecpoint_areequal(&P2, &Q2, &curve)) {
        status = AJ_ERR_UNKNOWN;
        AJ_Printf("REDP precomputed basepoints incorrect, point 2 does not match REDP-1(%s).", point2);
        goto Exit;
    }

Exit:
    if (status == AJ_OK) {
        return 1;
    } else {
        return 0;
    }
}

// Test the ECDHE_ECSPEKE key generation and agreement functions from aj_crypto_ecc.h
int test_ecspeke()
{
    AJ_GUID clientGUID;
    AJ_GUID serviceGUID;
    AJ_Status status;
    AJ_ECCPublicKey pk1, pk2;
    AJ_ECCPrivateKey sk1, sk2;
    AJ_ECCSecret secret1, secret2;
    const uint8_t pw[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    const uint8_t notpw[8] = { 8, 7, 6, 5, 4, 3, 2, 1 };

    AJ_CreateNewGUID((uint8_t*)&clientGUID, sizeof(AJ_GUID));
    AJ_CreateNewGUID((uint8_t*)&serviceGUID, sizeof(AJ_GUID));

    // Create key pairs from matching password
    status = AJ_GenerateSPEKEKeyPair(pw, sizeof(pw), &clientGUID, &serviceGUID, &pk1, &sk1);
    if (status != AJ_OK) {
        AJ_Printf("Failed to generate key pair 1 for ECDHE_SPEKE test\n");
        return 0;
    }
    status = AJ_GenerateSPEKEKeyPair(pw, sizeof(pw), &clientGUID, &serviceGUID, &pk2, &sk2);
    if (status != AJ_OK) {
        AJ_Printf("Failed to generate key pair 2 for ECDHE_SPEKE test\n");
        return 0;
    }

    // Do key agreement operation
    status = AJ_GenerateShareSecret(&pk2, &sk1, &secret1);
    if (status != AJ_OK) {
        AJ_Printf("Failed to generate shared secret 1 for ECDHE_SPEKE test\n");
        return 0;
    }
    status = AJ_GenerateShareSecret(&pk1, &sk2, &secret2);
    if (status != AJ_OK) {
        AJ_Printf("Failed to generate shared secret 2 for ECDHE_SPEKE test\n");
        return 0;
    }

    // Shared secrets should be equal
    if (memcmp(secret1.x, secret2.x, KEY_ECC_SZ) != 0) {
        AJ_Printf("Shared secrets for ECHDE_SPEKE test do not match\n");
        return 0;
    }

    // Re-create keypair 2 with a different password
    status = AJ_GenerateSPEKEKeyPair(notpw, sizeof(notpw), &clientGUID, &serviceGUID, &pk2, &sk2);
    if (status != AJ_OK) {
        AJ_Printf("Failed to re-generate key pair 2 for ECDHE_SPEKE test\n");
        return 0;
    }

    // Re-do key agreement operation
    status = AJ_GenerateShareSecret(&pk2, &sk1, &secret1);
    if (status != AJ_OK) {
        AJ_Printf("Failed to generate shared secret 1 for ECDHE_SPEKE test\n");
        return 0;
    }
    status = AJ_GenerateShareSecret(&pk1, &sk2, &secret2);
    if (status != AJ_OK) {
        AJ_Printf("Failed to generate shared secret 2 for ECDHE_SPEKE test\n");
        return 0;
    }

    // Shared secrets should no longer be equal
    if (memcmp(secret1.x, secret2.x, KEY_ECC_SZ) == 0) {
        AJ_Printf("Shared secrets for ECHDE_SPEKE test match when they shouldn't\n");
        return 0;
    }

    return 1;
}

int AJ_Main()
{
    int tests_ran = 0;
    int passed = 0;

    AJ_Printf("Running tests...\n");

    passed += run_fp256_tests();
    tests_ran++;

    passed += test_curve_basics();
    tests_ran++;

    passed += test_curve_arith_basics();
    tests_ran++;

    passed += run_scalarmul_kats();
    tests_ran++;

    passed += run_scalarmul_randomized();
    tests_ran++;

    passed += test_ecdh();
    tests_ran++;

    passed += test_ecdsa();
    tests_ran++;

    passed += test_conversion();
    tests_ran++;

    passed += test_redp();
    tests_ran++;

    passed += test_ecspeke();
    tests_ran++;

    AJ_Printf("  Ran %d tests, %d passed.\n", tests_ran, passed);

    AJ_Printf("Running benchmarks...\n");
    scalarmul_benchmark();

    return 0;
}


#ifdef AJ_MAIN
int main()
{
    return AJ_Main();
}
#endif
