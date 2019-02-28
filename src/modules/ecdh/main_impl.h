/**********************************************************************
 * Copyright (c) 2015 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODULE_ECDH_MAIN_H
#define SECP256K1_MODULE_ECDH_MAIN_H

#include "secp256k1_ecdh.h"
#include "ecmult_const_impl.h"

int secp256k1_ecdh(const secp256k1_context* ctx, unsigned char *result, const secp256k1_pubkey *point, const unsigned char *scalar, unsigned int flags) {
    int ret = 0;
    int overflow = 0;
    secp256k1_gej res;
    secp256k1_ge pt;
    secp256k1_scalar s;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(result != NULL);
    ARG_CHECK(point != NULL);
    ARG_CHECK(scalar != NULL);
    ARG_CHECK((flags & SECP256K1_FLAGS_TYPE_MASK) == SECP256K1_FLAGS_TYPE_COMPRESSION);

    secp256k1_pubkey_load(ctx, &pt, point);
    secp256k1_scalar_set_b32(&s, scalar, &overflow);
    if (overflow || secp256k1_scalar_is_zero(&s)) {
        ret = 0;
    } else {
        unsigned char x[32];
        unsigned char y[32];
        int compressed = flags & SECP256K1_FLAGS_BIT_COMPRESSION;

        secp256k1_ecmult_const(&res, &pt, &s, 256);
        secp256k1_ge_set_gej(&pt, &res);
        secp256k1_fe_normalize(&pt.x);
        secp256k1_fe_normalize(&pt.y);

        secp256k1_fe_get_b32(&result[1], &pt.x);
        if (compressed) {
            result[0] = secp256k1_fe_is_odd(&pt.y) ? SECP256K1_TAG_PUBKEY_ODD : SECP256K1_TAG_PUBKEY_EVEN;
        } else {
            result[0] = SECP256K1_TAG_PUBKEY_UNCOMPRESSED;
            secp256k1_fe_get_b32(&result[33], &pt.y);
        }

        ret = 1;
    }

    secp256k1_scalar_clear(&s);
    return ret;
}

#endif /* SECP256K1_MODULE_ECDH_MAIN_H */
