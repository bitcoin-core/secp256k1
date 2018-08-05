/**********************************************************************
 * Copyright (c) 2013, 2014, 2015 Thomas Daede, Cory Fields           *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#define USE_BASIC_CONFIG 1

#include "basic-config.h"
#include "include/secp256k1.h"
#include "field_impl.h"
#include "scalar_impl.h"
#include "group_impl.h"
#include "ecmult_gen_impl.h"

static void default_error_callback_fn(const char* str, void* data) {
    (void)data;
    fprintf(stderr, "[libsecp256k1] internal consistency check failed: %s\n", str);
    abort();
}

static const secp256k1_callback default_error_callback = {
    default_error_callback_fn,
    NULL
};

int main(int argc, char **argv) {
    secp256k1_ecmult_gen_context ctx;
    int inner;
    int outer;
    FILE* fp;
    const char *SC_FORMAT = "    SC(%uu, %uu, %uu, %uu, %uu, %uu, %uu, %uu, %uu, %uu, %uu, %uu, %uu, %uu, %uu, %uu)";

#if USE_COMB
    const int blocks = COMB_BLOCKS;
    const int points = COMB_POINTS;
#if COMB_OFFSET
    secp256k1_ge_storage offset;
#endif
#else
    const int blocks = 64;
    const int points = 16;
#endif

    (void)argc;
    (void)argv;

    fp = fopen("src/ecmult_static_context.h","w");
    if (fp == NULL) {
        fprintf(stderr, "Could not open src/ecmult_static_context.h for writing!\n");
        return -1;
    }
    
    fprintf(fp, "#ifndef _SECP256K1_ECMULT_STATIC_CONTEXT_\n");
    fprintf(fp, "#define _SECP256K1_ECMULT_STATIC_CONTEXT_\n");
    fprintf(fp, "#include \"src/group.h\"\n");
    fprintf(fp, "#define SC SECP256K1_GE_STORAGE_CONST\n");

    secp256k1_ecmult_gen_context_init(&ctx);
    secp256k1_ecmult_gen_context_build(&ctx, &default_error_callback);

#if USE_COMB
#if COMB_OFFSET
    secp256k1_ge_to_storage(&offset, &ctx.offset);
    fprintf(fp, "static const secp256k1_ge_storage secp256k1_ecmult_gen_ctx_offset =\n");
    fprintf(fp, SC_FORMAT, SECP256K1_GE_STORAGE_CONST_GET(offset));
    fprintf(fp, ";\n");
#endif
#endif

    fprintf(fp, "static const secp256k1_ge_storage secp256k1_ecmult_gen_ctx_prec[%i][%i] = {\n",
        blocks, points);
    for(outer = 0; outer != blocks; outer++) {
        fprintf(fp,"{\n");
        for(inner = 0; inner != points; inner++) {
            fprintf(fp, SC_FORMAT, SECP256K1_GE_STORAGE_CONST_GET((*ctx.prec)[outer][inner]));
            if (inner != (points - 1)) {
                fprintf(fp,",\n");
            } else {
                fprintf(fp,"\n");
            }
        }
        if (outer != (blocks - 1)) {
            fprintf(fp,"},\n");
        } else {
            fprintf(fp,"}\n");
        }
    }
    fprintf(fp,"};\n");
    secp256k1_ecmult_gen_context_clear(&ctx);
    
    fprintf(fp, "#undef SC\n");
    fprintf(fp, "#endif\n");
    fclose(fp);
    
    return 0;
}
