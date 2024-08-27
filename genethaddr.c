#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <secp256k1.h>
#include <sodium.h>
#include "keccak256.h"
#include "genethaddr.h"

#define SECKEY_GEN_SUCCESS (void *) 0
#define SECKEY_GEN_FAILURE (void *) 1

pthread_mutex_t mutex;

typedef enum {
    SECKEY_GEN_STATUS_GENERATING,
    SECKEY_GEN_STATUS_COMPLETED
} SecKeyGenStatus;

secp256k1_context *create_secp256k1_context() {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    if (!ctx) {
        printf("secp256k1 context creation error\n");
        return NULL;
    }
    uint8_t seed[32];
    randombytes_buf(seed, 32);
    if (!secp256k1_context_randomize(ctx, seed)) {
        printf("secpk256k1 context randomizing error\n");
        return NULL;
    }
    return ctx;
}

void keccak256(uint8_t *result, const uint8_t *data, size_t size) {
    SHA3_CTX ctx;
    keccak_init(&ctx);
    keccak_update(&ctx, data, size);
    keccak_final(&ctx, result);
}

typedef struct {
    SecKeyGenStatus seckey_gen_status;
    uint8_t (*address_checker)(const uint8_t *address);
    uint8_t *seckey;
    uint8_t *address;
} GenSecKeyArg;

void *gen_seckey(void *arg) {
    GenSecKeyArg *gen_seckey_arg = arg;

    secp256k1_context *ctx = create_secp256k1_context();
    if (!ctx)
        return SECKEY_GEN_FAILURE;

    uint8_t seckey[32];
    secp256k1_pubkey pubkey_struct;
    size_t pubkey_out_size = 65;
    uint8_t pubkey_out[65];
    uint8_t pubkey_keccak[32];

    while (gen_seckey_arg->seckey_gen_status == SECKEY_GEN_STATUS_GENERATING) {
        randombytes_buf(seckey, 32);
        if (!secp256k1_ec_pubkey_create(ctx, &pubkey_struct, seckey)) {
            printf("secp256k1 pubkey creation error\n");
            return SECKEY_GEN_FAILURE;
        }
        if (!secp256k1_ec_pubkey_serialize(
                ctx, pubkey_out, &pubkey_out_size, &pubkey_struct,
                SECP256K1_EC_UNCOMPRESSED)) {
            printf("secp256k1 pubkey serialization error\n");
            return SECKEY_GEN_FAILURE;
        }
        keccak256(pubkey_keccak, pubkey_out + 1, 64);
        if (gen_seckey_arg->address_checker(pubkey_keccak + 12)) {
            if (pthread_mutex_lock(&mutex)) {
                printf("Mutex lock error\n");
                return SECKEY_GEN_FAILURE;
            }
            if (gen_seckey_arg->seckey_gen_status == SECKEY_GEN_STATUS_COMPLETED)
                break;
            gen_seckey_arg->seckey_gen_status = SECKEY_GEN_STATUS_COMPLETED;
            gen_seckey_arg->seckey = malloc(32);
            if (!gen_seckey_arg->seckey) {
                printf("SecKey allocation error\n");
                return SECKEY_GEN_FAILURE;
            }
            memcpy(gen_seckey_arg->seckey, seckey, 32);
            gen_seckey_arg->address = malloc(20);
            if (!gen_seckey_arg->address) {
                printf("Address allocation error\n");
                return SECKEY_GEN_FAILURE;
            }
            memcpy(gen_seckey_arg->address, pubkey_keccak + 12, 20);
            if (pthread_mutex_unlock(&mutex)) {
                printf("Mutex unlock error\n");
                return SECKEY_GEN_FAILURE;
            }
        }
    }

    secp256k1_context_destroy(ctx);
    return SECKEY_GEN_SUCCESS;
}

GeneratedEthKey generate_private_key(
    uint8_t (*address_checker)(const uint8_t *address),
    size_t nthreads
) {
    GeneratedEthKey eth_key = {0};
    if (sodium_init() < 0) {
        printf("Sodium init error\n");
        return eth_key;
    }

    GenSecKeyArg arg = {
        .seckey_gen_status = SECKEY_GEN_STATUS_GENERATING,
        .address_checker = address_checker
    };
    if (pthread_mutex_init(&mutex, NULL)) {
        printf("Mutex init error\n");
        return eth_key;
    }
    pthread_t *threads = malloc(nthreads * sizeof(pthread_t));
    if (!threads) {
        printf("Threads allocation error\n");
        return eth_key;
    }
    for (size_t i = 0; i < nthreads; ++i)
        if (pthread_create(&threads[i], NULL, gen_seckey, &arg)) {
            printf("Thread creation error\n");
            return eth_key;
        }
    for (size_t i = 0; i < nthreads; ++i)
        if (pthread_join(threads[i], NULL)) {
            printf("Thread joining error\n");
            return eth_key;
        }
    free(threads);
    if (pthread_mutex_destroy(&mutex)) {
        printf("Mutex destroying error\n");
        return eth_key;
    }

    eth_key.key = arg.seckey;
    eth_key.address = arg.address;
    return eth_key;
}
