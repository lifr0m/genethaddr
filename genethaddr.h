#ifndef GENETHADDR_H
#define GENETHADDR_H

#include <sys/types.h>

typedef struct {
    uint8_t *key;
    uint8_t *address;
} GeneratedEthKey;

GeneratedEthKey generate_private_key(
    uint8_t (*address_checker)(const uint8_t *address),
    size_t nthreads
);

#endif
