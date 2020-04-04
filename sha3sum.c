#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sha3.h"

static void help(const char *argv0) {
    fprintf(stderr, "Usage: %s -b 256|384|512 [-k]\n", argv0);
    exit(-1);
}

int main(int argc, char *argv[])
{
    unsigned use_keccak = 0;
    unsigned bit_size = 0;

    opterr = 0;
    int oc;

    while ((oc = getopt(argc, argv, "hkb:")) != -1)
        switch (oc)
        {
        case 'h':
            help(argv[0]);
        case 'k':
            use_keccak = 1;
            break;
        case 'b':
            bit_size = atoi(optarg);
            break;
        case '?':
            if (optopt == 'b')
                fprintf(stderr, "Option -%c requires an argument.\n", optopt);
            else
                fprintf(stderr, "Unknown option `-%c'.\n", optopt);
            help(argv[0]);
        default:
            abort();
        }

    switch (bit_size)
    {
    case 256:
    case 384:
    case 512:
        break;
    default:
        fprintf(stderr, "Bit size must be 256, 384 or 512.\n");
        help(argv[0]);
    }

    sha3_context c;

    switch (bit_size)
    {
    case 256:
        sha3_Init256(&c);
        break;
    case 384:
        sha3_Init384(&c);
        break;
    case 512:
        sha3_Init512(&c);
        break;
    }

    if( use_keccak ) {
        enum SHA3_FLAGS flags2 = sha3_SetFlags(&c, SHA3_FLAGS_KECCAK);
        if( flags2 != SHA3_FLAGS_KECCAK )  {
            fprintf(stderr, "Failed to set Keccak mode.\n");
            exit(-1);
        }
    }

    char b[1024];
    size_t l = fread(b, 1, sizeof(b), stdin);
    while (l)
    {
        sha3_Update(&c, b, l);
        l = fread(b, 1, sizeof(b), stdin);
    }
    const uint8_t* hash = sha3_Finalize(&c);

    unsigned i;
    for (i = 0; i < bit_size / 8; i++)
        printf("%02x", hash[i]);
    printf("\n");

    return 0;
}
