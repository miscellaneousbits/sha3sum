#include <fcntl.h>
#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "sha3.h"

static void help(const char *argv0) {
    printf("To call: %s -b 256|384|512 [-k]\n", argv0);
    exit(-1);
}

static void byte_to_hex(uint8_t b, char s[23]) {
    unsigned i=1;
    s[0] = s[1] = '0';
    s[2] = '\0';
    while(b) {
        unsigned t = b & 0x0f;
        if (t < 10)
            s[i] = '0' + t;
        else
            s[i] = 'a' + t - 10;
        i--;
        b >>= 4;
    }
}

int main(int argc, char *argv[])
{
    sha3_context c;
    const uint8_t *hash;
    unsigned i;
    unsigned use_keccak = 0;
    unsigned bit_size = 0;

    opterr = 0;
    int oc;

    while ((oc = getopt(argc, argv, "hkb:")) != -1)
        switch (oc)
        {
        case 'h':
            help(argv[0]);
            exit(0);
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
            printf("Failed to set Keccak mode");
            return 2;
        }
    }

    char b[256];
    for (;;)
    {
        size_t l = fread(b, 1, sizeof(b), stdin);
        if (l == 0)
            break;
        sha3_Update(&c, b, l);
    }
    hash = sha3_Finalize(&c);

    for (i = 0; i < bit_size / 8; i++)
    {
        char s[3];
        byte_to_hex(hash[i], s);
        printf("%s", s);
    }
    printf("\n");

    return 0;
}
