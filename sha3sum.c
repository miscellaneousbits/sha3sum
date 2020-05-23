#include <ctype.h>
#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sha3.h"

static char atohexnibble(char* p)
{
    char c = *p;

    if ((c >= '0') && (c <= '9'))
        return c - '0';
    if ((c >= 'a') && (c <= 'f'))
        return c - 'a' + 10;
    if ((c >= 'A') && (c <= 'F'))
        return c - 'A' + 10;

    fprintf(stderr, "Invalid hex character %c\n", c);
    exit(-1);
    //return 0;
}

static char atohexbyte(char* bp)
{
    return atohexnibble(bp) << 4 | atohexnibble(bp + 1);
}

static void help(const char *argv0) {
    fprintf(stderr,
        "Usage: %s -b 256|384|512 [-k] [-x] string\n"
        " -b Digest size in bits\n"
        " -k Use KECCAK\n"
        " -x Hex string\n",
        argv0);
    exit(-1);
}

int main(int argc, char *argv[])
{
    unsigned use_keccak = 0;
    unsigned use_hex = 0;
    unsigned bit_size = 0;

    opterr = 0;
    int c;

    while ((c = getopt(argc, argv, "hdxkb:")) != -1)
        switch (c)
        {
        case 'h':
            help(argv[0]);
        case 'k':
            use_keccak = 1;
            break;
        case 'd':
            debug = 1;
            break;
        case 'x':
            use_hex = 1;
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
    char *b;
    if (optind < argc)
        b = argv[optind];
    else
    {
        fprintf(stderr, "No string to hash\n");
        help(argv[0]);
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

    sha3_context ctx;

    switch (bit_size)
    {
    case 256:
        sha3_Init256(&ctx);
        break;
    case 384:
        sha3_Init384(&ctx);
        break;
    case 512:
        sha3_Init512(&ctx);
        break;
    }

    if( use_keccak ) {
        enum SHA3_FLAGS flags2 = sha3_SetFlags(&ctx, SHA3_FLAGS_KECCAK);
        if( flags2 != SHA3_FLAGS_KECCAK )  {
            fprintf(stderr, "Failed to set Keccak mode.\n");
            exit(-1);
        }
    }

    size_t l = strlen(b);
    if (use_hex)
    {
        if (l & 1)
        {
            fprintf(stderr,
                "Hex string must have even number of characters.\n");
            exit(-1);
        }
        char h[512];
        char* bp = b;
        char* hp = h;
        for (unsigned i = 0; i < l; i += 2, bp += 2, hp++)
            *hp = atohexbyte(bp);
        sha3_Update(&ctx, h, l / 2);
    }
    else
        sha3_Update(&ctx, b, l);
    const uint8_t* hash = sha3_Finalize(&ctx);

    if (debug)
        printf("digest: ");
    for (unsigned i = 0; i < bit_size / 8; i++)
        printf("%02x", hash[i]);
    printf("\n");

    return 0;
}
