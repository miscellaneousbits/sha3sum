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
    printf("To call: %s 256|384|512 [-k] (-f file_path | string).\n", argv0);
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
    unsigned bit_size;
    const char* file_path = NULL;
    int fd;
    struct stat st;
    void* p = NULL;
    unsigned i;
    unsigned use_keccak = 0;
    unsigned use_file = 0;

    opterr = 0;
    int oc;

    while ((oc = getopt(argc, argv, "hkf:")) != -1)
        switch (oc)
        {
        case 'h':
            help(argv[0]);
            exit(0);
        case 'k':
            use_keccak = 1;
            break;
        case 'f':
            use_file = 1;
            file_path = optarg;
            break;
        case '?':
            if (optopt == 'f')
                fprintf(stderr, "Option -%c requires an argument.\n", optopt);
            else
                fprintf(stderr, "Unknown option `-%c'.\n", optopt);
            help(argv[0]);
        default:
            abort();
        }

    // parse positionals

    if (optind >= argc)
    {
        fprintf(
            stderr, "Bit size must be specified as either 256, 384 or 512\n");
        help(argv[0]);
    }

    bit_size = atoi(argv[optind++]);

    switch (bit_size)
    {
    case 256:
    case 384:
    case 512:
        break;
    default:
        help(argv[0]);
    }

    if (!use_file)
    {
        if (optind < argc)
        {
            p = strdup(argv[optind]);
            st.st_size = (loff_t)strlen(p);
        }
        else
        {
            fprintf(stderr, "Either file path or string must be specified.\n");
            help(argv[0]);
        }
    }
    else
    {
        fd = open(file_path, O_RDONLY);
        if (fd == -1)
        {
            printf("Cannot open file '%s' for reading", file_path);
            return 2;
        }
        i = fstat(fd, &st);
        if (i)
        {
            close(fd);
            printf("Cannot determine the size of file '%s'", file_path);
            return 2;
        }

        p = malloc(st.st_size);
        if (p == NULL)
        {
            printf("Cannot memory-map file '%s'", file_path);
            return 2;
        }
        read(fd, p, st.st_size);
        close(fd);
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
    sha3_Update(&c, p, st.st_size);
    hash = sha3_Finalize(&c);

    free(p);

    for (i = 0; i < bit_size / 8; i++)
    {
        char s[3];
        byte_to_hex(hash[i], s);
        printf("%s", s);
    }
    printf("\n");

    return 0;
}
