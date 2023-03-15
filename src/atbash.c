#include <algorithms.h>

#include <stdio.h>

#include <algo_utils.h>

void algo_atbash(void) {
    char buf[256];

    printf("plaintext: ");
    fgets(buf, sizeof buf, stdin);

    for(char *c = buf; *c; c++) {
        if(IS_UPPERCASE(*c))
            *c = 'Z' - (*c - 'A');
        else if(IS_LOWERCASE(*c))
            *c = 'z' - (*c - 'a');
    }
    printf("ciphertext: %s", buf);
}
