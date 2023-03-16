#include <algorithms.h>

#include <stdio.h>
#include <string.h>

#include <algo_utils.h>

void algo_vigenere(void) {
    char buf[256], key[256];

    printf("plaintext: ");
    fgets(buf, sizeof buf, stdin);
    buf[strcspn(buf, "\n")] = '\0';
    printf("key: ");
    fgets(key, sizeof key, stdin);
    key[strcspn(key, "\n")] = '\0';

    for(char *c = buf, *k = key; *c; c++) {
        unsigned char shift;
        if(*k == '\0') k = key;
        shift = IS_UPPERCASE(*k)
            ? *k - 'A'
            : IS_LOWERCASE(*k)
            ? *k - 'a'
            : 0;

        if(IS_UPPERCASE(*c))
            *c = 'A' + (*c - 'A' + shift) % 26, k++;
        else if(IS_LOWERCASE(*c))
            *c = 'a' + (*c - 'a' + shift) % 26, k++;
    }
    printf("ciphertext: %s\n", buf);
}
