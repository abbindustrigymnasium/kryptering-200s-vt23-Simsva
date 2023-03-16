#include <algorithms.h>

#include <stdio.h>
#include <string.h>

#include <algo_utils.h>

void algo_caesar(void) {
    char buf[256];
    unsigned char shift;

    printf("plaintext: ");
    fgets(buf, sizeof buf, stdin);
    buf[strcspn(buf, "\n")] = '\0';
    printf("shift: ");
    scanf("%hhu", &shift);

    for(char *c = buf; *c; c++) {
        if(IS_UPPERCASE(*c))
            *c = 'A' + (*c - 'A' + shift) % 26;
        else if(IS_LOWERCASE(*c))
            *c = 'a' + (*c - 'a' + shift) % 26;
    }
    printf("ciphertext: %s\n", buf);
}
