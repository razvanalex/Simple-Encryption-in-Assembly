extern int strfind(char *src, char *dest);

#include <stdio.h>

int main() {
    char a[100] = "1234567890ABCDEFG";
    char b[100] = "a";
    int r = strfind(a, b);

    printf("%d\n", r);
    if (r == 1) {
        printf("OK");
    }
    else {
        printf("Not Ok");
    }
    
    return 0;
}