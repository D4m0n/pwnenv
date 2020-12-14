#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    FILE *fp = fopen("./testfile", "r");
    char b[100] = {0,};
    fread(&b, 8, 1, fp);
    printf("%s\n", b);
}
