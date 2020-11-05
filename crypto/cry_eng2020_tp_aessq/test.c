#include "attack.h"
void print_vect(uint8_t *v, int n)
{
    int i;
    printf("0x%02x", v[0]);
    for (i = 0; i < n; i++)
    {
        printf(", 0x%02x", v[i]);
    }
    printf(".\n");
}

int main(int argc, char *argv[])
{
    int i, acc, n = 0;
    printf("Enter the number of times you want to try the attack :");
    scanf("%d", &n);
    puts("");
    while (i < n)
    {
        printf("Try number %d\n", i);
        if (attack() == 0)
            acc++;

        i++;
        puts("");
    }

    if (acc == n)
    {
        printf("\033[0;32m");
        printf("All attacks were successful.\n");
        printf("\033[0m");
    }

    return 0;
}
