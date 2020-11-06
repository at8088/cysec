#include "attack.h"

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
