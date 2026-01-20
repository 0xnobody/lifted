#include <stdio.h>

#include "annotations.h"

/*
extern "C" int POLARIS_ANNOTATE test(int x)
{
    int temp = x % 16;

    if (temp < 10)
    {
        return x * 2;
    }
    return x * 5;
}
*/
extern "C" int POLARIS_ANNOTATE test(int x)
{
    long int decimalNumber, remainder, quotient;
    int i = 1, j, temp;
    char hexadecimalNumber[100];

    decimalNumber = x;

    quotient = decimalNumber;

    while (quotient != 0)
    {
        temp = quotient % 16;

        // To convert integer into character
        if (temp < 10)
            temp = temp + 48;
        else
            temp = temp + 55;

        hexadecimalNumber[i++] = temp;
        quotient = quotient / 16;
    }

    printf("Equivalent hexadecimal value of decimal number %d: \n", decimalNumber);
    for (j = i - 1; j > 0; j--)
        printf("%c", hexadecimalNumber[j]);

    return 0;
}
