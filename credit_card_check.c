#include <stdio.h>
#include <stdbool.h>
#include <string.h>

static bool check_number(char *input)
{
    // Remove whitespace
    int pos = 0;
    int skippedCharsCount = 0;
    while(input[pos])
    {
        input[pos - skippedCharsCount] = input[pos];
        if(input[pos] == ' ' || input[pos] == '\n')
            ++skippedCharsCount;
        ++pos;
    }
    int inputLength = pos - skippedCharsCount;
    if(inputLength != 16)
        return false;
    
    // Calculate checksum
    bool flag = false;
    int digitLookup[] = { 0, 2, 4, 6, 8, 1, 3, 5, 7, 9 };
    int summandCounts[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    for(int i = inputLength - 1; i >= 0; --i)
    {
        int digit = input[i] - '0';
        if(flag)
            ++summandCounts[digitLookup[digit]];
        else
            ++summandCounts[digit];
        flag = !flag;
    }
    int sum = 0;
    for(int i = 0; i < 10; ++i)
        sum = (sum + i * summandCounts[i]) % 10;
    return sum == 0;
}

int main(int argc, char **argv)
{
    char input[10000];
    if(!fgets(input, sizeof(input), stdin))
        return 1;
    printf("Checking credit card number '%s'...", input);
    bool result = check_number(input);
    if(result)
        printf("valid!\n");
    else
        printf("invalid!\n");
    return 0;
}