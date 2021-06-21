#include <stdio.h>
#include <stdint.h>
#include <x86intrin.h>

// Reference key array
// There are 10 keys with 64 bytes each
#define KEY_COUNT 10
extern uint8_t keys[][64];

// Key selection function
void select_key();

// Flushes the given memory address from cache.
void clflush(void *ptr)
{
    __builtin_ia32_clflush(ptr);
    _mm_lfence();
}

// Gets the current time stamp counter value from the processor.
uint64_t rdtsc()
{
    _mm_lfence();
    return __rdtsc();
}

int main()
{
    /*
        TODO
		Preparation:
        1. Flush an arbitrary key from cache
        2. Measure access time to this key (e.g. by reading first key byte into a variable)
        3. Measure access time to this key again
    */
    

    // Test each key
    for(int i = 0; i < KEY_COUNT; ++i)
    {
        /*
            TODO
            For a number of rounds:
                1. Remove i-th key from cache
                2. Run Eve's key selection
                3. Measure and store time for accessing this key
            Print average of access times for this key
        */
    }
}