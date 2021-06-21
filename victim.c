#include <stdint.h>
#include <string.h>

#define KEY_COUNT 10
__attribute__((aligned(64)))
uint8_t keys[KEY_COUNT][64]; // The keys are left uninitialized; we only care for the memory itself, not its values
uint8_t selected_key[64];

void select_key()
{
    memcpy(selected_key, keys[6], 64);
}