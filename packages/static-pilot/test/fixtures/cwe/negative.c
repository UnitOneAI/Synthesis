#include <stdio.h>
void bounded_input(void) { char input[20]; fgets(input, sizeof(input), stdin); }

void bounded_copy(char *dest, const char *src, size_t capacity) { snprintf(dest, capacity, "%s", src); }
