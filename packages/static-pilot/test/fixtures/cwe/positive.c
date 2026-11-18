#include <stdio.h>
void unsafe_input(void) { char input[20]; gets(input); }

void unbounded_copy(char *dest, const char *src) { strcpy(dest, src); }
