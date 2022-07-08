#include <stdio.h>

float foo(int aa, int ii) {
    printf("aa:%d ii:%d", aa, ii);
    return 13.37;
}

void main() {
  printf("%p\n", foo);
  while(1) {
    foo(11, 22);
    getchar();
  }
}