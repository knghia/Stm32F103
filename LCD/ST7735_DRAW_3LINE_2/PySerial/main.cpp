#include <iostream>
#include <stdio.h>
using namespace std;

uint8_t cvt_to_hex(uint8_t d_ascii) {
  if (('0' <= d_ascii) && (d_ascii <= '9'))
    return (d_ascii - 48);
  else if (('a' <= d_ascii) && (d_ascii <= 'f'))
    return (d_ascii - 87);
  else if (('A' <= d_ascii) && (d_ascii <= 'F'))
    return (d_ascii - 55);
  return 0x00;
}

int main(){
    printf("ascii %d ",cvt_to_hex('A'));

    char buffer[50];
    int a = 10, b = 20, c;
    int d = 0;
    c = a + b;
    d = sprintf(buffer, "Sum of %d and %d is %d", a, b, c);
    printf("%s %d", buffer, d);

    return 0;
}
