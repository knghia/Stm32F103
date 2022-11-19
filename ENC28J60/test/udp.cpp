#include <iostream>
using namespace std;
#include <stdio.h>
#include <inttypes.h>
#define u08 uint8_t
#define u16 uint16_t
#define u32 uint32_t

// u08 a[] = {
//     0xc0, 0xa8, 0x89, 0x0a,
//     0xc0, 0xa8, 0x89, 0x64,
//     0x13, 0x8a, 0x13, 0x8c, 0x00, 0x0a, 0x93, 0xdb, 0x31, 0x31};

u08 a[] = {
    0xc0, 0xa8, 0x00, 0x1F,
    0xc0, 0xa8, 0x00, 0x1E,
    0x00, 0x11, 
    0x00, 0x0A,
    0x00, 0x14,
    0x00, 0x0A,
    0x00, 0x0A,
    0x48, 0x69
};

extern uint16_t swap16(uint16_t data){
	uint8_t h = (data>>8);
	uint8_t l = data%256;
	return ((l<<8) + h);
}

extern u16 icmp_ip_checksum(u08 *ip_data, u16 len){
	u32 cs= 0;
	while(len>1){
		cs += (u16) (((u32)*ip_data<<8)|*(ip_data+1));
		ip_data+=2;
		len-=2;
	}
    if(len){
        cs+=((u32)*ip_data)<<8;
    }
	while (cs>>16){
		cs=(u16)cs+(cs>>16);
	}
	cs=~cs;
	return swap16(cs);
}

int main(void){
    printf("data \r\n");
    u16 cs = icmp_ip_checksum(a,20);
    printf("cs %04x \r\n",cs);
    return 1;
}