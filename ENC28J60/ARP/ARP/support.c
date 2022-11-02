
#include "support.h"

uint8_t copy_array(uint8_t* dest, uint8_t* source, uint8_t len){
    for(uint8_t i=0; i<len; i++){
        dest[i] = source[i];
    }
    return len;
}

bool compare_array(uint8_t* a,const uint8_t* b, uint8_t len){
	uint8_t i = 0;
	for (i=0;i<len;i++){
		if(a[i] != b[i]){
			return false;
		}
	}
	return true;
}

uint16_t swap16(uint16_t data){
	uint8_t h = (data>>8);
	uint8_t l = data%256;
	return ((l<<8) + h);
}