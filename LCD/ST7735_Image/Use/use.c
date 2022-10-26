
#include "use.h"
#include "image.h"

//void ST7735_Draw(const uint8_t* data,uint16_t len) {
//	uint16_t i = 0;
//	CS_L();
//	A0_H();
//	for(i=0;i<len-1;i+=2){
//		ST7735_write((uint8_t)data[i+1]);
//		ST7735_write((uint8_t)data[i]);
//	}
//	CS_H();
//}


void ST7735_Draw(const uint8_t* data,uint16_t len) {
	uint16_t i = 0;
	CS_L();
	A0_H();
	for(i=0;i<len-2;i+=3){
		ST7735_write((uint8_t)data[i]);
		ST7735_write((uint8_t)data[i+1]);
		ST7735_write((uint8_t)data[i+2]);
	}
	CS_H();
}
extern void setup(void){

	ST7735_Init();
	ST7735_AddrSet(0,0,160,128);
	ST7735_Clear(0x0000);
	// ST7735_Draw((uint8_t*)gImage_starry_night,40960);
	
	ST7735_Draw((uint8_t*)test_img_128x160,61440);
}

extern void loop(void){
	
}

