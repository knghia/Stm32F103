
#include "use.h"

extern void setup(void){
	int i=0;
	tft_init();
	
	tft_command(0x2C);
	for(i=0;i<1000;i++){
		tft_write(0xFF);
		tft_write(0x00);
	}
	
	tft_pixel(50,50,0xf0f0);
}
extern void loop(void){
	
}
