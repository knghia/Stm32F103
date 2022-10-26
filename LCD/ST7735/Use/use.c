
#include "use.h"


extern void setup(void){

	ST7735_Init();
	ST7735_AddrSet(0,0,159,127);
	ST7735_Clear(0x0000);

	ST7735_PutStr5x7(0,0,"nguyen tuan anh",RGB565(255,0,0));
}
extern void loop(void){
	
}

