
#include <string.h>
#include "st7735.h"
#include "st7735_text.h"
#include "font5x7.h"

void ST7735_PutChar5x7(uint16_t X, uint16_t Y, uint8_t chr, uint16_t color) {
	uint16_t i,j;
	uint8_t buffer[5];
  uint8_t CH = color >> 8;
  uint8_t CL = (uint8_t)color;

	memcpy(buffer,&Font5x7[(chr - 32) * 5],5);

	CS_L();
	ST7735_AddrSet(X,Y,X + 4,Y + 6);
	A0_H();
	for (j = 0; j < 7; j++) {
        for (i = 0; i < 5; i++) {
    		if ((buffer[i] >> j) & 0x01) {
    			ST7735_write(CH);
    			ST7735_write(CL);
    		} else {
    			ST7735_write(0x00);
    			ST7735_write(0x00);
    		}
    	}
    }
	CS_H();
}

void ST7735_PutStr5x7(uint8_t X, uint8_t Y, char *str, uint16_t color) {
    while (*str) {
        ST7735_PutChar5x7(X,Y,*str++,color);
        if (X < scr_width - 6) { X += 6; } else if (Y < scr_height - 8) { X = 0; Y += 8; } else { X = 0; Y = 0; }
    };
}
