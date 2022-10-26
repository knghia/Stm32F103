
#ifndef ST7735_GRAPHICS_H
#define ST7735_GRAPHICS_H
#include "st7735.h"

extern void ST7735_Line(int16_t X1, int16_t Y1, int16_t X2, int16_t Y2, uint16_t color);
extern void ST7735_8_point(int xc, int yc, int x, int y, uint16_t color);
extern void ST7735_Circle(int yc,int xc,int r,uint16_t color);

#endif


