
#ifndef ST7735_H
#define ST7735_H
#include <string.h>
#include <inttypes.h>
#include "config.h"

typedef enum {
	scr_normal = 0,
	scr_CW     = 1,
	scr_CCW    = 2,
	scr_180    = 3
} ScrOrientation_TypeDef;

/*
	A0 = HIGH : data
	A0 = LOW : command
*/
#define scr_h						size_h
#define scr_w						size_w

#define A0_H()       		st7735_AO_high()
#define A0_L()      		st7735_AO_low()

#define RST_H()       	st7735_RST_high()
#define RST_L()      		st7735_RST_low()
		
#define CS_L()       		st7735_CS_low()
#define CS_H()      		st7735_CS_high()

#define ST7735_write(d) st7735_spi_write(d)

extern uint16_t scr_width;
extern uint16_t scr_height;

void ST7735_cmd(uint8_t cmd);
void ST7735_data(uint8_t data);

uint16_t RGB565(uint8_t R,uint8_t G,uint8_t B);

void ST7735_Init(void);
void ST7735_Orientation(ScrOrientation_TypeDef orientation);
void ST7735_AddrSet(uint16_t XS, uint16_t YS, uint16_t XE, uint16_t YE);
void ST7735_Clear(uint16_t color);
void ST7735_Pixel(uint16_t X, uint16_t Y, uint16_t color);


#endif


