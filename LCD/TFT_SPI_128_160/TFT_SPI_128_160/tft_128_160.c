
#include "tft_128_160.h"

uint16_t scr_width;
uint16_t scr_height;

void tft18_cmd(uint8_t cmd) {
	A0_L();
	tft18_write(cmd);
}

void tft18_data(uint8_t data) {
	A0_H();
	tft18_write(data);
}

uint16_t RGB565(uint8_t R,uint8_t G,uint8_t B) {
	return ((R >> 3) << 11) | ((G >> 2) << 5) | (B >> 3);
}

#define ST7735_MADCTL_MY  0x80
#define ST7735_MADCTL_MX  0x40
#define ST7735_MADCTL_MV  0x20
#define ST7735_MADCTL_ML  0x10
#define ST7735_MADCTL_RGB 0x00
#define ST7735_MADCTL_BGR 0x08
#define ST7735_MADCTL_MH  0x04

#define ST7735_NOP     0x00
#define ST7735_SWRESET 0x01
#define ST7735_RDDID   0x04
#define ST7735_RDDST   0x09

#define ST7735_SLPIN   0x10
#define ST7735_SLPOUT  0x11
#define ST7735_PTLON   0x12
#define ST7735_NORON   0x13

#define ST7735_INVOFF  0x20
#define ST7735_INVON   0x21
#define ST7735_DISPOFF 0x28
#define ST7735_DISPON  0x29
#define ST7735_CASET   0x2A
#define ST7735_RASET   0x2B
#define ST7735_RAMWR   0x2C
#define ST7735_RAMRD   0x2E

#define ST7735_PTLAR   0x30
#define ST7735_COLMOD  0x3A
#define ST7735_MADCTL  0x36

#define ST7735_FRMCTR1 0xB1
#define ST7735_FRMCTR2 0xB2
#define ST7735_FRMCTR3 0xB3
#define ST7735_INVCTR  0xB4
#define ST7735_DISSET5 0xB6

#define ST7735_PWCTR1  0xC0
#define ST7735_PWCTR2  0xC1
#define ST7735_PWCTR3  0xC2
#define ST7735_PWCTR4  0xC3
#define ST7735_PWCTR5  0xC4
#define ST7735_VMCTR1  0xC5

#define ST7735_RDID1   0xDA
#define ST7735_RDID2   0xDB
#define ST7735_RDID3   0xDC
#define ST7735_RDID4   0xDD

#define ST7735_PWCTR6  0xFC

#define ST7735_GMCTRP1 0xE0
#define ST7735_GMCTRN1 0xE1

void tft18_Init(void) {
	tft18_spi_init();
	tft18_gpio_init();

	// Reset display
	CS_H();
	RST_H();
	Delay_ms(5);
	RST_L();
	Delay_ms(5);
	RST_H();
	CS_H();
	Delay_ms(5);
	CS_L();

	tft18_cmd(ST7735_SLPOUT); 		// Sleep out & booster on
	Delay_ms(120); 								// Datasheet says what display wakes about 120ms (may be much faster actually)
	
/*
	B1H : FRMCTR1 - Frame Rate Control (In normal mode/ Full colors)
	Frame rate=fosc/((RTNA + 20) x (LINE + FPA + BPA))
	focs = 333kHz
*/
	tft18_cmd(ST7735_FRMCTR1);   	// In normal mode (full colors):
	A0_H();
	tft18_write(0x05); 	// RTNA set 1-line period: RTNA2, RTNA0
	tft18_write(0x3c); 	// Front porch: FPA5,FPA4,FPA3,FPA2
	tft18_write(0x3c); 	// Back porch: BPA5,BPA4,BPA3,BPA2

// Frame rate=fosc/((RTNA + 20) x (LINE + FPA + BPA))

	tft18_cmd(0xb2);   	// In idle mode (8-colors):
	A0_H();
	tft18_write(0x05); 	// RTNB set 1-line period: RTNAB, RTNB0
	tft18_write(0x3c); 	// Front porch: FPB5,FPB4,FPB3,FPB2
	tft18_write(0x3c); 	// Back porch: BPB5,BPB4,BPB3,BPB2

	tft18_cmd(0xb3);   	// In partial mode + full colors:
	A0_H();
	tft18_write(0x05); 	// RTNC set 1-line period: RTNC2, RTNC0
	tft18_write(0x3c); 	// Front porch: FPC5,FPC4,FPC3,FPC2
	tft18_write(0x3c); 	// Back porch: BPC5,BPC4,BPC3,BPC2
	tft18_write(0x05); 	// RTND set 1-line period: RTND2, RTND0
	tft18_write(0x3c); 	// Front porch: FPD5,FPD4,FPD3,FPD2
	tft18_write(0x3c); 	// Back porch: BPD5,BPD4,BPD3,BPD2

	tft18_cmd(0xB4);   	// Display dot inversion control:
	tft18_data(0x03);  	// NLB,NLC

	tft18_cmd(0x3a);   	// Interface pixel format
	tft18_data(0x05);  	// 16-bit/pixel RGB 5-6-5 (65k colors)
	tft18_cmd(0x20);   	// Display inversion off

	tft18_cmd(0x13);   	// Partial mode off

	tft18_cmd(0x26);   	// Gamma curve set:
	tft18_data(0x01);  	// Gamma curve 1 (G2.2) or (G1.0)
	tft18_cmd(0x29);   	// Display on

	CS_H();
}
