
#ifndef TFT_128_160_H
#define TFT_128_160_H

#ifdef __cplusplus
extern "C"{
#endif

#include <inttypes.h>
#include "config.h"
#include "font5x7.h"
#include "garmin-digits.h"

/*
	A0 = HIGH : data
	A0 = LOW : command
*/
#define scr_h						size_h
#define scr_w						size_w

#define A0_H()       		tft18_AO_high()
#define A0_L()      		tft18_AO_low()

#define RST_H()       	tft18_RST_high()
#define RST_L()      		tft18_RST_low()
		
#define CS_L()       		tft18_CS_low()
#define CS_H()      		tft18_CS_high()

#define tft18_write(d) 	tft18_spi_write(d)

extern void tft_reset(void);
extern void tft_command(uint8_t cmd);
extern void tft_data(uint8_t data);
extern void tft_write(uint8_t data);

extern void tft_init(void);

void tff_current(uint16_t XS, uint16_t YS, uint16_t XE, uint16_t YE);
void tft_pixel(uint16_t X, uint16_t Y, uint16_t color);

#ifdef __cplusplus
}
#endif

#endif
