#ifndef CONFIG_H
#define CONFIG_H

#include "main.h"

#define size_w       	128
#define size_h       	160

#define Delay_ms(t)		HAL_Delay(t)

void tft18_gpio_init(void);
void tft18_spi_init(void);
void tft18_spi_write(uint8_t data);
void tft18_CS_low(void);
void tft18_CS_high(void);
void tft18_AO_low(void);
void tft18_AO_high(void);
void tft18_RST_low(void);
void tft18_RST_high(void);

#endif
