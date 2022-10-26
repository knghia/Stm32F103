#ifndef CONFIG_H
#define CONFIG_H

#include "main.h"

#define size_w       	128
#define size_h       	160

#define Delay_ms(t)		HAL_Delay(t)

void st7735_gpio_init(void);
void st7735_spi_init(void);
void st7735_spi_write(uint8_t data);
void st7735_CS_low(void);
void st7735_CS_high(void);
void st7735_AO_low(void);
void st7735_AO_high(void);
void st7735_RST_low(void);
void st7735_RST_high(void);

#endif
