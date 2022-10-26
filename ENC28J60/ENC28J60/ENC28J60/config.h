#ifndef CONFIG_H
#define CONFIG_H
#include "main.h"

#define delay_ms(t) HAL_Delay(t)

void enc28j60_CS_low(void);
void enc28j60_CS_high(void);
void enc28j60_RST_low(void);
void enc28j60_RST_high(void);
void enc28j60_spi_init(void);
void enc28j60_spi_write(uint8_t data);
uint8_t enc28j60_spi_read(void);

#endif
