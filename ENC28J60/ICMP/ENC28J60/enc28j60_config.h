#ifndef ENC28J60_CONFIG_H
#define ENC28J60_CONFIG_H
#include "main.h"

#define delay_ms(t) HAL_Delay(t)

void enc28j60_CS_low(void);
void enc28j60_CS_high(void);
void enc28j60_RST_low(void);
void enc28j60_RST_high(void);
void enc28j60_spi_init(void);
void enc28j60_spi_write(uint8_t data);
uint8_t enc28j60_spi_read(void);

extern void enc28j60_write_cmd(uint8_t opcode, uint8_t address, uint8_t data);
extern uint8_t enc28j60_read_cmd(uint8_t opcode, uint8_t address);

#endif
