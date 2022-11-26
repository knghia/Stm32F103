#ifndef SPI_H
#define SPI_H
#include "main.h"

void ENC28J60_CSL(void);
void ENC28J60_CSH(void);

void ENC28J60_RST_L(void);
void ENC28J60_RST_H(void);
u08 SPI1_ReadWrite(uint8_t data);

#endif
