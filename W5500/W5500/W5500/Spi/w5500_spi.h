#ifndef W5500_SPI_H
#define W5500_SPI_H
#include "main.h"

void W5500_CSL(void);
void W5500_CSH(void);

void W5500_RST_L(void);
void W5500_RST_H(void);

void W5500_SPI_Write(uint8_t data);
u08 W5500_SPI_Read(void);

void W5500_SPI_Write_Buff(u08* pBuf, u08 len);
void W5500_SPI_Read_Buff(u08* pBuf, u08 len);

#endif
