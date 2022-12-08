
#ifndef W5500_USE_H
#define W5500_USE_H
#include "main.h"

void w5500_cs_select(void);
void w5500_cs_deselect(void);
void w5500_spi_writebyte(uint8_t data);
u08 w5500_spi_readbyte(void);
void w5500_spi_writeburst(u08* pBuf, u16 len);
void w5500_spi_readburst(u08* pBuf, u16 len);

void w5500_phy_init(void);
void w5500_network_info_init(void);
void w5500_network_info_show(void);
int W5500_Init(void);

#endif
