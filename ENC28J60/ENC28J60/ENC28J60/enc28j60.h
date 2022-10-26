
#ifndef ENC28J60_H
#define ENC28J60_H
#include "main.h"


/* ECON 1: Ethernet controler register 1 */
#define ECON1 	0x1F
#define TXRST		7
#define RXRST		6
#define DMAST		5
#define CSUMEN	4
#define TXRTS		3
#define RXEN		2
#define BSEL1		1
#define BSEL0		0

extern void enc28j60_init(void);
extern void enc28j60_write_cmd(uint8_t address, uint8_t data);  
extern uint8_t enc28j60_read_cmd(uint16_t address);  
extern void enc28j60_poll(void);

#endif
