
#ifndef ENC28J60_H
#define ENC28J60_H
#include "main.h"
#include <stdbool.h>

/* Opcode */
#define RCR 		0x00
#define RBM			0x3A
#define WCR			0x40
#define WBM			0x60
#define BFS			0x80
#define BFC			0xA0
#define SRC			0xE0		

typedef enum{
	BANK_NONE =-1,
	BANK_0 =0x00,
	BANK_1 =0x01,
	BANK_2 =0x02,
	BANK_3 =0x03
}BANK;

#define ERDPTL 		0x00
#define ERDPTH 		0x01

#define EWRPTL 		0x02
#define EWRPTH 		0x03

#define ETXSTL 		0x04
#define ETXSTH 		0x05

#define ETXNDL 		0x06
#define ETXNDH 		0x07

#define ERXSTL 		0x08
#define ERXSTH 		0x09

#define ERXNDL 		0x0A
#define ERXNDH 		0x0B

#define ERXRDPTL 	0x0C
#define ERXRDPTH 	0x0D

#define ERXWRPTL 	0x0E
#define ERXWRPTH 	0x0F  

/* 0x07FF - 0x0000 */
#define RX_SIZE					0x07FF // 1000
#define RX_START_ADD 		0x0000
#define RX_STOP_ADD			(RX_START_ADD+RX_SIZE)

#define TX_SIZE					0x07FF // 1000
#define TX_START_ADD 		(RX_START_ADD+RX_SIZE +1)
#define TX_STOP_ADD			(TX_START_ADD+TX_SIZE)

/* MACON1: MAC CONTROL REGISTER 1 */
#define MACON1 		0x00
#define TXPAUS		3
#define RXPAUS		2
#define PASSALL		1
#define MARXEN		0

/* MACON3: MAC CONTROL REGISTER 3 */
#define MACON3 		0x02
#define PADCFG2		7
#define PADCFG1		6
#define PADCFG0		5
#define TXCRCEN		4
#define PHDREN		3
#define HFRMEN		2
#define FRMLNEN		1
#define FULDPX		0

/* MACON4: MAC CONTROL REGISTER 4 */
#define MACON4 		0x03
#define DEFER			6
#define BPEN			5
#define NOBKOFF		4

/* MABBIPG: MAC BACK-TO-BACK INTER-PACKET GAP REGISTER */
#define MABBIPG 	0x04

/* Non-Back-to-Back Inter-Packet Gap */
#define MAIPGL 		0x06
#define MAIPGH 		0x07

/* Non-Back-to-Back Inter-Packet Gap */
#define MACLCON1 	0x08
#define MACLCON2 	0x09

/* Maximum frame length */
#define MAMXFL 		0x0A
#define MAMXFH 		0x0B

/* MAC address */
#define MAADR6		0x01
#define MAADR5		0x00
#define MAADR4		0x03
#define MAADR3		0x02
#define MAADR2		0x05
#define MAADR1		0x04

/* MICMD: MII COMMAND REGISTER */
#define MICMD			0x12
#define MIISCAN		1
#define MIIRD			0

#define MIREGADR	0x14
#define MIWRL			0x16
#define MIWRH			0x17
#define MIRDL			0x18
#define MIRDH			0x19

/* MISTAT: MII STATUS REGISTER */
#define MISTAT		0x0A
#define NVALID		2
#define SCAN			1
#define BUSY			0

/* ECOCON: CLOCK OUTPUT CONTROL REGISTER */
#define ECOCON		0x15
#define COCON2		2
#define COCON1		1
#define COCON0		0

/* PHCON1: PHY CONTROL REGISTER 1 */
#define PHCON1 		0x00
#define PRST 			15
#define PLOOPBK 	14
#define PPWRSV 		11
#define PDPXMD 		8

#define PHSTAT1 	0x01
#define PHID1 		0x02
#define PHID2 		0x03

/* PHCON2: PHY CONTROL REGISTER 2 */
#define PHCON2 		0x10
#define FRCLNK 		14
#define TXDIS 		13
#define JABBER 		10
#define HDLDIS 		8

#define PHSTAT2 	0x11
#define PHIE 			0x12
#define PHIR 			0x13 

/* PHLCON: PHY MODULE LED CONTROL REGISTER */
#define PHLCON 		0x14
#define LACFG3		11
#define LACFG2		10
#define LACFG1		9
#define LACFG0		8
#define LBCFG3		7
#define LBCFG2		6
#define LBCFG1		5
#define LBCFG0		4
#define LFRQ1			3
#define LFRQ0			2
#define STRCH			1

/* EIE: ETHERNET INTERRUPT ENABLE REGISTER */
#define EIE 			0x1B
#define INTIE			7
#define PKTIE			6
#define DMAIE			5
#define LINKIE		4
#define TXIE			3
#define TXERIE		1
#define RXERIE		0

/* EIR: ETHERNET INTERRUPT REQUEST (FLAG) REGISTER */
#define EIR 			0x1C
#define PKTIF			6
#define DMAIF			5
#define LINKIF		4
#define TXIF			3
#define TXERIF		1
#define RXERIF		0

/* ESTAT :  ETHERNET STATUS REGISTER */
#define ESTAT			0x1D
#define INT 			7
#define BUFER 		6
#define LATECOL 	4
#define RXBUSY 		2
#define TXABRT 		1
#define CLKRDY 		0

/* ECON1: ETHERNET CONTROL REGISTER 1 */
#define ECON1 		0x1F
#define TXRST			7
#define RXRST			6
#define DMAST			5
#define CSUMEN		4
#define TXRTS			3
#define RXEN			2
#define BSEL1			1
#define BSEL0			0

/* ECON2: ETHERNET CONTROL REGISTER 2 */
#define ECON2 		0x1E
#define AUTOINC		7
#define PKTDEC		6
#define PWRSV			5
#define VRPS			3

#define ERXFCON 	0x18
#define EPKTCNT 	0x19

#define DEBUG

extern uint8_t enc28j60_init(uint8_t MAC[]);
extern void enc28j80_set_bank(BANK bank);

extern uint8_t enc28j80_read_control_res(BANK bank,uint8_t address);
extern void enc28j80_write_control_res(BANK bank,uint8_t address,uint8_t data);

extern bool enc28j80_write_phy(uint8_t address,uint16_t data);
extern uint16_t enc28j80_read_phy(uint8_t address);

extern void enc28j80_write_bytes(uint16_t address,uint8_t data);

extern bool enc28j80_send_packet(uint8_t *data, uint16_t len);
extern bool enc28j80_receive_packet(uint8_t *data, uint16_t len);

extern void enc28j60_poll(void);

#endif
