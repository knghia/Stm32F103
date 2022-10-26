#include <stdio.h>
#include "config.h"
#include "binary.h"
#include "enc28j60.h"
#include "crc32.h"

volatile BANK enc28j60_bank = BANK_NONE;
extern void enc28j80_set_bank(BANK bank){
	if(bank != enc28j60_bank){
		enc28j60_bank = bank;
		enc28j60_write_cmd(BFC, ECON1, B11);
		enc28j60_write_cmd(BFS, ECON1, bank);
	}
}

extern uint8_t enc28j80_read_control_res(BANK bank,uint8_t address){
	uint8_t data;
	enc28j80_set_bank(bank);
	data = enc28j60_read_cmd(RCR,address);
	return data;
}

extern void enc28j80_write_control_res(BANK bank,uint8_t address,uint8_t data){
	enc28j80_set_bank(bank);
	enc28j60_write_cmd(WCR,address,data);
}

extern uint8_t enc28j60_init(uint8_t MAC[]){
	
#ifdef DEBUG
	printf("Start init ...\r\n");
#endif
	uint8_t i = 0;
	uint8_t status = 0;
	int16_t timeout = 1000;
	uint8_t MY_MAC[6]= {0};
	enc28j60_RST_low();
	delay_ms(1);
	enc28j60_RST_high();
	delay_ms(1000);
	enc28j60_spi_init();
	
	/* reset software */
	enc28j60_write_cmd(SRC, 0x1F,0);
	delay_ms(2);
	/* check  */
	do{
		status = enc28j60_read_cmd(RCR, ESTAT);
		if ((status&(1<<CLKRDY)) != 0x00){
			break;
		}
	}while(timeout--);

#ifdef DEBUG
	if (timeout == -1){
		printf("Time out \r\n");
		return false;
	}
	else{
		printf("Finish 0x%02x\r\n",status);
	}
#endif

	/* Set address rx, tx buff */
	enc28j80_write_control_res(BANK_0, ETXSTL, TX_START_ADD%256);
	enc28j80_write_control_res(BANK_0, ETXSTH, TX_START_ADD/256);
	
	enc28j80_write_control_res(BANK_0, ETXNDL, TX_STOP_ADD%256);
	enc28j80_write_control_res(BANK_0, ETXNDH, TX_STOP_ADD/256);
	
	enc28j80_write_control_res(BANK_0, ERXSTL, RX_START_ADD%256);
	enc28j80_write_control_res(BANK_0, ERXSTH, RX_START_ADD/256);
	
	enc28j80_write_control_res(BANK_0, ERXNDL, RX_STOP_ADD%256);
	enc28j80_write_control_res(BANK_0, ERXNDH, RX_STOP_ADD/256);
	
	/* Reset address rx, tx buff to 0*/
	enc28j80_write_control_res(BANK_0, EWRPTL, TX_START_ADD%256);
	enc28j80_write_control_res(BANK_0, EWRPTH, TX_START_ADD>>8);
	
	enc28j80_write_control_res(BANK_0, ERDPTL, RX_START_ADD%256);
	enc28j80_write_control_res(BANK_0, ERDPTH, RX_START_ADD/256);

#ifdef DEBUG
	uint8_t h,l= 0 ;
	
	printf("Tx space 0x%04x:0x%04x\r\n",TX_START_ADD, TX_STOP_ADD);
	printf("Rx space 0x%04x:0x%04x\r\n",RX_START_ADD, RX_STOP_ADD);
	
	l = enc28j80_read_control_res(BANK_0, EWRPTL);
	h = enc28j80_read_control_res(BANK_0, EWRPTH);
	printf("Tx pointer 0x%04x\r\n",h*256+l);
	
	l = enc28j80_read_control_res(BANK_0, ERDPTL);
	h = enc28j80_read_control_res(BANK_0, ERDPTH);
	printf("Rx pointer 0x%04x\r\n",h*256+l);
#endif
	/* MAC configuration P34*/
	/* 1 */
	enc28j80_write_control_res(BANK_2, MACON1, (1<<TXPAUS)|(1<<RXPAUS)|(1<<MARXEN));
 	/* 2 */
	enc28j80_write_control_res(BANK_2, MACON3, (B101<<PADCFG0)|(1<<TXCRCEN)|(1<<FRMLNEN)|(1<<FULDPX));
	/* 3 */
	/* 4 : 1518 */
	enc28j80_write_control_res(BANK_2, MAMXFL, 1518%256);
	enc28j80_write_control_res(BANK_2, MAMXFH, 1518/256);
	/* 5 : 15h */
	enc28j80_write_control_res(BANK_2, MABBIPG, 0x15);
	/* 6 : 12h */
	enc28j80_write_control_res(BANK_2, MAIPGL, 0x12);
	/* 7,8 */
	/* 9. MAC address*/
	enc28j80_write_control_res(BANK_3, MAADR1, MAC[0]);
	enc28j80_write_control_res(BANK_3, MAADR2, MAC[1]);
	enc28j80_write_control_res(BANK_3, MAADR3, MAC[2]);
	enc28j80_write_control_res(BANK_3, MAADR4, MAC[3]);
	enc28j80_write_control_res(BANK_3, MAADR5, MAC[4]);
	enc28j80_write_control_res(BANK_3, MAADR6, MAC[5]);

	MY_MAC[0] = enc28j80_read_control_res(BANK_3, MAADR1);
	MY_MAC[1] = enc28j80_read_control_res(BANK_3, MAADR2);
	MY_MAC[2] = enc28j80_read_control_res(BANK_3, MAADR3);
	MY_MAC[3] = enc28j80_read_control_res(BANK_3, MAADR4);
	MY_MAC[4] = enc28j80_read_control_res(BANK_3, MAADR5);
	MY_MAC[5] = enc28j80_read_control_res(BANK_3, MAADR6);
	
#ifdef DEBUG
	printf("MAC : 0x%02x-0x%02x-0x%02x-0x%02x-0x%02x-0x%02x\r\n",MY_MAC[0],MY_MAC[1],MY_MAC[2],MY_MAC[3],MY_MAC[4],MY_MAC[5]);
#endif
	for (i=0;i<6;i++){
		if (MY_MAC[i] != MAC[i])
			return false;
	}

	/* 	PHY config
			To check PHY config, you can read a phy config address is 0x14h.
		Because the reset value is 
	*/
	enc28j80_write_phy(PHCON1,(1<<PDPXMD));
	/* Config LED */
	enc28j80_write_phy(PHLCON, (1<<STRCH)|(B01<<LFRQ0)|(B0100<<LACFG0)|(B0011<<LBCFG0));
	/* Setup interrupt */
	enc28j60_write_cmd(BFC, EIE, (1<<INTIE)|(1<<PKTIE));
	enc28j60_write_cmd(BFS, EIE, (1<<INTIE)|(1<<PKTIE));
	/* Setup clock */
	enc28j80_write_control_res(BANK_3, ECOCON, (1<<COCON1));
	/* Receive enable */
	enc28j60_write_cmd(BFS, ECON1, (1<<RXEN));
	/* Increment address when write,read */
	enc28j60_write_cmd(BFS, ECON2, (1<<AUTOINC));
	
#ifdef DEBUG
	printf("Finish !\r\n");
#endif
	return 1;
}

/* Read PHY config P19 */
extern uint16_t enc28j80_read_phy(uint8_t address){
	uint8_t status_h = 0;
	uint8_t status_l = 0;
	int16_t timeout = 1000;
	/* 1. Write address of the PHY register */
	enc28j80_write_control_res(BANK_2, MIREGADR, address);
	/* 2.1 Set the MICMD.MIIRD bit */
	enc28j80_write_control_res(BANK_2, MICMD, (1<<MIISCAN));
	enc28j80_write_control_res(BANK_2, MICMD, (1<<MIISCAN)|(1<<MIIRD));
	/* 2.2 Wait 10.24 µs. Read the MISTAT.BUSY bit */
	delay_ms(1);
	do{
		status_h = enc28j80_read_control_res(BANK_3, MISTAT);
		if (status_h&(1<<BUSY)){
			break;
		}
	}while(timeout--);
	
	if (timeout == -1){
		#ifdef DEBUG
				printf("Time out {%d}-{%02x}\r\n",timeout,status_h);
		#endif
		return 0xFFFF;
	}
	#ifdef DEBUG
	printf("MISTAT : 0x%02x {%d}\r\n",status_h, timeout);
	#endif
	/* 4. Clear the MICMD.MIIRD bit */
	enc28j80_write_control_res(BANK_2, MICMD, 0);
	/* 5. Read the desired data from the MIRDL and MIRDH registers */
	status_l = enc28j80_read_control_res(BANK_2, MIRDL);
	status_h = enc28j80_read_control_res(BANK_2, MIRDH);
	
	#ifdef DEBUG
	printf("MIRDL, MIRDH : 0x%02x-0x%02x\r\n",status_l, status_h);
	#endif
	
	return ((status_h<<8) + status_l);
}

/* Write PHY config P19 */
extern bool enc28j80_write_phy(uint8_t address,uint16_t data){
	uint8_t status = 0;
	int16_t timeout = 1000;
	/* 1. Write address of the PHY register */
	enc28j80_write_control_res(BANK_2, MIREGADR, address);
	/* 2. Write the lower 8 to write into the MIWRL */
	enc28j80_write_control_res(BANK_2, MIWRL, data%256);
	/* 3. Write the lower 8 to write into the MIWRH */
	enc28j80_write_control_res(BANK_2, MIWRH, data/256);
	do{
		status = enc28j80_read_control_res(BANK_3, MISTAT);
		if (status&(1<<BUSY)){
			break;
		}
	}while(timeout--);
	
	if (timeout == -1){
		return false;
	}
	return true;
}

extern void enc28j80_write_buffs(uint8_t* data,uint16_t len){
	uint16_t i = 0;
	uint32_t crc = crc32(&(data[14]), 28);
	enc28j60_CS_low();
	enc28j60_spi_write(0x7A);
	enc28j60_spi_write(0x00);
	for(i=0;i<len;i++){
			enc28j60_spi_write(*data++);
	}
	enc28j60_spi_write((crc&0xFF000000)>>24);
	enc28j60_spi_write((crc&0x00FF0000)>>16);
	enc28j60_spi_write((crc&0x0000FF00)>>8);
	enc28j60_spi_write(crc&0x000000FF);
	enc28j60_CS_high();
}

extern bool enc28j80_send_packet(uint8_t *data, uint16_t len){
	#ifdef DEBUG
		printf("Send .....\r\n");
	#endif
	int32_t timeout = 10000;
	uint8_t status = 0;
	/* Calculate CRC */
	/* 1. Appropriately program the ETXST Pointer */
	enc28j80_write_control_res(BANK_0, ETXSTL, TX_START_ADD%256);
	enc28j80_write_control_res(BANK_0, ETXSTH, TX_START_ADD>>8);
	/* 2. Write data into buffer */
	enc28j80_write_buffs(data, len);
	/* 3. Appropriately program the ETXND Pointer */
	enc28j80_write_control_res(BANK_0, ETXNDL, (TX_START_ADD+len)%256);
	enc28j80_write_control_res(BANK_0, ETXNDH, (TX_START_ADD+len)>>8);
	/* Reset start address write */
	enc28j80_write_control_res(BANK_0, EWRPTL, TX_START_ADD%256);
	enc28j80_write_control_res(BANK_0, EWRPTH, TX_START_ADD>>8);
	/* 3,4 */
	/* 5. Start the transmission */
	enc28j60_write_cmd(BFS, ECON1, (1<<TXRTS));
	do{
		status = enc28j80_read_control_res(BANK_0, ECON1);
		// when the packet is finished or was aborted, the ECON1.TXRTS will be cleaned
		if((status&(1<<TXRTS)) == 0){
			break;
		}
//		status = enc28j80_read_control_res(BANK_0, ESTAT);
	}while(timeout--);
	if(timeout == -1){
		#ifdef DEBUG
			printf("Timeout %2d 0x%02x\r\n",timeout, status);
		#endif
		return false;
	}
	#ifdef DEBUG
		printf("Finished ! \r\n");
	#endif
	return true;
}

extern bool enc28j80_receive_packet(uint8_t *data, uint16_t len){
	
	return false;
}

uint8_t rx_buff[512] = {0};
uint8_t rx_head = 0;
uint16_t next_point = 0;
uint16_t length_of_rx_buff = 0;

uint8_t flags = 0;

extern void enc28j80_read_receive_buffs(uint16_t len){
	uint8_t i = 0;
	if (flags == 1){
		printf("Request \r\n");
		printf("NEXT						: %04x \r\n",rx_buff[0] + (rx_buff[1]>>8));
		printf("LENGTH					: %04x \r\n",rx_buff[2] + (rx_buff[3]>>8));
		printf("STATUS 				2	: %04x \r\n",rx_buff[4]);
		printf("STATUS 				3	: %04x \r\n",rx_buff[5]);
		
		printf("Destination MAC	: %02x %02x %02x %02x %02x %02x \r\n",rx_buff[6],rx_buff[7],rx_buff[8],rx_buff[9],rx_buff[10],rx_buff[11]);
		printf("Source MAC			: %02x %02x %02x %02x %02x %02x \r\n",rx_buff[12],rx_buff[13],rx_buff[14],rx_buff[15],rx_buff[16],rx_buff[17]);
		
		printf("Ethertype				: %02x %02x \r\n",rx_buff[18], rx_buff[19]);
		
		printf("Hardware Type		: %02x %02x \r\n",rx_buff[20], rx_buff[21]);
		
		printf("Protocol type		: %02x %02x \r\n",rx_buff[22], rx_buff[23]);
		
		printf("Hardware length	: %02x \r\n",rx_buff[24]);
		printf("Protocol length	: %02x \r\n",rx_buff[25]);
		
		printf("Operation				: %02x %02x \r\n",rx_buff[26], rx_buff[27]);
		
		printf("SHA							: %02x %02x %02x %02x %02x %02x \r\n",rx_buff[28],rx_buff[29],rx_buff[30],rx_buff[31],rx_buff[32],rx_buff[33]);
		printf("SPA							: %02x %02x %02x %02x \r\n",rx_buff[34],rx_buff[35],rx_buff[36],rx_buff[37]);
		printf("THA							: %02x %02x %02x %02x %02x %02x \r\n",rx_buff[38],rx_buff[39],rx_buff[40],rx_buff[41],rx_buff[42],rx_buff[43]);
		printf("TPA							: %02x %02x %02x %02x \r\n",rx_buff[44],rx_buff[45],rx_buff[46],rx_buff[47]);

//		printf("SHA							: %02x %02x %02x %02x %02x %02x \r\n",rx_buff[26],rx_buff[27],rx_buff[28],rx_buff[29],rx_buff[30],rx_buff[31]);
//		printf("SPA							: %02x %02x %02x %02x \r\n",rx_buff[32],rx_buff[33],rx_buff[34],rx_buff[35]);
//		printf("THA							: %02x %02x %02x %02x %02x %02x \r\n",rx_buff[36],rx_buff[37],rx_buff[38],rx_buff[39],rx_buff[40],rx_buff[41]);
//		printf("TPA							: %02x %02x %02x %02x \r\n",rx_buff[42],rx_buff[43],rx_buff[44],rx_buff[45]);
//		

		printf("Head						: %04x \r\n",rx_head);
		printf("\r\n");
		
		return;
	}
	enc28j60_CS_low();
	enc28j60_spi_write(0x3A);
	for(i=0;i<len;i++){
		if (flags == 0){
			if (rx_head > 3){
				if(length_of_rx_buff >= 42){
					rx_buff[rx_head] = enc28j60_spi_read();
				}
			}
			else{
				rx_buff[rx_head] = enc28j60_spi_read();
			}
			if (rx_head == 1){
				next_point = rx_buff[0] + (rx_buff[1]>>8);
			}
			if (rx_head == 3){
				length_of_rx_buff = rx_buff[2] + (rx_buff[3]>>8);
			}
			rx_head++;
			if(rx_head == (length_of_rx_buff + 6)){
				flags = 1;
				enc28j60_CS_high();
			}
		}
	}
	enc28j60_CS_high();
}

uint16_t length = 0;
uint16_t part_length = 0;
uint16_t tx_pointer = 0;
uint8_t _data = 0; 

extern void enc28j60_poll(void){
	length = enc28j80_read_control_res(BANK_1, EPKTCNT);
	if (length > 0){
		enc28j80_read_receive_buffs(length);
	}
	HAL_Delay(1000);
}



