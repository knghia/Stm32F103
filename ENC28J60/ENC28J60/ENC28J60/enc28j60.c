#include "config.h"
#include "enc28j60.h"

extern void enc28j60_write_cmd(uint8_t address, uint8_t data){
	address = (2<<4)|address;
	enc28j60_CS_low();
	enc28j60_spi_write(address);
	enc28j60_spi_write(data);
	enc28j60_CS_high();
}

extern uint8_t enc28j60_read_cmd(uint16_t address){
	uint8_t result = 0;
	enc28j60_CS_low();
	enc28j60_spi_write(address);
	result = enc28j60_spi_read();
	enc28j60_CS_high();
	
	return result;
}


uint8_t status = 0;
uint8_t cmd_status = 0;

extern void enc28j60_init(void){
	enc28j60_RST_low();
	delay_ms(1);
	enc28j60_RST_high();
	delay_ms(1000);
	enc28j60_spi_init();
	
	enc28j60_write_cmd(ECON1, 0x01);
}

extern void enc28j60_poll(void){
	status = enc28j60_read_cmd(ECON1);
	HAL_Delay(100);
}


