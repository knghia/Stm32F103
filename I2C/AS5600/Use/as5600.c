
#include "as5600.h"

extern void as5600_init(void){
	i2c_init();
}

extern void as5600_write(uint8_t byte){
		i2c_write(AS5600_ADDRESS, byte);
}        

extern uint16_t as5600_read(uint16_t address_of_register){
	uint16_t data;
	data = i2c_read(AS5600_ADDRESS,address_of_register);
	return data;
}

