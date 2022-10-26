
#ifndef I2C_H
#define I2C_H
#include "main.h"

extern void i2c_init(void);
extern void i2c_write(uint8_t write_address, uint8_t byte);
extern uint16_t i2c_read(uint8_t read_address, uint8_t address_of_register);

#endif
