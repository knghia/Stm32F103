
#ifndef I2C_H
#define I2C_H
#include "main.h"

extern void i2c_init(void);
extern void i2c_write(uint8_t address, uint8_t byte);
;

#endif
