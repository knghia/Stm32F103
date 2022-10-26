
#ifndef AS5600_H_
#define AS5600_H_
#include "main.h"
#include "i2c.h"

#define AS5600_ADDRESS 			0x36

#define delay_ms(t)	HAL_Delay(t)

extern void as5600_init(void);
extern void as5600_write(uint8_t byte);
extern uint16_t as5600_read(uint16_t address_of_register);
        
#endif
