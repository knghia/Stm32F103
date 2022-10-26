#ifndef PCF8574_H_
#define PCF8574_H_
#include "main.h"
#include "i2c.h"

#define ADDRESS_WRITE 		78
#define ADDRESS_READ 			79

#define delay_ms(t)	HAL_Delay(t)

extern void i2c_lcd4_init(void);
extern void i2c_lcd4_cmd(uint8_t Cmd);
extern void i2c_lcd4_put(char Data);
extern void i2c_lcd4_puts(char* Data);
extern void i2c_lcd4_print(int row, int col,char* Data);
extern void i2c_lcd4_cursor(int row, int col);
extern void i2c_lcd_print_number(unsigned long n, uint8_t base);

#endif
