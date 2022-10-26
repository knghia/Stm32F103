
#ifndef NOKIA5110_H
#define NOKIA5110_H

#ifdef __cplusplus
extern "C"{
#endif

#include <inttypes.h>
#include "main.h"
#include "font.h"

extern void spi_init(void);
extern void spi_write(uint8_t data);
extern void spi_print(uint8_t* data,uint8_t len);

extern void nokia5110_init(void);
extern void nokia5110_reset(void);
extern void nokia5110_cmd(uint8_t cmd);
extern void nokia5110_write(uint8_t data);
extern void nokia5110_print(uint8_t *data,int len);
extern void nokia5110_cursor(uint8_t row,uint8_t col);
extern void nokia5110_init(void);

extern void nokia5110_text(uint8_t row,uint8_t col,char data);
extern void nokia5110_texts(uint8_t row,uint8_t col,char* data);
#ifdef __cplusplus
}
#endif

#endif
