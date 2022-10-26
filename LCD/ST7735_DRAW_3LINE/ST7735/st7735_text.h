
#ifndef ST7735_TEXT_H
#define ST7735_TEXT_H
#include <string.h>
#include <inttypes.h>
#include "config.h"
#include "st7735.h"
#include "font5x7.h"

void ST7735_PutChar5x7(uint16_t X, uint16_t Y, uint8_t chr, uint16_t color);
void ST7735_PutStr5x7(uint8_t X, uint8_t Y, char *str, uint16_t color);

#endif


