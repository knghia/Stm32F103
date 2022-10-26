
#include "pcf8574.h"

static void pcf8574_write(uint8_t byte){
		i2c_write(ADDRESS_WRITE, byte);
}
              
extern void i2c_lcd4_cmd(uint8_t Cmd){

    uint8_t data_u, data_l;
		uint8_t data_t[4];
		data_u = (Cmd&0xf0);
		data_l = ((Cmd<<4)&0xf0);
		data_t[0] = data_u|0x0C;  //en=1, rs=0
		data_t[1] = data_u|0x08;  //en=0, rs=0
		data_t[2] = data_l|0x0C;  //en=1, rs=0
		data_t[3] = data_l|0x08;  //en=0, rs=0

    pcf8574_write(data_t[0]);delay_ms(1);
    pcf8574_write(data_t[1]);
    pcf8574_write(data_t[2]);delay_ms(1);
    pcf8574_write(data_t[3]);
		delay_ms(2);
}

extern void i2c_lcd4_put(char Data){
    uint8_t data_u, data_l;
		uint8_t data_t[4];
		data_u = (Data&0xf0);
		data_l = ((Data<<4)&0xf0);
		data_t[0] = data_u|0x0D;  //en=1, rs=0
		data_t[1] = data_u|0x09;  //en=0, rs=0
		data_t[2] = data_l|0x0D;  //en=1, rs=0
		data_t[3] = data_l|0x09;  //en=0, rs=0

    pcf8574_write(data_t[0]);delay_ms(1);
    pcf8574_write(data_t[1]);delay_ms(1);
    pcf8574_write(data_t[2]);delay_ms(1);
    pcf8574_write(data_t[3]);delay_ms(1);
}

extern void i2c_lcd4_high(uint8_t byte){
    uint8_t data_u = (byte&0xf0)|0x04;
    pcf8574_write(data_u);
		data_u&=~(1<<2);
    pcf8574_write(data_u);
}

extern void i2c_lcd4_puts(char *Data){
    while(*Data!= 0){
        i2c_lcd4_put(*Data);
        Data+= 1;
    }
}

extern void i2c_lcd4_print(int row,int col,char *Data){
    i2c_lcd4_cursor(row,col);
    i2c_lcd4_puts(Data);
}

extern void i2c_lcd4_cursor(int row,int col){
    if (row==0)
        i2c_lcd4_cmd(0x80+col);
    else
        i2c_lcd4_cmd(0x80+0x40+col);
}

extern void i2c_lcd4_init(void){
    i2c_init();
    delay_ms(60);
    i2c_lcd4_high(0x30); 
    
    delay_ms(5);
    i2c_lcd4_high(0x30);
    
    delay_ms(1);
    i2c_lcd4_high(0x30);
    i2c_lcd4_high(0x20);
    
    i2c_lcd4_cmd(0x01);
    i2c_lcd4_cmd(0x28);
		i2c_lcd4_cmd(0x0c);
    i2c_lcd4_cmd(0x06);
    delay_ms(10);
}


extern void i2c_lcd_print_number(unsigned long n, uint8_t base)
{
  char buf[8 * sizeof(long) + 1];
  char *str = &buf[sizeof(buf) - 1];

  *str = '\0';
  if (base < 2) base = 10;

  do {
    char c = n % base;
    n /= base;

    *--str = c < 10 ? c + '0' : c + 'A' - 10;
  } while(n);

  i2c_lcd4_puts(str);
}

