#include <mega328p.h>
#include <delay.h>
#include <spi.h>
#include "uart.h"
#include "enc28j60.h"
#include "net.h"
#include "arp.h"

void INT1_init()
{
 PORTD.3=0; //no pull
 DDRD.3=0;// input mode
 EICRA=0x08; //INT1 Mode: Falling Edge
 EIMSK=0x02;
 EIFR=0x02; //kich hoat ngat chan int1
}
// External Interrupt 1 service routine
interrupt [EXT_INT1] void ext_int1_isr(void)
{
   NET_loop();
}

uint32_t sys_tick;
void TIMER1_init_1ms()
{
  sys_tick=0;
  TCCR1B=0x02;  // timer 1 2Mhz
  TIMSK1=0x01;  // Timer/Counter 1 Interrupt(s) initialization
}
interrupt [TIM1_OVF] void timer1_ovf_isr(void) // Timer1 overflow interrupt service routine
{
  TCNT1H=0xF8;
  TCNT1L=0x2D;
  sys_tick++;
  ARP_clear_table();
}
void main(void)
{
#pragma optsize-
CLKPR=0x80;
CLKPR=0x00;
#ifdef _OPTIMIZE_SIZE_
#pragma optsize+
#endif

PORTB=0xff;
DDRB=0xff;
DDRB.4=0;

PORTC=0xff;
DDRC=0xff;

PORTD=0xff;
DDRD=0xff;

// SPI initialization
// SPI Type: Master
// SPI Clock Rate: 4000,000 kHz
// SPI Clock Phase: Cycle Start
// SPI Clock Polarity: Low
// SPI Data Order: MSB First
SPCR=0x50;
SPSR=0x00;

UART_init();
INT1_init();
TIMER1_init_1ms();

UART_putString("IOT47.com - ENC28J60 tutorial !!!\r\n");
ENC29J600_ini();

#asm("sei")
while (1)
      {

      }
}
