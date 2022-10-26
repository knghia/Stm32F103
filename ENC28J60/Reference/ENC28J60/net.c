#include "net.h"

uint8_t eth_buffer[BUFFER_LENGTH];

extern const uint8_t macaddr[6];
extern const uint8_t ip[4];
extern uint8_t debug_string[60];  //khai bao lai mang de debug ta man serial

void NET_SendFrame(uint8_t *EthFrame,uint16_t len)
{
	
	for(uint16_t i=0;i<len;i++){
		printf("%02x ",EthFrame[i]);
	}
	
  //sprintf(debug_string,"Gui goi tin ethernet co do dai: %i\r\n",len);
  //UART_putString(debug_string);
  ENC28J60_send_packet(EthFrame,len);
}
uint16_t NET_ipchecksum(uint8_t *IP_packet_start)
{
  uint32_t checksum=0;
  uint16_t length=20;
    while(length) //cong het cac byte16 lai
    {
       checksum += (uint16_t) (((uint32_t)*IP_packet_start<<8)|*(IP_packet_start+1));
       IP_packet_start+=2;
	   length-=2;
    }
    while (checksum>>16) checksum=(uint16_t)checksum+(checksum>>16);
    //nghich dao bit
    checksum=~checksum;
    //hoan vi byte thap byte cao
    return  swap16(checksum);
}
void NET_ipRead(uint8_t *IP_Frame,uint16_t len)
{
  //chung ta se kiem tra xem goi tin do thuoc loai nao tcp hay udp hay icmp
  if(IP_Frame[23] == 0x01) //it is ICMP packet
  {
     ICMP_read(IP_Frame,len);
  }
  else if(IP_Frame[23] == 0x11) //it is UDP packet
  {
     UDP_read(IP_Frame,len);
  }
}
void NET_read(uint8_t *net_buffer,uint16_t len)
{
  //in ra do dai cua goi tin
  //sprintf(debug_string,"Da doc goi tin ra, do dai goi tin=%i\r\n",len);
  //UART_putString(debug_string);

  //kiem tra xem co phai goi tin ARP khong
  if(net_buffer[12] == 0x08 && net_buffer[13] == 0x06)
  {
    if(len>41)
    {
    //day dung la goi tin ARP
    //UART_putString("Day la goi tin ARP\r\n");
    //gui goi tin cho thu vien ARP.h xu li
    ARP_read_packet(net_buffer,len);
    }
  }
  //kiem tra xem co phai goi tin IP khong
  else if(net_buffer[12] == 0x08 && net_buffer[13] == 0x00)
  {
     //check ip
     //UART_putString("Day la goi tin IP\r\n");
     NET_ipRead(net_buffer,len);
  }
}
void NET_loop(void)
{
 uint16_t len;
 while(1)
 {
    len=ENC28J60_read_packet(eth_buffer,BUFFER_LENGTH);
    if(len==0)return;
    else NET_read(eth_buffer,len);
 }
}
//--------------------------------------------------------------------------
//End file

