#include "icmp.h"


extern const uint8_t macaddr[6];
extern const uint8_t ip[4];
extern uint8_t debug_string[60];

uint16_t ICMP_checksum(ICMP_struct *icmp_packet,uint16_t icmp_len )
{
    uint32_t checksum=0;
    uint8_t *ptr;
    icmp_packet->ICMP_checkSum=0; //reset check sum
    icmp_len-=34;    //bo qua truong ethernet va truong ip
    ptr = &icmp_packet->ICMP_Type;
    while(icmp_len>1) //cong het cac byte16 lai
    {
       checksum += (uint16_t) (((uint32_t)*ptr<<8)|*(ptr+1));
       ptr+=2;
	   icmp_len-=2;
    }
    if(icmp_len) checksum+=((uint32_t)*ptr)<<8; //neu con le 1 byte
    while (checksum>>16) checksum=(uint16_t)checksum+(checksum>>16);

    //nghich dao bit
    checksum=~checksum;

    //hoan vi byte thap byte cao
    return (  ((checksum>>8)&0xFF) | ((checksum<<8)&0xFF00)  );
}

void ICMP_ping_reply(ICMP_struct * ping_packet,uint16_t len)
{
  uint8_t buffer_temp[6];  //buff trung gian phuc vu hoan doi

  //hoan vi MAC
  memcpy(buffer_temp,ping_packet->MAC_nguon,6);           //copy mac nguon vao bo nho tam
  memcpy(ping_packet->MAC_nguon,ping_packet->MAC_dich,6); //copy mac dich vai mac nguon
  memcpy(ping_packet->MAC_dich,buffer_temp,6);

  //hoan vi IP
  memcpy(buffer_temp,ping_packet->SourceIP,4);           //copy ip nguon vao bo nho tam
  memcpy(ping_packet->SourceIP,ping_packet->DestIP,4);   //copy ip dich vai mac nguon
  memcpy(ping_packet->DestIP,buffer_temp,4);

  //make packet reply
  ping_packet->ICMP_Type = 0x00; //type = reply
  ping_packet->ICMP_checkSum = ICMP_checksum(ping_packet,len);

  NET_SendFrame((uint8_t *)ping_packet,len); //gui phan hoi
}

void ICMP_read(uint8_t *ICMP_Frame,uint16_t len)
{
   ICMP_struct *ICMP_Ping_Packet = (ICMP_struct *)ICMP_Frame;

  //kiem tra dia chi ip xem co phai no gui cho minh khong
  if( memcmp(ICMP_Ping_Packet->DestIP,ip,4) )return; // dung memcmp de so sanh, neu khac thi thoat

  //kiem tra xem co phai ping reuqest khong ?
  if(ICMP_Ping_Packet->ICMP_Type == 0x08)
  {
      //UART_putString("Da nhan 1 goi ping request\r\n");
     //phan hoi lai goi ping
     ICMP_ping_reply(ICMP_Ping_Packet,len);
  }
}

//--------------------------------------------------
//End file
