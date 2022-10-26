#include "udp.h"

extern const uint8_t macaddr[6];
extern const uint8_t ip[4];
extern uint8_t debug_string[60];
void UDP_read(uint8_t *UDP_Frame,uint16_t len)
{
  UDP_struct *UDP_Struct_Frame = (UDP_struct *)UDP_Frame;
  //kiem tra dia chi ip xem co phai no gui cho minh khong
  if( memcmp(UDP_Struct_Frame->DestIP,ip,4) )return; // dung memcmp de so sanh, neu khac thi thoat

}

uint16_t UDP_checksum(UDP_struct *UDP_Struct_Frame)
{
   uint32_t checksum;
   uint8_t *ptr;
   uint16_t length;
   UDP_Struct_Frame->UDP_Checksum=0; //reset check sum
   length = swap16(UDP_Struct_Frame->UDP_Length) + 8;
   ptr = (uint8_t *)&UDP_Struct_Frame->SourceIP;

   checksum=0x11 + length-8;
   while(length>1) //cong het cac byte16 lai
    {
       checksum += (uint16_t) (((uint32_t)*ptr<<8)|*(ptr+1));
       ptr+=2;
	   length-=2;
    }
    if(length) checksum+=((uint32_t)*ptr)<<8; //neu con le 1 byte
    while (checksum>>16) checksum=(uint16_t)checksum+(checksum>>16);
    //nghich dao bit
    checksum=~checksum;
    //hoan vi byte thap byte cao
    return swap16(checksum);
}
uint8_t UDP_send(uint8_t *IP_dest,uint16_t port_dest,uint8_t *data,uint8_t len,uint32_t timeout)
{
   uint32_t count=0;
   uint16_t frame_length;
	 uint8_t mac[] = {0x08, 0x10, 0x19, 0x97, 0x25, 0x25};
	 uint8_t mac_source[] = {0x28, 0xd2, 0x44, 0xcc, 0x71, 0x41};
	 uint8_t ip_source[] = {192, 168, 137, 10};
   UDP_struct UDP_Struct_Frame;
//   while(1)
//   {
//     if(ARP_table_checkIP(IP_dest) != -1)break; // da nhan dc MAC
//     ARP_send_request(IP_dest);
//     delay_ms(50);
//     count+=50;
//     if(count >= timeout)
//     {
//       printf("Chua gui goi tin udp\r\n");
//       return 0; //gui that bai
//     }
//   }

//   //make Ethernet II
//   ARP_table_get_MAC(IP_dest,UDP_Struct_Frame.MAC_dich);   //mac cua thang nhan
   memcpy(UDP_Struct_Frame.MAC_nguon, mac_source, 6);  //mac cua enc28j60
	 memcpy(UDP_Struct_Frame.MAC_dich, mac, 6);
   UDP_Struct_Frame.Ethernet_type = 0x0008; // Type = 0x800 = IP

   //make IP packet
   UDP_Struct_Frame.Header_length = 0x45;
   UDP_Struct_Frame.Services=0x00;
   UDP_Struct_Frame.TotoLength=swap16(len+8+20);
   UDP_Struct_Frame.Identification=0x32b9;
   UDP_Struct_Frame.Flag=0x0000;
   UDP_Struct_Frame.TimeToLive=0x80;
   UDP_Struct_Frame.Protocol=0x11; //UDP
   UDP_Struct_Frame.CheckSum=0x0000;
   memcpy(UDP_Struct_Frame.SourceIP,ip_source,4); //ip cua enc28j60
   memcpy(UDP_Struct_Frame.DestIP,IP_dest,4); //ip cua thang nhan
   //tinh checksum goi ip
   UDP_Struct_Frame.CheckSum=NET_ipchecksum((uint8_t *)&UDP_Struct_Frame.Header_length);


   //make UDP packet
   UDP_Struct_Frame.UDP_Source_Port = swap16(ENC28J60_UDP_PORT);
   UDP_Struct_Frame.UDP_Dest_Port =  swap16(port_dest);
   UDP_Struct_Frame.UDP_Length = swap16(len + 8);
   UDP_Struct_Frame.UDP_Checksum=0x0000;
   memcpy(UDP_Struct_Frame.data , data, len); //copy data to struct
   //tinh checksum cho udp
   UDP_Struct_Frame.UDP_Checksum = UDP_checksum(&UDP_Struct_Frame);

   frame_length = swap16(UDP_Struct_Frame.UDP_Length) + 34;
   NET_SendFrame((uint8_t *)&UDP_Struct_Frame,frame_length); //gui goi tin udp
   return 1; //da gui
}
//--------------------------------------------------
//end file
