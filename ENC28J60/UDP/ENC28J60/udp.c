#include <string.h>
#include <stdio.h>
#include "udp.h"
#include "crc.h"
#include "enc28j60.h"
#include "enc28j60_config.h"

uint16_t UDP_checksum(uint8_t *data, uint16_t length){
	uint32_t checksum = 0;
	checksum = 0x11 + length;
	while(length>1){
		checksum += (uint16_t) (((uint32_t)*data<<8)|*(data+1));
		data+=2;
		length-=2;
	}
	if(length){
		checksum+=((uint32_t)*data)<<8;
	}
	while (checksum>>16){
		checksum=(uint16_t)checksum+(checksum>>16);
	}
  checksum=~checksum;
  return swap16(checksum);
}

uint16_t NET_ipchecksum(uint8_t *IP_packet_start){
	uint32_t checksum=0;
	uint16_t length=20;
	while(length){
		checksum += (uint16_t) (((uint32_t)*IP_packet_start<<8)|*(IP_packet_start+1));
		IP_packet_start+=2;
		length-=2;
	}
	while (checksum>>16){
		checksum=(uint16_t)checksum+(checksum>>16);
	}
	checksum=~checksum;
	return  swap16(checksum);
}

void udp_send_packet(uint8_t* package, uint16_t len){
	enc28j60_send_packet(package, len);
}

extern void udp_send_package(uint8_t mac_dest[6],const uint8_t ip_dest[4],uint16_t dest_port, uint8_t* data, uint16_t length){
  static uint16_t identification = UDP_IP_IDENTIFICATION;
	UDP_Struct udp_struct;
	
	memcpy(udp_struct.MAC_source, _MAC_SOURCE, 6);
	memcpy(udp_struct.MAC_dest, mac_dest, 6);
	udp_struct.Ethernet_type = swap16(UDP_ETHERNET_TYPE);
	
	udp_struct.Header_length = UDP_HEADER_LENGTH;
	udp_struct.Services = UDP_SERVICES;
	udp_struct.TotalLength = swap16(UDP_IP_SIZE + length);
	udp_struct.Identification = swap16(identification);
	udp_struct.Flag = swap16(UDP_FLAG);
	udp_struct.TimeToLive = UDP_TIME_TO_LIVE;
	udp_struct.Protocol = UDP_PROTOCOL;
	udp_struct.CheckSum = NET_ipchecksum((uint8_t *)&udp_struct.Header_length);
	
	udp_struct.CheckSum = 0x0000;

	memcpy(udp_struct.SourceIP, _IP_SOURCE, 4);
	memcpy(udp_struct.DestIP, ip_dest, 4);

	udp_struct.UDP_Source_Port = swap16(SOURCE_PORT);
	udp_struct.UDP_Dest_Port = swap16(dest_port);
	udp_struct.UDP_Length = swap16(UDP_SIZE + length);
	udp_struct.UDP_Checksum = 0x0000;
	memcpy(udp_struct.UDP_data, data, length);
	udp_struct.UDP_Checksum = UDP_checksum((uint8_t*)&(udp_struct.SourceIP), UDP_SIZE + length);
	
	udp_send_packet((uint8_t*)&udp_struct,  UDP_FRAME_SIZE + length);
	identification+=1;
}

uint8_t udp_data[200];
uint16_t udp_length = 0;

extern bool udp_receive_package(void){
	udp_length = enc28j60_receive_package(udp_data);
	if (udp_length > 0){
		return false;
	}
	if ((udp_data[UDP_IP_I_PROTOCOL] != UDP_PROTOCOL) ||
			(udp_data[UDP_I_DEST_PORT] != (SOURCE_PORT>>8)) || 
			(udp_data[UDP_I_DEST_PORT+1] != (SOURCE_PORT%256))){
			return false;
	}
	return true;
}


