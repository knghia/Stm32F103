#include <string.h>
#include <stdio.h>
#include "icmp.h"
#include "crc.h"
#include "enc28j60.h"
#include "enc28j60_config.h"

uint16_t ICMP_checksum(uint8_t *data, uint16_t len){
	uint32_t i = 0;
	uint32_t sum = 0;
	while(len>1){
		sum += 0xFFFF & ((data[i]<<8)|data[i+1]);
		i+=2;
		len-=2;
	}
	if (len){
		sum += (0xFF & *data)<<8;
	}
	while (sum>>16){
		sum= ((uint16_t)sum+(sum>>16));
	}
	sum=~sum;
	return swap16((uint16_t) sum);
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

	return swap16(checksum);
}

void udp_send_packet(uint8_t* package, uint16_t len){
	enc28j60_send_packet(package, len);
}

extern void icmp_send_package(uint8_t mac_dest[6],const uint8_t ip_dest[4], uint8_t* data, uint16_t length){
  static uint16_t ipv4_identification = IPV4_IDENTIFICATION;
	static uint16_t icmp_identification = ICMP_IDENTIFIER;
	static uint16_t icmp_senquence_number = ICMP_SEQUENCE_NUMBER;
	ICMP_Struct icmp_struct;
	
	memcpy(icmp_struct.MAC_source, mac_dest, 6);
	memcpy(icmp_struct.MAC_dest,_MAC_SOURCE , 6);
	icmp_struct.Ethernet_type = swap16(IPV4_ETHERNET_TYPE);
	
	icmp_struct.Header_length = IPV4_HEADER_LENGTH;
	icmp_struct.Services = IPV4_SERVICES;
	icmp_struct.TotalLength = swap16(IPV4_SIZE + length);
	icmp_struct.Identification = swap16(ipv4_identification);
	icmp_struct.Flag = swap16(IPV4_FLAG);
	icmp_struct.TimeToLive = IPV4_TIME_TO_LIVE;
	icmp_struct.Protocol = IPV4_PROTOCOL_ICMP;
	icmp_struct.CheckSum = NET_ipchecksum((uint8_t *)&icmp_struct.Header_length);

	memcpy(icmp_struct.SourceIP, _IP_SOURCE, 4);
	memcpy(icmp_struct.DestIP, ip_dest, 4);

	icmp_struct.ICMP_Type = ICMP_REQUEST;
	icmp_struct.ICMP_Code = ICMP_CODE;
	icmp_struct.ICMP_Identification = swap16(icmp_identification);
	icmp_struct.ICMP_SequenceNumber = swap16(icmp_senquence_number);
	memcpy(icmp_struct.ICMP_data, data, length);
	
	icmp_struct.ICMP_Checksum = 0x0000;
	icmp_struct.ICMP_Checksum = ICMP_checksum((uint8_t*)&(icmp_struct.ICMP_Type), ICMP_SIZE + length);
	udp_send_packet((uint8_t*)&icmp_struct.MAC_source[0], IPV4_ICMP_SIZE + length);
	
	ipv4_identification+=1;
	icmp_identification+=1;
	icmp_senquence_number+=1;
}

uint8_t icmp_data[200];
uint16_t icmp_length = 0;

extern bool icmp_receive_package(void){
	icmp_length = enc28j60_receive_package(icmp_data);
	if (icmp_length > 0){
		return false;
	}
	if ((icmp_data[I_IPV4_PROTOCOL] != IPV4_PROTOCOL_ICMP)){
			return false;
	}
	
	for(uint8_t i=0;i<icmp_length;i++){
			printf("0x%02x, ",icmp_data[i]);
	}
	printf("\r\n");
	return true;
}


