#ifndef NET_H
#define NET_H

#include "main.h"

// #define DEBUG

/* IP */

#define IPV4_ETHERNET_TYPE 				0x0800
#define IPV4_HEADER_LENGTH				0x45
#define IPV4_SERVICES							0x00
#define IPV4_IDENTIFICATION				0x0810
#define IPV4_FLAG									0x0000
#define IPV4_TIME_TO_LIVE					128
#define IPV4_PROTOCOL_ICMP				0x01	// 1
#define IPV4_PROTOCOL_UDP					0x11	// 17

#define ETHERNET_II_SIZE					14
#define IPV4_SIZE									20

#define I_IPV4_MAC_SOURCE					0
#define I_IPV4_MAC_DEST						6
#define I_IPV4_ETHERNET_TYPE			12

#define I_IPV4_HARD_LENGTH			14
#define I_IPV4_SERVICES					15
#define I_IPV4_TOTAL_LENGTH			16
#define I_IPV4_IDENTIFICATION		18
#define I_IPV4_FLAG							20
#define I_IPV4_TIMETOLIVE				22
#define I_IPV4_PROTOCOL					23
#define I_IPV4_CHECKSUM					24
#define I_IPV4_SOURCE_IP				26
#define I_IPV4_DEST_IP					30

typedef enum{
	NONE = 0,
	ARP = 1,
	ICMP = 2,
	UDP = 3
}ProtocolIP;

extern bool net_analysis(void);
extern void net_init(u08 mymac[6], u08 myip[4], u16 myport);

/* ARP */

#define ARP_PACKET_LEN					42
#define ARP_ETHERNET_TYPE				0x0806
#define ARP_HARDWAVE_TYPE				0x0001
#define ARP_PROTOCOL_TYPE				0x0800
#define ARP_SIZE								0x0604
#define ARP_OPCODE_REPLY				0x0002
#define ARP_OPCODE_REQUEST			0x0001

#define I_ARP_MAC_DEST					0
#define I_ARP_MAC_SOURCE				6
#define I_ARP_ETHERNET_TYPE			12
#define I_ARP_HARDWAVE_TYPE			14
#define I_ARP_PROTOCOL_TYPE			16
#define I_ARP_SIZE							18
#define I_ARP_OPCODE						20
#define I_ARP_MAC_SENDER				22
#define I_ARP_IP_SENDER					28
#define I_ARP_MAC_TARGET				32
#define I_ARP_IP_TARGET					38

typedef struct{
	u08 MAC_dest[6];             				// MAC destination
	u08 MAC_source[6];                  // MAC source
	u16 Ethernet_type;                 	// Ethernet type
	
	u16 Hardwave_type;                 	// Hardwave type
	u16 Protocol_type;                 	// Protocol type (ARP)
	u16 Size;                          	// Size
	u16 Opcode;                        	// Opcode
	u08 MAC_sender[6];                  // Sender MAC
	u08 IP_sender[4];                   // Sender IP
	u08 MAC_target[6];                  // Target MAC
	u08 IP_target[4];                   // Target IP
}ARP_Frame;

extern bool net_arp_check_broadcast(u08* ping, u16 len);
extern void net_arp_reply(u08* ping, u16 len);
extern bool net_arp_get_mac_ip_pc(u08 mac_target[6], u08 ip_target[4], u16 timeout);

/* ICMP */

#define ICMP_REPLY								0x00
#define ICMP_REQUEST							0x08
#define ICMP_CODE									0x00
#define ICMP_IDENTIFIER						0x0001
#define ICMP_SEQUENCE_NUMBER			0x0015

#define I_ICMP_TYPE								34
#define I_ICMP_CODE								35
#define I_ICMP_CHECKSUM						36
#define I_ICMP_IDENTIFIER					38
#define I_ICMP_SEQUENCE_NUMBER		40

#define IPV4_ICMP_SIZE						42
#define ICMP_SIZE									8

typedef struct{
	/* It is Ethernet Frame II */
	u08 MAC_dest[6];
	u08 MAC_source[6];
	u16 Ethernet_type;
	/* IP */
	u08 Header_length; 
	u08 Services;
	/* Total length */
	u16 TotalLength;
	u16 Identification;
	u16 Flag;
	u08 TimeToLive;
	u08 Protocol;
	u16 CheckSum;
	u08 SourceIP[4];
	u08 DestIP[4];
	/* ICMP */
	u08 ICMP_Type;
	u08 ICMP_Code;
	u16 ICMP_Checksum; 
	u16 ICMP_Identification;
	u16 ICMP_SequenceNumber;
	u08 ICMP_Data[255]; 
}ICMP_Frame;

extern void net_icmp_reply(u08* ping, u16 len);
extern bool net_icmp_check(u08* ping, u16 len);
extern void net_icmp_response(u08* data, u16 len);

/* UDP */
#define I_UDP_SRC_PORT 			34 // 0x22
#define I_UDP_DST_PORT 			36 // 0x24
#define I_UDP_LEN 					38 // 0x26
#define I_UDP_CHECKSUM 			40 // 0x28
#define I_UDP_DATA 					42 // 0x2A
#define UDP_SIZE						8

typedef struct{
	/* It is Ethernet Frame II */
	u08 MAC_dest[6];
	u08 MAC_source[6];
	u16 Ethernet_type;
	/* IP */
	u08 Header_length; 
	u08 Services;
	/* Total length
		Form: Header_length - Data
	*/
	u16 TotalLength;
	u16 Identification;
	u16 Flag;
	u08 TimeToLive;
	u08 Protocol;
	u16 CheckSum;
	u08 SourceIP[4];
	u08 DestIP[4];
	/* UDP */
  u16 UDP_Source_Port;
  u16 UDP_Dest_Port;
  u16 UDP_Length;
  u16 UDP_Checksum;
  u08 UDP_Data[255];
}UDP_Frame;

extern bool net_udp_check(u08* response, u16 len);
extern void net_udp_reply(u08* ping, u16 len);
extern void net_udp_handle(u08 num);
extern void net_udp_request(u08* response, u08* data, u16 len_of_data);

#define TCP_CWR 0x80
#define TCP_ECE 0x40
#define TCP_URG 0x20
#define TCP_ACK 0x10
#define TCP_PSH 0x08
#define TCP_RST 0x04
#define TCP_SYN 0x02
#define TCP_FIN 0x01

typedef struct{
	/* It is Ethernet Frame II */
	u08 MAC_dest[6];
	u08 MAC_source[6];
	u16 Ethernet_type;
	/* IP */
	u08 Header_length; 
	u08 Services;
	u16 TotalLength;
	u16 Identification;
	u16 Flag;
	u08 TimeToLive;
	u08 Protocol;
	u16 CheckSum;
	u08 SourceIP[4];
	u08 DestIP[4];
  /* TCP */
  u16 TCP_Source_Port;
  u16 TCP_Dest_Port;
  u32 TCP_Sequence_Number;
  u32 TCP_Acknowledgement;
  u08 TCP_Data_Offset;
  u08 TCP_Flags;
  u16 TCP_Window;
  u16 TCP_Checksums;
  u16 TCP_Urgent_Pointer;
  u08 TCP_Data[];
}TCP_struct;


//--------------------------------------------------

#endif
