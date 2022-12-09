#ifndef NET_H
#define NET_H

#include "main.h"

#define DEBUG
#define BUFFER_SIZE 1500
/* IP */

#define IPV4_ETHERNET_TYPE 				0x0800
#define IPV4_ETHERNET_TYPE_H 			0x08
#define IPV4_ETHERNET_TYPE_L 			0x00

#define IPV4_HEADER_LENGTH				0x45
#define IPV4_SERVICES							0x00
#define IPV4_IDENTIFICATION				0x0810
#define IPV4_FLAG									0x0000
#define IPV4_TIME_TO_LIVE					128
#define IPV4_PROTOCOL_ICMP				0x01	// 1
#define IPV4_PROTOCOL_UDP					0x11	// 17
#define IPV4_PROTOCOL_TCP					0x06	// 6

#define ETHERNET_II_SIZE				14
#define IPV4_SIZE							20

#define I_IPV4_MAC_SOURCE				0
#define I_IPV4_MAC_DEST					6
#define I_IPV4_ETHERNET_TYPE_H			12
#define I_IPV4_ETHERNET_TYPE_L			13

#define I_IPV4_HARD_LENGTH				14
#define I_IPV4_SERVICES					15
#define I_IPV4_TOTAL_LENGTH_H		16
#define I_IPV4_TOTAL_LENGTH_L		17
#define I_IPV4_IDENTIFI_H			18
#define I_IPV4_IDENTIFI_L			19
#define I_IPV4_FLAG						20
#define I_IPV4_TIMETOLIVE				22
#define I_IPV4_PROTOCOL					23
#define I_IPV4_CHECKSUM					24
#define I_IPV4_SOURCE_IP				26
#define I_IPV4_DEST_IP					30

typedef enum{
	NONE = 0,
	ARP = 1,
	ICMP = 2,
	UDP = 3,
	TCP_IP = 4
}ProtocolIP;

extern bool net_poll(void);
extern void net_init(u08 mymac[6], u08 myip[4], u16 myport, u08 ip_of_pc[4]);

/* ARP */

#define ARP_PACKET_LEN					42
#define ARP_ETHERNET_TYPE				0x0806
#define ARP_HARDWAVE_TYPE				0x0001
#define ARP_PROTOCOL_TYPE				0x0800
#define ARP_SIZE						0x0604
#define ARP_OPCODE_REPLY				0x0002
#define ARP_OPCODE_REQUEST				0x0001

#define I_ARP_MAC_DEST					0
#define I_ARP_MAC_SOURCE				6

#define I_ARP_ETHERNET_TYPE_H			12
#define I_ARP_ETHERNET_TYPE_L			13

#define I_ARP_HARDWAVE_TYPE_H			14
#define I_ARP_HARDWAVE_TYPE_L			15

#define I_ARP_PROTOCOL_TYPE_H			16
#define I_ARP_PROTOCOL_TYPE_L			17

#define I_ARP_SIZE_H					18
#define I_ARP_SIZE_L					19

#define I_ARP_OPCODE_H					20
#define I_ARP_OPCODE_L					21

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
extern void net_arp_reply(void);
extern bool net_arp_get_mac_ip_pc(u08 mac_target[6], u08 ip_target[4], u16 timeout);

/* ICMP */
#define ICMP_REPLY						0x00
#define ICMP_REQUEST					0x08
#define ICMP_CODE							0x00
#define ICMP_IDENTIFIER				0x0001
#define ICMP_SEQUENCE_NUMBER	0x0015

#define I_ICMP_TYPE						34
#define I_ICMP_CODE						35

#define I_ICMP_CHECKSUM_H			36
#define I_ICMP_CHECKSUM_L			37

#define I_ICMP_IDENTIFIER_H		38
#define I_ICMP_IDENTIFIER_L		39

#define I_ICMP_SEQ_NUM_H			40
#define I_ICMP_SEQ_NUM_L			41

#define IPV4_ICMP_SIZE				42
#define ICMP_SIZE							8

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
extern void net_icmp_request(u08* data, u16 len);

/* UDP */
#define I_UDP_SRC_PORT_H 		34 // 0x22
#define I_UDP_SRC_PORT_L 		35 // 0x22

#define I_UDP_DST_PORT_H 		36 // 0x24
#define I_UDP_DST_PORT_L 		37 // 0x24

#define I_UDP_LEN_H 			38 // 0x26
#define I_UDP_LEN_L 			39 // 0x26

#define I_UDP_CHECKSUM_H 		40 // 0x28
#define I_UDP_CHECKSUM_L 		41 // 0x28

#define I_UDP_DATA 				42 // 0x2A
#define UDP_SIZE					8

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
  u08 UDP_Data[512];
}UDP_Frame;

/* TCP */
#define I_TCP_SRC_PORT_H 			34
#define I_TCP_SRC_PORT_L 			35
#define I_TCP_DST_PORT_H 			36
#define I_TCP_DST_PORT_L 			37
#define I_TCP_SEQ_NUM					38 // 4 bytes
#define I_TCP_ACK_NUM 				42 // 4 bytes

/* Flags */
#define I_TCP_FLAGS_H 				46
#define I_TCP_FLAGS_L 				47

#define TCP_FLAGS_FIN 			(1<<0)
#define TCP_FLAGS_SYN 			(1<<1)
#define TCP_FLAGS_RST 			(1<<2)
#define TCP_FLAGS_PUSH 			(1<<3)
#define TCP_FLAGS_ACK 			(1<<4)
#define TCP_FLAGS_URG				(1<<5)				
#define TCP_FLAGS_ECN_ECHO	(1<<6) 			
#define TCP_FLAGS_CWR				(1<<7)

#define I_TCP_WIN_H					48
#define I_TCP_WIN_L					49

#define I_TCP_CHECKSUM_H		50
#define I_TCP_CHECKSUM_L		51

#define I_TCP_URG_POINTER_H	52
#define I_TCP_URG_POINTER_L	53

/* Data */
#define I_TCP_DATA					54
#define TCP_DATA_SIZE				54
/* Option */
/* Maximun segment size */
#define I_TCP_OPT_MSS_KIND		54
#define I_TCP_OPT_MSS_LEN			55
#define I_TCP_OPT_MSS_VALUE_H	56
#define I_TCP_OPT_MSS_VALUE_L	57
/* No-operation */
#define I_TCP_OPT_NOP_KIND_1	58
/* Window scale */
#define I_TCP_OPT_WS_KIND			59
#define I_TCP_OPT_WS_LEN			60
#define I_TCP_OPT_WS_SHIFT_COUNT	61
/* No-operation */
#define I_TCP_OPT_NOP_KIND_2		62
/* No-operation */
#define I_TCP_OPT_NOP_KIND_3		63
/* SACK permiited */
#define I_TCP_OPT_SACK_PER			64
#define I_TCP_OPT_SACK_LENN			65

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
  /* TCP */
  u16 TCP_Source_Port;
  u16 TCP_Dest_Port;
  u08 TCP_Seq_Number[4];
  u08 TCP_Ack_Number[4];
	u08 TCP_Data_Offset;
  u08 TCP_Flags;
  u16 TCP_Window;
  u16 TCP_Checksums;
  u16 TCP_Urgent_Pointer;
  u08 TCP_Data[255];
}TCP_Frame;

extern bool net_tcp_ip_check(u08* request, u16 len);
extern bool net_tcp_ip_reply(u08* request, u16 len);

extern void net_tcp_ip_push_handle(u08* request, u16 len);
extern void net_tcp_ip_handle(u08* request, u16 len);

typedef struct{
	u08 op;            	///< @ref DHCP_BOOTREQUEST or @ref DHCP_BOOTREPLY
	u08 htype;         	///< @ref DHCP_HTYPE10MB or @ref DHCP_HTYPE100MB
	u08 hlen;          	///< @ref DHCP_HLENETHERNET
	u08 hops;          	///< @ref DHCP_HOPS
	u08 xid[4];         ///< @ref DHCP_XID  This increase one every DHCP transaction.
	u16 secs;          	///< @ref DHCP_SECS
	u16 flags;         	///< @ref DHCP_FLAGSBROADCAST or @ref DHCP_FLAGSUNICAST
	u08 ciaddr[4];     	///< @ref Request IP to DHCP sever
	u08 yiaddr[4];     	///< @ref Offered IP from DHCP server
	u08 siaddr[4];     	///< No use 
	u08 giaddr[4];     	///< No use
	u08 chaddr[16];    	///< DHCP client 6bytes MAC address. Others is filled to zero
	u08 sname[64];     	///< No use
	u08 file[128];     	///< No use
	u08 OPT[312]; 			///< Option
}DHCP_Frame;

extern void net_dhcp_discover(void);
extern void net_dhcp_udp_send(u08* data, u16 len_of_data);

#endif
