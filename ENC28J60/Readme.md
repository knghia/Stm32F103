<span style="font-family: Courier New;">

# ARP

![image info](./Image/arp_request.png)

![image info](./Image/arp.png)

![image info](./Image/frame.png)

+ Destination MAC (6) : mặc định <ins>**0xFF,0xFF,0xFF,0xFF,0xFF,0xFF**</ins>

+ Source MAC PC (6) : địa chỉ nguồn, là địa chỉ của <ins>**ENC28J60**</ins>

+ Ethernet Type (2) : thể hiện đây là bản tin <ins>**ARP (0x08 0x06)**</ins>

+ Htype (2) : hardware type -  Ethernet <ins>**0x00 0x01**</ins> 

+ Ptype (2) : protocol type - IP <ins>**0x00 0x01**</ins> 

+ HLEN (2) : hardware length <ins>**0x06**</ins>

+ PLEN (2) : protocol length <ins>**0x04**</ins>

+ OPRE Request (2) : request <ins>**0x00 và 0x01**</ins>, reply <ins>**0x00 và 0x02**</ins>

+ Sender MAC PC (6) : địa chỉ MAC của ENC28J60

+ Sender IP (4) : địa chỉ của ENC28J60

+ Target MAC (6) : mặc định là <ins>**0x00,0x00,0x00,0x00,0x00,0x00**</ins>

+ Target IP (4) : địa chỉ của PC

# Get mac

![image info](./Image/terminal.png)

Địa chỉ trùng với địa chỉ MAC và IP của cài đặt. PC đã lấy được địa của MAC và IP của ENC28J60

# Struct

```c
typedef struct
{
	uint8_t MAC_dest[6];             		// MAC destination
	uint8_t MAC_source[6];                  // MAC source
	uint16_t Ethernet_type;                 // Ethernet type
	uint16_t Hardwave_type;                 // Hardwave type
	uint16_t Protocol_type;                 // Protocol type (ARP)
	uint16_t Size;                          // Size
	uint16_t Opcode;                        // Opcode
	uint8_t MAC_sender[6];                  // Sender MAC
	uint8_t IP_sender[4];                   // Sender IP
	uint8_t MAC_target[6];                  // Target MAC
	uint8_t IP_target[4];                   // Target IP
}ARP_Struct;
```

# 2. UDP

![image info](./Image/icmp_frame.png)

# 3. UDP

![image info](./Image/udp_frame.png)

![image info](./Image/frame_udp_cs.png)

# 4. TCP IP

![image info](./Image/tcp_ip_frame.png)

***Source port*** : Số hiệu của cổng tại máy tính gửi

***Destination port*** : Số hiệu của cổng tại máy tính nhận.

***Sequence number*** : Trường này có 2 nhiệm vụ. Nếu cờ SYN bật thì nó là số thứ tự gói ban đầu và byte đầu tiên được gửi có số thứ tự này cộng thêm 1. Nếu không có cờ SYN thì đây là số thứ tự của byte đầu tiên

***Acknowledgement number*** Nếu cờ ACK bật thì giá trị của trường chính là số thứ tự gói tin tiếp theo mà bên nhận cần.

***Data offset*** Trường có độ dài 4 bít quy định độ dài của phần header (tính theo đơn vị từ 32 bít). Phần header có độ dài tối thiểu là 5 từ (160 bit) và tối đa là 15 từ (480 bít).

***Reserved*** Dành cho tương lai và có giá trị là 0

***Flags*** (hay Control bits) : URG ACK PSH RST SYN FIN

***Window*** Số byte có thể nhận bắt đầu từ giá trị của trường báo nhận (ACK)

***Checksum*** : 16 bít kiểm tra cho toàn bộ gói TCP và 1 phần của gói IP

***Urgent pointer*** Nếu cờ URG bật thì giá trị trường này chính là số từ 16 bít mà số thứ tự gói tin (sequence number) cần dịch trái.

***Options*** Đây là trường tùy chọn. Nếu có thì độ dài là bội số của 32 bít.

Dữ liệu Dữ liệu của gói TCP

</span>