
#include "w5500_use.h"

#define DEFAULT_MAC_ADDR    {0x08,0x10,0x19,0x97,0x25,0x25}
#define DEFAULT_IP_ADDR     {192,168,137,10}
#define DEFAULT_SUB_MASK    {255,255,255,0}
#define DEFAULT_GW_ADDR     {192,168,0,1}
#define DEFAULT_DNS_ADDR    {8,8,8,8}

#define SS		4
#define RST		3

void w5500_cs_select(void){
	HAL_GPIO_WritePin(SPI1_SS_GPIO_Port, SPI1_SS_Pin, GPIO_PIN_RESET);
}

void w5500_cs_deselect(void){
	HAL_GPIO_WritePin(SPI1_SS_GPIO_Port, SPI1_SS_Pin, GPIO_PIN_SET);
}

void w5500_spi_writebyte(uint8_t data){
	HAL_SPI_Transmit(&hspi1, &data, 1, 100);
}

u08 w5500_spi_readbyte(void){
	uint8_t c = 0;
	HAL_SPI_Receive(&hspi1, &c, 1, 100);
	return c;
}

void w5500_spi_writeburst(u08* pBuf, u16 len){
	HAL_SPI_Transmit(&hspi1, pBuf, len, 100);
}

void w5500_spi_readburst(u08* pBuf, u16 len){
	HAL_SPI_Receive(&hspi1, pBuf, len, 100);
}

void w5500_phy_init(void){
	wiz_PhyConf conf;
	conf.by = PHY_CONFBY_SW;
	conf.mode = PHY_MODE_MANUAL;
	conf.speed = PHY_SPEED_100;
	conf.duplex = PHY_DUPLEX_FULL;
	wizphy_setphyconf(&conf);
}

void w5500_network_info_init(void){
    wiz_NetInfo info;
    
    uint8_t mac[6] = DEFAULT_MAC_ADDR;
    uint8_t ip[4] = DEFAULT_IP_ADDR;
    uint8_t sn[4] = DEFAULT_SUB_MASK;
    uint8_t gw[4] = DEFAULT_GW_ADDR;
    uint8_t dns[4] = DEFAULT_DNS_ADDR;
    
    memcpy(info.mac, mac, 6);
    memcpy(info.ip, ip, 4);
    memcpy(info.sn, sn, 4);
    memcpy(info.gw, gw, 4);
    memcpy(info.dns, dns, 4);
    info.dhcp = NETINFO_DHCP;
    wizchip_setnetinfo(&info);
}

void w5500_network_info_show(void){
    wiz_NetInfo info;
    wizchip_getnetinfo(&info);
    printf("w5500 network infomation:\r\n");
    printf("  -mac:%d:%d:%d:%d:%d:%d\r\n", info.mac[0], info.mac[1], info.mac[2], 
            info.mac[3], info.mac[4], info.mac[5]);
    printf("  -ip:%d.%d.%d.%d\r\n", info.ip[0], info.ip[1], info.ip[2], info.ip[3]);
    printf("  -sn:%d.%d.%d.%d\r\n", info.sn[0], info.sn[1], info.sn[2], info.sn[3]);
    printf("  -gw:%d.%d.%d.%d\r\n", info.gw[0], info.gw[1], info.gw[2], info.gw[3]);
    printf("  -dns:%d.%d.%d.%d\r\n", info.dns[0], info.dns[1], info.dns[2], info.dns[3]);

    printf("  -dhcp_mode: dhcp\r\n");
}

int W5500_Init(void){
	/* W5500 hard reset */
	HAL_GPIO_WritePin(RST_GPIO_Port, RST_Pin, GPIO_PIN_RESET);
	HAL_Delay(500);
	HAL_GPIO_WritePin(RST_GPIO_Port, RST_Pin, GPIO_PIN_SET);
	HAL_Delay(500);
	/* Register spi driver function */
    reg_wizchip_cs_cbfunc(w5500_cs_select, w5500_cs_deselect);
    reg_wizchip_spi_cbfunc(w5500_spi_readbyte, w5500_spi_writebyte);
    reg_wizchip_spiburst_cbfunc(w5500_spi_readburst, w5500_spi_writeburst);
	/* socket buffer size init */
	if(wizchip_init(NULL, NULL) != 0){
		return -1;
	}
    /* phy init */
    w5500_phy_init();
    /* network infomation init */
    w5500_network_info_init();
    /* show network infomation */
    w5500_network_info_show();
	return 0;
}
