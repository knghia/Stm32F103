
#include "w5500_use.h"

#define SS		4
#define RST		3

void W5500_CSL(void){
	HAL_GPIO_WritePin(SPI1_SS_GPIO_Port, SPI1_SS_Pin, GPIO_PIN_RESET);
}

void W5500_CSH(void){
	HAL_GPIO_WritePin(SPI1_SS_GPIO_Port, SPI1_SS_Pin, GPIO_PIN_SET);
}

void W5500_RST_L(void){
	HAL_GPIO_WritePin(RST_GPIO_Port, RST_Pin, GPIO_PIN_RESET);
}

void W5500_RST_H(void){
	HAL_GPIO_WritePin(RST_GPIO_Port, RST_Pin, GPIO_PIN_SET);
}

void W5500_SPI_Write(uint8_t data){
	HAL_SPI_Transmit(&hspi1, &data, 1, 100);
}

u08 W5500_SPI_Read(void){
	uint8_t c = 0;
	HAL_SPI_Receive(&hspi1, &c, 1, 100);
	return c;
}

void W5500_SPI_Write_Buff(u08* pBuf, u16 len){
	HAL_SPI_Transmit(&hspi1, pBuf, len, 100);
}

void W5500_SPI_Read_Buff(u08* pBuf, u16 len){
	HAL_SPI_Receive(&hspi1, pBuf, len, 100);
}

static bool ip_assigned = 0;
static uint8_t buff_size[] = { 2, 2, 2, 2 };

static uint8_t dhcp_buffer[1024];
static uint16_t dhcp_retry = 0;

void W5500_Init(void){
	i08 ret;

	HAL_GPIO_WritePin(RST_GPIO_Port, RST_Pin, GPIO_PIN_RESET);
	HAL_Delay(500);
	HAL_GPIO_WritePin(RST_GPIO_Port, RST_Pin, GPIO_PIN_SET);
	HAL_Delay(500);

	reg_wizchip_cs_cbfunc(W5500_CSL, W5500_CSH);
	reg_wizchip_spi_cbfunc(W5500_SPI_Read, W5500_SPI_Write);
	reg_wizchip_spiburst_cbfunc(W5500_SPI_Read_Buff, W5500_SPI_Write_Buff);

	//check version register
	u08 version = getVERSIONR();
	if(version != 0x04)
	{
		printf("getVERSIONR returns wrong version!\n");
		return;
	}
	//check PHY status
	wiz_PhyConf phyConf;
	wizphy_getphystat(&phyConf);
	printf("PHY conf.by = {%d}, conf.mode={%d}, conf.speed={%d}, conf.duplex={%d}\n",\
		phyConf.by, phyConf.mode, phyConf.speed, phyConf.duplex);
}

