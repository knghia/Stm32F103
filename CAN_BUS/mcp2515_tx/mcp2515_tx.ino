
#include <SPI.h>
#include <mcp2515.h>

struct can_frame canMsg;
MCP2515 mcp2515(10);

void setup(){
  while (!Serial);
  Serial.begin(9600);
  SPI.begin();

  mcp2515.reset();
  mcp2515.setBitrate(CAN_500KBPS, MCP_8MHZ);
  mcp2515.setNormalMode();

  canMsg.can_id  = 0x036;
  canMsg.can_dlc = 8;
  canMsg.data[0] = 30;
  canMsg.data[1] = 40;
  canMsg.data[2] = 0x00;
  canMsg.data[3] = 0x00;
  canMsg.data[4] = 0x00;
  canMsg.data[5] = 0x00;
  canMsg.data[6] = 0x00;
  canMsg.data[7] = 0x00;
}

void loop(){
  mcp2515.sendMessage(&canMsg);
  delay(500);
}
