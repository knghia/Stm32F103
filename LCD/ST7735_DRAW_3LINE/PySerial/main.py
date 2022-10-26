
import time
import serial
import numpy as np

try:
    connect = serial.Serial(port="COM9", baudrate=115200,timeout=0.1)
except serial.SerialException as error:
    print ("error : ",error)

x = [0,60,20, 50, 50]

while(1):
    x[0]+=1
    if x[0]> 60:
        x[0] = 0

    x[1]+=2
    if x[1]> 60:
        x[1] = 20

    x[2]+=4
    if x[2]> 60:
        x[2] = 20

    x[3]+=1
    if x[3]> 60:
        x[3] = 20


    data = ":{:02x}{:02x}{:02x}{:04x}{:04x}\r\n".format(*x)
    print(data)
    connect.write(data.encode())
    time.sleep(0.2)