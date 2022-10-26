
R = 0x74
G = 0x6D
B = 0x67

# 746D67

B = (B >> 3) & 0x1f
G = ((G >> 2) & 0x3f) << 5
R = ((R >> 3) & 0x1f) << 11
color565 = (B | G | R)

s = "0x{:02X}{:02X}".format(int(color565/256), color565%256)
print(s)