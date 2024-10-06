from io import BytesIO


class structhelper_io:
    pos = 0

    def __init__(self, data: bytes = None, direction='little'):
        self.data = BytesIO(bytearray(data))
        self.direction = direction

    def setdata(self, data, offset=0):
        self.pos = offset
        self.data = data

    def split_4bit(self, direction=None):
        tmp = self.data.read(1)[0]
        return (tmp >> 4) & 0xF, tmp & 0xF

    def qword(self, direction=None):
        if direction is None:
            direction = self.direction
        dat = int.from_bytes(self.data.read(8), direction)
        return dat

    def signed_qword(self, direction=None):
        if direction is None:
            direction = self.direction
        dat = int.from_bytes(self.data.read(8), direction, signed=True)
        return dat

    def dword(self, direction=None):
        if direction is None:
            direction = self.direction
        dat = int.from_bytes(self.data.read(4), direction)
        return dat

    def signed_dword(self, direction=None):
        if direction is None:
            direction = self.direction
        dat = int.from_bytes(self.data.read(4), direction, signed=True)
        return dat

    def dwords(self, dwords=1, direction=None):
        if direction is None:
            direction = self.direction
        dat = [int.from_bytes(self.data.read(4), direction) for _ in range(dwords)]
        return dat

    def short(self, direction=None):
        if direction is None:
            direction = self.direction
        dat = int.from_bytes(self.data.read(2), direction)
        return dat

    def signed_short(self, direction=None):
        if direction is None:
            direction = self.direction
        dat = int.from_bytes(self.data.read(2), direction, signed=True)
        return dat

    def shorts(self, shorts, direction=None):
        if direction is None:
            direction = self.direction
        dat = [int.from_bytes(self.data.read(2), direction) for _ in range(shorts)]
        return dat

    def byte(self):
        dat = self.data.read(1)[0]
        return dat
    def read(self, length=0):
        if length==0:
            return self.data.read()
        return self.data.read(length)
    def bytes(self, rlen=1):
        dat = self.data.read(rlen)
        if dat == b'':
            return dat
        if rlen == 1:
            return dat[0]
        return dat

    def signed_bytes(self, rlen=1):
        dat = [int.from_bytes(self.data.read(1),'little', signed=True) for _ in range(rlen)]
        if dat == b'':
            return dat
        if rlen == 1:
            return dat[0]
        return dat

    def string(self, rlen=1):
        dat = self.data.read(rlen)
        return dat

    def getpos(self):
        return self.data.tell()

    def seek(self, pos):
        self.data.seek(pos)


def char2cp(value):
    if 0x30<=value<=0x39:
        return value-0x30
    elif 0x61 <= value <= 0x7A:
        return (value-0x61)+10
    elif 0x41 <= value <= 0x5A:
        return (value-0x41)+10
def luhn36(msg):
    sum = 0
    for i in range(len(msg)):
        tmp = char2cp(ord(msg[i]))
        if ((i+1) % 2) != 0:
            tmp*=2
        adv = tmp // 36
        if adv != 0:
            value = adv + tmp%36
        else:
            value = tmp%36
        sum+=value
    checksum = 36 - (sum % 36)
    return checksum

if __name__ == "__main__":
    # FIN87astrdge12k8
    if luhn36("87astrdge12kxyz")==8:
        print("Luhn36 OK")