import math

from OpenDroneID.decoder import decode
from OpenDroneID.utils import structhelper_io
import json

class Parser:
    packet = bytearray()

    def __init__(self, packet):
        self.packet = packet

    def _b2b(self, byteval: bytearray) -> list[int]:
        bs = ' '.join(f'{x:08b}' for x in byteval)
        res = [int(bit) for bit in bs]
        res.reverse()
        return res

class Astm_F3411_22a_adv_data:
    msg_type = None
    version = None
    msg_size = None
    msg_count = None

    def __init__(self, data):
        bt = structhelper_io(data)
        self.msg = decode(bt)

    def __repr__(self):
        return self.msg

class Astm_F3411_22a_nan_service_info:
    def __init__(self, data):
        bt = structhelper_io(data)
        self.msg_counter = bt.byte()
        self.msg = decode(bt)

    def __repr__(self):
        return self.msg

class Astm_F3411_22a_nan_desc:
    attribute_id = None
    length = None
    service_id = None
    instance_id = None
    requestor_instance_id = None
    service_control = None
    service_info_length = None
    service_info = None

    def __init__(self, data):
        bt = structhelper_io(data)
        self.attribute_id = bt.byte()
        # 3 = Discovery frame, 0 = Master indication frame
        self.length = bt.short()
        if self.attribute_id == 3:
            self.service_id = bt.bytes(6)
            self.instance_id = bt.byte()
            self.requestor_instance_id = bt.byte()
            self.service_control = bt.byte()
            self.service_info_length = bt.byte()
            self.service_info = Astm_F3411_22a_nan_service_info(bt.read())
            self.msg = {"NAN discovery":self.service_info}
        elif self.attribute_id == 0:
            self.master_performance = bt.byte()
            self.random_factor = bt.byte()
            self.cluster_attribute_id = bt.byte()
            self.anchor_master_info_length = bt.short()
            self.anchor_master_info = bt.bytes(self.anchor_master_info_length)
            self.msg = {"NAN beacon":{"AnchorMasterRank":self.anchor_master_info[:8].hex(),"HopCountToAnchorMaster":self.anchor_master_info[9],"AnchorMasterBeaconTransmissionTime":int.from_bytes(self.anchor_master_info[9:],'little')}}

    def __repr__(self):
        return self.service_info

class Astm_F3411_22a:
    def __init__(self, data):
        bt = structhelper_io(data)
        self.oui = bt.bytes(3)
        self.vend_type = bt.byte()
        if self.vend_type == 0x13: # NAN Packet
            self.nan_service_desc = Astm_F3411_22a_nan_desc(bt.read())
            if self.nan_service_desc is not None:
                if self.nan_service_desc.attribute_id == 3:
                    self.msg = {"OUI": self.oui.hex(), "VendorType": self.vend_type, "MsgCounter": self.msg_counter,
                                "DRI": self.nan_service_desc.msg}
                elif self.nan_service_desc.attribute_id == 0:
                    self.msg = {"OUI": self.oui.hex(), "VendorType": self.vend_type,
                                "Beacon": self.nan_service_desc.msg}
            else:
                self.msg = {}
        elif self.vend_type == 0xD: # Beacon
            self.msg_counter = bt.byte()
            self.adv_data = Astm_F3411_22a_adv_data(bt.read())
            if self.adv_data is not None:
                self.msg={"OUI":self.oui.hex(),"VendorType":self.vend_type,"MsgCounter":self.msg_counter,"DRI":self.adv_data.msg}
            else:
                self.msg = {}

    def __repr__(self):
        return json.dumps(self.msg)


class AstmStandard(Parser):
    def __init__(self, packet):
        super().__init__(packet)
        self.msg = Astm_F3411_22a(self.packet).msg

    def __repr__(self):
        return json.dumps(self.msg)

@staticmethod
def dji_angle(value:int) -> float:
    double_val = float(value / 100)
    if double_val == 0:
        return double_val
    elif (double_val < 0) or (double_val >= 180):
        return double_val + 180
    else:
        return double_val % 180
@staticmethod
def dji_coord(value:int) -> float:
    return round((value * 180) / math.pi / 10 ** 7)

class DJIV1:
    serial_number = b""
    longitude = 0
    latitude = 0
    height = 0
    x_speed = 0
    y_speed = 0
    yaw = 0
    home_longitude = 0
    home_latitude = 0
    uuid = b""
    msg = {}

    def __init__(self, data):
        bt = structhelper_io(data)
        bt.short()
        bt.bytes(2)
        self.serial_number = bt.bytes(16)
        self.longitude = dji_coord(bt.signed_dword())
        self.latitude = dji_coord(bt.signed_dword())
        bt.short()
        self.height = bt.short()
        self.x_speed = bt.signed_short()
        self.y_speed = bt.signed_short()
        bt.signed_short()
        bt.signed_short()
        bt.signed_short()
        self.yaw = dji_angle(bt.signed_short())
        self.home_longitude = dji_coord(bt.signed_dword())
        self.home_latitude = dji_coord(bt.signed_dword())
        bt.byte()
        bt.byte()
        self.uuid = bt.bytes(20)

    def __repr__(self):
        return self.msg

class DJIV2:
    serial_number = b""
    longitude = 0
    latitude = 0
    height = 0
    x_speed = 0
    y_speed = 0
    yaw = 0
    home_longitude = 0
    home_latitude = 0
    pilot_latitude = 0
    pilot_longitude = 0
    uuid = b""
    msg = {}

    def __init__(self, data):
        bt = structhelper_io(data)
        bt.short()
        bt.bytes(2)
        self.serial_number = bt.bytes(16)
        self.longitude = dji_coord(bt.signed_dword())
        self.latitude = dji_coord(bt.signed_dword())
        bt.short()
        self.height = bt.short()
        self.x_speed = bt.signed_short()
        self.y_speed = bt.signed_short()
        bt.signed_short()
        self.yaw = dji_angle(bt.signed_short())
        bt.qword()
        self.pilot_latitude = dji_coord(bt.signed_dword())
        self.pilot_longitude = dji_coord(bt.signed_dword())
        self.home_longitude = dji_coord(bt.signed_dword())
        self.home_latitude = dji_coord(bt.signed_dword())
        bt.byte()
        bt.byte()
        self.uuid = bt.bytes(20)

    def __repr__(self):
        return self.msg


class DJIMsg:
    def __init__(self, data):
        """
        _version_1_format: str = '<H2s16siiHHhhhhhhiiBB20s'
        protocol_v1: int = 1

        _version_2_format: str = '<H2s16siiHHhhhhQiiiiBB20s'
        protocol_v2: int = 2

        _version_2_lte_format = _version_2_format + 'H'
        lte_max_len = 89
        """
        bt = structhelper_io(data)
        self.oui = bt.bytes(3)
        self.vend_type = bt.bytes(4)
        self.version = bt.byte()
        if self.version == 1:
            self.adv_data = DJIV1(bt.read())
        elif self.version == 2:
            self.adv_data = DJIV2(bt.read())
        self.msg={"OUI":self.oui.hex(),"VendorType":self.vend_type,"DRI":self.adv_data.msg}

    def __repr__(self):
        return json.dumps(self.msg)


class DJI(Parser):
    def __init__(self, packet):
        super().__init__(packet)
        self.msg = DJIMsg(self.packet).msg

    def __repr__(self):
        return json.dumps(self.msg)


def oui_to_parser(oui, packet):
    if oui in [0x506f9a, 0x903ae6, 0xfa0bbc]:
        return AstmStandard(packet)
    elif oui in [0x60601F,0x481CB9, 0x34D262]:
        return DJI(packet)
