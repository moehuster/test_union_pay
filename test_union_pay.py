# -*- coding: utf-8 -*-
'''
银联支付接口测试程序
'''

import socket
import struct
from datetime import datetime
from binascii import hexlify
from binascii import unhexlify
from functools import reduce
import pydes
import py8583
import py8583spec


HOST = '202.101.25.188'
PORT = 20140


def parse_package(data):
    """ 银联8583报文解析 """
    if len(data) <= 2:
        return
    data_len = struct.unpack_from("!H", data[:2])[0]
    if data_len != len(data) - 2:
        print("Invalid length {0} - {1}".format(data_len, len(data) - 2))
    else:
        iso_packet = py8583.Iso8583(IsoMsg=data[2:], IsoSpec=py8583spec.IsoSpec1987BCD())
        iso_packet.PrintMessage()


def calc_pinblock(**kw):
    """ 计算PinBlock """
    tmk = kw.get("TMK", "159D86C7C1F779EA29F77A6858E0DA2A")
    pik = kw.get("PIK", "75CAD854C2E59A5EEDD7CA7410C2C215")
    pan = kw.get("PAN", "6212142000000000012")
    passwd = kw.get("passwd", "123456")
    des3 = pydes.triple_des(unhexlify(tmk))
    pinkey = des3.decrypt(unhexlify(pik))
    des3 = pydes.triple_des(pinkey)
    pinblock = unhexlify(('06'+passwd).ljust(16, 'F'))
    customer_data = unhexlify('0000'+pan[-13:-1])
    plain_pin = list(map(lambda x, y: x ^ y, pinblock, customer_data))
    return hexlify(des3.encrypt(plain_pin)).decode('latin1').upper()


def calc_mac_ecb(**kw):
    """ 计算报文MAC值(ECB算法) """
    tmk = kw.get("TMK", "159D86C7C1F779EA29F77A6858E0DA2A")
    mak = kw.get("MAK", "E6218EF29513B143")
    mab = kw.get("MAB", None)
    mab += ''.rjust(8-len(mab) % 8, '\x00').encode('latin1')
    mab = reduce(lambda x, y: bytes(list(map(lambda a, b: a ^ b, x, y))),
                 [mab[i:i+8] for i in range(0, len(mab), 8)])
    des3 = pydes.triple_des(unhexlify(tmk))
    mackey = des3.decrypt(unhexlify(mak))
    des = pydes.des(mackey)
    ret = des.encrypt(hexlify(mab[:4]).upper())
    ret = bytes(list(map(lambda x, y: x ^ y, ret, hexlify(mab[4:]).upper())))
    ret = des.encrypt(ret)
    return hexlify(hexlify(ret[:4]).upper()).decode('latin1')


def calc_mac_cbc(**kw):
    """ 计算报文MAC值(CBC算法) """
    tmk = kw.get("TMK", "159D86C7C1F779EA29F77A6858E0DA2A")
    mak = kw.get("MAK", "E6218EF29513B143")
    vec = kw.get("IV", "\x00\x00\x00\x00\x00\x00\x00\x00")
    mab = kw.get("MAB", None)
    vec = vec.encode('latin1')
    mab += ''.rjust(8-len(mab) % 8, '\x00').encode('latin1')
    des3 = pydes.triple_des(unhexlify(tmk))
    mackey = des3.decrypt(unhexlify(mak))
    des = pydes.des(mackey)
    for i in range(0, len(mab), 8):
        vec = bytes(list(map(lambda a, b: a ^ b, vec, mab[i:i+8])))
        vec = des.encrypt(vec)
    return hexlify(vec).upper().decode('latin1')


def terminal_checkin(**kw):
    """ 设备终端签到 """
    now = datetime.now()
    req_packet = py8583.Iso8583(IsoSpec=py8583spec.IsoSpec1987BCD())
    req_packet.MTI('0800')
    req_packet.TPDU('6005810000')
    req_packet.HEADER('603100000000')
    req_packet.FieldData(11, int(now.strftime('%H%M%S'))) # 终端流水
    req_packet.FieldData(41, kw.get('TerminalNo', '52010009')) # 终端代码
    req_packet.FieldData(42, kw.get('MerchantNo', '898520154110004')) # 商户代码
    req_packet.FieldData(60, now.strftime('00%y%m%d003'))
    print("设备终端签到:")
    req_packet.PrintMessage()
    data = req_packet.BuildIso()
    data = struct.pack('!H', len(data)) + data
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))
    py8583.MemDump("Sending: ", data)
    sock.send(data)
    data = sock.recv(4096)
    py8583.MemDump('Received: ', data)
    sock.close()
    parse_package(data)


def balance_query(**kw):
    """ 账户余额查询 """
    now = datetime.now()
    req_packet = py8583.Iso8583(IsoSpec=py8583spec.IsoSpec1987BCD())
    req_packet.MTI('0200')
    req_packet.TPDU('6005810000')
    req_packet.HEADER('603100000000')
    req_packet.FieldData(2, kw.get('PAN', '6212142000000000012')) # 主账号
    req_packet.FieldData(3, '300000') # 交易处理码
    req_packet.FieldData(11, now.strftime('%H%M%S')) # 终端交易流水
    req_packet.FieldData(14, '2912') # 卡有效期
    req_packet.FieldData(22, '051') # 服务点输入方式
    req_packet.FieldData(23, kw.get('CardOrder', '000')) # 卡序列号
    req_packet.FieldData(25, '00') # 服务点条件码
    req_packet.FieldData(26, '06') # 服务点PIN获取码
    req_packet.FieldData(35, kw.get('Track2', '6212142000000000012=29122206899031006')) # 二磁道数据
    req_packet.FieldData(36, kw.get('Track3', None)) # 三磁道数据
    req_packet.FieldData(41, kw.get('TerminalNo', '52010009')) # 终端代码
    req_packet.FieldData(42, kw.get('MerchantNo', '898520154110004')) # 商户代码
    req_packet.FieldData(49, '156') # 交易货币代码
    req_packet.FieldData(52, kw.get('PinBlock', None)) # 个人标识码数据
    req_packet.FieldData(53, '2600000000000000') # 安全控制信息
    req_packet.FieldData(55, kw.get('ICData', None)) # IC卡数据域
    req_packet.FieldData(60, now.strftime('01%y%m%d00000060'))
    req_packet.FieldData(64, '0000000000000000')
    req_packet.FieldData(64, calc_mac_cbc(MAB=req_packet.BuildIso()[11:-8]))  # 报文鉴别码
    print("账户余额查询:")
    req_packet.PrintMessage()
    data = req_packet.BuildIso()
    data = struct.pack('!H', len(data)) + data
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))
    py8583.MemDump("Sending: ", data)
    sock.send(data)
    data = sock.recv(4096)
    py8583.MemDump('Received: ', data)
    sock.close()
    parse_package(data)


def balance_payment(**kw):
    """ 缴费 """
    now = datetime.now()
    req_packet = py8583.Iso8583(IsoSpec=py8583spec.IsoSpec1987BCD())
    req_packet.MTI('0200')
    req_packet.TPDU('6005810000')
    req_packet.HEADER('603100000000')
    req_packet.FieldData(2, kw.get('PAN', '6212142000000000012')) # 主账号
    req_packet.FieldData(3, '190000') # 交易处理码
    req_packet.FieldData(4, kw.get('amount', '3').rjust(12, '0')) # 交易金额
    req_packet.FieldData(11, now.strftime('%H%M%S')) # 终端交易流水
    req_packet.FieldData(14, '2912') # 卡有效期
    req_packet.FieldData(22, '051') # 服务点输入方式
    req_packet.FieldData(23, kw.get('CardOrder', '000')) # 卡序列号
    req_packet.FieldData(25, '81') # 服务点条件码
    req_packet.FieldData(26, '06') # 服务点PIN获取码
    req_packet.FieldData(35, kw.get('Track2', '6212142000000000012=29122206899031006')) # 二磁道数据
    req_packet.FieldData(36, kw.get('Track3', None)) # 三磁道数据
    req_packet.FieldData(41, kw.get('TerminalNo', '52010009')) # 终端代码
    req_packet.FieldData(42, kw.get('MerchantNo', '898520154110004')) # 商户代码
    req_packet.FieldData(48, 'KP77SG0C26323520140909356184                70000000201809#') # 行业特定信息
    req_packet.FieldData(49, '156') # 交易货币代码
    req_packet.FieldData(52, kw.get('PinBlock', None)) # 个人标识码数据
    req_packet.FieldData(53, '2600000000000000') # 安全控制信息
    req_packet.FieldData(55, kw.get('ICData', None)) # IC卡数据域
    req_packet.FieldData(60, now.strftime('22%y%m%d00000060'))
    req_packet.FieldData(64, '0000000000000000')
    req_packet.FieldData(64, calc_mac_cbc(MAB=req_packet.BuildIso()[11:-8]))  # 报文鉴别码
    print("缴费: ")
    req_packet.PrintMessage()
    data = req_packet.BuildIso()
    data = struct.pack('!H', len(data)) + data
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))
    py8583.MemDump("Sending: ", data)
    sock.send(data)
    data = sock.recv(4096)
    py8583.MemDump('Received: ', data)
    sock.close()
    parse_package(data)


def payment_revoke(**kw):
    """ 缴费撤销 """
    now = datetime.now()
    req_packet = py8583.Iso8583(IsoSpec=py8583spec.IsoSpec1987BCD())
    req_packet.MTI('0200')
    req_packet.TPDU('6005810000')
    req_packet.HEADER('603100000000')
    req_packet.FieldData(2, kw.get('PAN', '6212142000000000012')) # 主账号
    req_packet.FieldData(3, '280000') # 交易处理码
    req_packet.FieldData(4, kw.get('amount', '1').rjust(12, '0')) # 交易金额
    req_packet.FieldData(11, now.strftime('%H%M%S')) # 终端交易流水
    req_packet.FieldData(14, '2912') # 卡有效期
    req_packet.FieldData(22, '051') # 服务点输入方式
    req_packet.FieldData(23, kw.get('CardOrder', '000')) # 卡序列号
    req_packet.FieldData(25, '81') # 服务点条件码
    req_packet.FieldData(26, '06') # 服务点PIN获取码
    req_packet.FieldData(35, kw.get('Track2', '6212142000000000012=29122206899031006')) # 二磁道数据
    req_packet.FieldData(36, kw.get('Track3', None)) # 三磁道数据
    req_packet.FieldData(37, kw.get('ReferNo', None)) # 原交易参考号
    req_packet.FieldData(38, kw.get('AuthNo', None)) # 原交易授权码
    req_packet.FieldData(41, kw.get('TerminalNo', '52010009')) # 终端代码
    req_packet.FieldData(42, kw.get('MerchantNo', '898520154110004')) # 商户代码
    req_packet.FieldData(48, 'KP77SG0C26323520140909356184                70000000201809#') # 行业特定信息
    req_packet.FieldData(49, '156') # 交易货币代码
    req_packet.FieldData(52, kw.get('PinBlock', None)) # 个人标识码数据
    req_packet.FieldData(53, '2600000000000000') # 安全控制信息
    req_packet.FieldData(60, now.strftime('22%y%m%d00000060'))
    req_packet.FieldData(61, kw.get('Field61', None)) # 原始交易信息
    req_packet.FieldData(64, '0000000000000000')
    req_packet.FieldData(64, calc_mac_cbc(MAB=req_packet.BuildIso()[11:-8]))  # 报文鉴别码
    print("缴费撤销: ")
    req_packet.PrintMessage()
    data = req_packet.BuildIso()
    data = struct.pack('!H', len(data)) + data
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))
    py8583.MemDump("Sending: ", data)
    sock.send(data)
    data = sock.recv(4096)
    py8583.MemDump('Received: ', data)
    sock.close()
    parse_package(data)


def payment_reversal(**kw):
    """ 冲正交易 """
    req_packet = py8583.Iso8583(IsoSpec=py8583spec.IsoSpec1987BCD())
    req_packet.MTI('0400')
    req_packet.TPDU('6005810000')
    req_packet.HEADER('603100000000')
    req_packet.FieldData(3, '190000') # 交易处理码
    req_packet.FieldData(4, kw.get('amount', '1').rjust(12, '0')) # 交易金额
    req_packet.FieldData(11, kw.get('TraceNo', None)) # 原交易流水
    req_packet.FieldData(14, '2912') # 卡有效期
    req_packet.FieldData(22, '051') # 服务点输入方式
    req_packet.FieldData(23, kw.get('CardOrder', '000')) # 卡序列号
    req_packet.FieldData(25, '81') # 服务点条件码
    req_packet.FieldData(35, kw.get('Track2', '6212142000000000012=29122206899031006')) # 二磁道数据
    req_packet.FieldData(36, kw.get('Track3', None)) # 三磁道数据
    req_packet.FieldData(38, kw.get('AuthNo', None)) # 原交易授权码
    req_packet.FieldData(39, '96') # 冲正原因
    req_packet.FieldData(41, kw.get('TerminalNo', '52010009')) # 终端代码
    req_packet.FieldData(42, kw.get('MerchantNo', '898520154110004')) # 商户代码
    req_packet.FieldData(48, 'KP77SG0C26323520140909356184                70000000201809#') #行业特定信息
    req_packet.FieldData(49, '156') # 交易货币代码
    req_packet.FieldData(55, kw.get('ICData', None)) # IC卡数据域
    req_packet.FieldData(60, kw.get('Field60', None))
    req_packet.FieldData(61, kw.get('Field61', None)) # 原始交易信息
    req_packet.FieldData(64, '0000000000000000')
    req_packet.FieldData(64, calc_mac_cbc(MAB=req_packet.BuildIso()[11:-8]))  # 报文鉴别码
    print("冲正交易: ")
    req_packet.PrintMessage()
    data = req_packet.BuildIso()
    data = struct.pack('!H', len(data)) + data
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))
    py8583.MemDump("Sending: ", data)
    sock.send(data)
    data = sock.recv(4096)
    py8583.MemDump('Received: ', data)
    sock.close()
    parse_package(data)


def profession_query(**kw):
    """ 行业信息查询 """
    now = datetime.now()
    req_packet = py8583.Iso8583(IsoSpec=py8583spec.IsoSpec1987BCD())
    req_packet.MTI('0100')
    req_packet.TPDU('6005810000')
    req_packet.HEADER('603100000000')
    req_packet.FieldData(3, '310000') # 交易处理码
    req_packet.FieldData(11, now.strftime('%H%M%S')) # 终端交易流水
    req_packet.FieldData(25, '87') # 服务点条件码
    req_packet.FieldData(41, kw.get('TerminalNo', '52010009')) # 终端代码
    req_packet.FieldData(42, kw.get('MerchantNo', '898520154110004')) # 商户代码
    req_packet.FieldData(48, kw.get('OrgCode', None)) #行业特定信息
    req_packet.FieldData(64, '0000000000000000')
    req_packet.FieldData(64, calc_mac_cbc(MAB=req_packet.BuildIso()[11:-8]))  # 报文鉴别码
    print("行业信息查询: ")
    req_packet.PrintMessage()
    data = req_packet.BuildIso()
    data = struct.pack('!H', len(data)) + data
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))
    py8583.MemDump("Sending: ", data)
    sock.send(data)
    data = sock.recv(4096)
    py8583.MemDump('Received: ', data)
    sock.close()
    parse_package(data)


if __name__ == '__main__':
    #terminal_checkin(TerminalNo='52010009')
    #balance_query(PinBlock=calc_pinblock(), ICData='9F2608BD23789651C50E119F2701809F101307010103A0A804010A010000045796F2D315039F3704A1DD65379F36020FFE950580800460009A031811139C01309F02060000000000005F2A02015682027C009F1A0201569F03060000000000009F3303604800')
    #balance_payment(PinBlock=calc_pinblock(), ICData='9F2608BD23789651C50E119F2701809F101307010103A0A804010A010000045796F2D315039F3704A1DD65379F36020FFE950580800460009A031811139C01309F02060000000000005F2A02015682027C009F1A0201569F03060000000000009F3303604800')
    #payment_reversal(amount='1', TraceNo='160310', AuthNo=None, Field60='2218111400000060', Field61='1811141603101114000000000000002000')
    payment_revoke(amount='3', ReferNo='204304908107', AuthNo=None, Field61='1811142043021114000000000000002000')
