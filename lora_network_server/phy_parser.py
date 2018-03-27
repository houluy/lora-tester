import math
import time
import base64
import json
from Crypto.Cipher import AES
from Crypto.Hash import CMAC
from Crypto.Util import Padding


class BytesOperation:
    @staticmethod
    def str_rev(obj_str):
        return ''.join([
            obj_str[x:x+2] for x in range(len(obj_str))
        ][-2::-2])

    @staticmethod
    def bytes_xor(bytea, byteb):
        return [bytearray.fromhex(
            '{:0>2x}'.format(x ^ y)) for (x, y) in zip(bytea, byteb)
        ]


class GatewayOp(BytesOperation):
    '''
    Gateway from Semtech
    '''
    def __init__(self, gateway_id):
        self.gateway_id = gateway_id
        self._call = {
            'pull': self.pull_data,
            'push': self.push_data,
        }
        self._gateway_attributes = [
            'version',
            'token',
            'identifier',
        ]

    @property
    def gateway_attributes(self):
        return self._gateway_attributes

    def _form_gateway_data(self, data):
        data = self._b64data(data)
        return json.dumps({
            "stat": {
                "time": str(time.time()),
                "rxnb": 1,
                "rxok": 0,
                "rxfw": 0,
                "ackr": 100,
                "dwnb": 0,
                "txnb": 0,
            },
            "rxpk": [{
                "tmst": 854980284,
                "chan": 7,
                "rfch": 0,
                "freq": 435.9,
                "stat": 1,
                "modu": 'LORA',
                "datr": 'SF12BW125',
                "codr": '4/5',
                "lsnr": 2,
                "rssi": -119,
                "size": 17,
                "data": data,
            }],
        }).encode('ascii')

    def _b64data(self, data):
        return base64.b64encode(bytearray.fromhex(data)).decode()

    def pull_data(self, version='02', token='83ec', identifier='02'):
        self.data_dict = {
            'version': version,
            'token': token,
            'identifier': identifier,
            'gateway_id': self.gateway_id,
        }
        self.bytes_str = (
            '{version}'
            '{token}'
            '{identifier}'
            '{gateway_id}'.format(**self.data_dict)
        )
        return bytearray.fromhex(self.bytes_str)

    def push_data(self, data, version='02', token='83ec', identifier='00'):
        data_bytes = self._form_gateway_data(data)
        self.data_dict = {
            'version': version,
            'token': token,
            'identifier': identifier,
            'gateway_id': self.gateway_id,
            'json_obj': data_bytes.hex(),
        }
        self.bytes_str = (
            '{version}'
            '{token}'
            '{identifier}'
            '{gateway_id}'
            '{json_obj}'.format(**self.data_dict)
        )
        return bytearray.fromhex(self.bytes_str)


class DeviceOp(BytesOperation):
    def __init__(self):
        self._attributes = [
            'DevAddr',
            'MHDR',
            'FCnt',
            'FPort',
            'FRMPayload',
            'FCtrl',
            'direction',
            'FOpts',
        ]
        self._join_attributes = [
            'AppEUI',
            'DevEUI',
            'DevNonce',
            'MHDR',
        ]
        self.FHDR_list = [
            'DevAddr',
            'FCtrl',
            'FCnt',
            'FOpts',
        ]

    @property
    def attributes(self):
        return self._attributes

    @property
    def join_attributes(self):
        return self._join_attributes

    @staticmethod
    def form_FHDR(DevAddr, FCtrl, FCnt, FOpts=''):
        DevAddr = DeviceOp.str_rev(DevAddr)
        if len(FCnt) == 8:
            FCnt = FCnt[4:]
        FCnt = DeviceOp.str_rev(FCnt)
        FOpts = DeviceOp.str_rev(FOpts)
        return '{}{}{}{}'.format(DevAddr, FCtrl, FCnt, FOpts)

    @staticmethod
    def _base_block(**kwargs):
        kwargs['DevAddr'] = DeviceOp.str_rev(kwargs.get('DevAddr'))
        kwargs['FCnt'] = DeviceOp.str_rev(kwargs.get('FCnt'))
        return '00000000{direction}{DevAddr}{FCnt}00'.format(**kwargs)

    @staticmethod
    def _B0(**kwargs):
        base_block = DeviceOp._base_block(**kwargs)
        return '49{base_block}{msg_length}'.format(
            base_block=base_block,
            msg_length=kwargs.get('msg_length')
        )

    @staticmethod
    def _A(**kwargs):
        base_block = DeviceOp._base_block(**kwargs)
        return '01{base_block}{i}'.format(
            base_block=base_block,
            i=kwargs.get('i')
        )

    @staticmethod
    def cal_mic(key, typ='normal', **kwargs):
        if typ == 'normal':
            msg = '{MHDR}{FHDR}{FPort}{FRMPayload}'.format(**kwargs)
            msg_bytes = bytearray.fromhex(msg)
            msg_length = '{:0>2x}'.format(len(msg_bytes))
            B0 = DeviceOp._B0(msg_length=msg_length, **kwargs)
            obj_msg = B0 + msg
            obj_msg = bytearray.fromhex(obj_msg)
        else:
            msg = '{MHDR}{AppEUI}{DevEUI}{DevNonce}'.format(**kwargs)
            obj_msg = bytearray.fromhex(msg)
        cobj = CMAC.new(key, ciphermod=AES)
        cobj.update(obj_msg)
        return cobj.hexdigest()[:8]

    @staticmethod
    def encrypt(key, **kwargs):
        payload = kwargs.get('FRMPayload').encode()
        pld_len = len(payload) // 2
        payload = Padding.pad(payload, 16)
        k = math.ceil(pld_len / 16)
        cryptor = AES.new(key, AES.MODE_ECB)
        S = b''
        for i in range(1, k + 1):
            kwargs['i'] = '{:0>2x}'.format(i)
            _A_each = DeviceOp._A(**kwargs)
            Ai = bytearray.fromhex(_A_each)
            Si = cryptor.encrypt(Ai)
            S += Si
        return b''.join(DeviceOp.bytes_xor(S, payload))[:pld_len * 2 + 1]

    def form_join(self, key, **kwargs):
        AppEUI = DeviceOp.str_rev(kwargs.get('AppEUI'))
        DevEUI = DeviceOp.str_rev(kwargs.get('DevEUI'))
        DevNonce = DeviceOp.str_rev(kwargs.get('DevNonce'))
        MIC = DeviceOp.cal_mic(
            key=key,
            typ='join',
            AppEUI=AppEUI,
            DevEUI=DevEUI,
            DevNonce=DevNonce,
            MHDR=kwargs.get('MHDR')
        )
        return ''.join([
            kwargs.get('MHDR'),
            AppEUI,
            DevEUI,
            DevNonce,
            MIC
        ])

    def form_payload(self, NwkSKey, AppSKey, **kwargs):
        if kwargs.get('FRMPayload'):
            FRMPayload = DeviceOp.encrypt(key=AppSKey, **kwargs).hex()
        else:
            FRMPayload = ''
        if not kwargs.get('FHDR'):
            FHDR = DeviceOp.form_FHDR(
                **{k: kwargs.get(k) for k in self.FHDR_list}
            )
        else:
            FHDR = kwargs.get('FHDR')
        kwargs['FRMPayload'] = FRMPayload
        kwargs['FHDR'] = FHDR
        MIC = DeviceOp.cal_mic(key=NwkSKey, **kwargs)
        return ''.join([
            kwargs.get('MHDR'),
            kwargs.get('FHDR'),
            kwargs.get('FPort'),
            FRMPayload,
            MIC
        ])


if __name__ == '__main__':
    DevAddr = 'ABCDEF12'
    direction = '00'
    FCnt = '000000FF'
    FCnt_low = FCnt[-4:]
    payload = 'hello'
    FPort = '02'
    MHDR = '80'
    FCtrl = '00'
    key = bytearray.fromhex('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF')
    device = DeviceOp()
    FHDR = device.form_FHDR(DevAddr=DevAddr, FCtrl=FCtrl, FCnt=FCnt_low)
    kwargs = {
        'DevAddr': DevAddr,
        'FCnt': FCnt,
        'FHDR': FHDR,
        'MHDR': MHDR,
        'FPort': FPort,
        'direction': direction,
        'FCtrl': FCtrl,
        'FRMPayload': payload,
    }
    mic = device.cal_mic(key=key, **kwargs)
    enc_msg = device.encrypt(key=key, **kwargs)
    macpayload = device.form_payload(key=key, **kwargs)
