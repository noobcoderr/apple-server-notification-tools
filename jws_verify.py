# -*- coding: UTF-8 -*-
"""
@Description: 苹果服务端通知v2的处理逻辑
@Project ：apple-subsciption-tools 
@File    ：jws_verify.py
@IDE     ：PyCharm 
@Author  ：noobcoderr
@Date    ：2023/4/13 21:42 
"""
import base64
import json
from OpenSSL import crypto
import jwt


class AppleIapTools(object):

    @classmethod
    def verify_jws(cls, jws):
        """
        验证jws格式回调的签名。
        jws格式: header.payload.signature
        header: {'alg': "ES256", 'x5c':['服务器证书','中间证书','根证书']}
        验证步骤:
        1、验证证书链的有效性。使用苹果根证书对x5c内的根证书进行验证；再使用x5c内的根证书对中间证书进行验证;最后使用中间证书对服务器证书进行验证，完成证书链的验证
        2、使用有效证书验证签名。使用header内指定的alg算法和x5c内的服务器证书对signature进行验证，确保body未被篡改
        以上2步完成即可保证回传的数据是可信未且被篡改的
        :param jws:
        :return:
        """
        jws_lst = jws.split(".")
        if len(jws_lst) != 3:
            return {}, "jws format error"
        header, payload, signature = jws_lst
        header = cls.decode_base64_data(header)
        if not header:
            return {}, "header format error"

        alg = header.get("alg")
        x5c = header.get("x5c")

        # 先验证x5c证书链
        err = cls.verify_apple_jws_cert_chain(x5c)
        if err:
            return {}, "verify cert chain fail {}".format(err)

        # 再校验jws签名
        # 先解析出x5c内服务器证书的公钥
        server_cert = x5c[0]
        try:
            cert = "-----BEGIN CERTIFICATE-----\n" + server_cert + "\n-----END CERTIFICATE-----"
            server_cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
            public_key = crypto.dump_publickey(crypto.FILETYPE_PEM, server_cert.get_pubkey()).decode("utf-8")
        except Exception as e:
            return {}, "build server cert fail {}".format(e)

        # 从证书内解析出公钥
        try:
            decode_jws = jwt.decode(jws, public_key, algorithms=[alg])
        except Exception as e:
            return {}, "sign check fail {}".format(e)
        return decode_jws, ""

    @classmethod
    def verify_apple_jws_cert_chain(cls, x5c):
        """
        验证苹果server notify的证书链
        'x5c':['服务器证书','中间证书','根证书']
        我们验证顺序: 苹果根证书->x5c根证书, x5c根证书->中间证书, 中间证书->服务器证书
        :param x5c:
        :return:
        """
        if not x5c or not isinstance(x5c, list):
            return "x5c type error"
        # 加载x5c证书，转为X509证书格式
        x5c_cert = []
        try:
            for each in x5c:
                cert = "-----BEGIN CERTIFICATE-----\n" + each + "\n-----END CERTIFICATE-----"
                new_cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
                x5c_cert.append(new_cert)
        except Exception as e:
            return "x5c certification load exception {}".format(e)
        # 加载苹果根证书
        cert_file = open("./AppleRootCA-G3.cer", "rb")
        apple_root_cert = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_file.read())
        cert_file.close()

        # 接下来验证证书链，验证失败会报错:OpenSSL.crypto.X509StoreContextError: unable to get local issuer certificate
        # 首先验证x5c内的根证书
        store = crypto.X509Store()
        store.add_cert(apple_root_cert)
        try:
            store_ctx = crypto.X509StoreContext(store, x5c_cert[2])
            store_ctx.verify_certificate()
        except Exception as e:
            return "verify root certification exception {}".format(e)

        # 接下来验证x5c内的中间证书
        store.add_cert(x5c_cert[2])
        try:
            store_ctx = crypto.X509StoreContext(store, x5c_cert[1])
            store_ctx.verify_certificate()
        except Exception as e:
            return "verify mid certification exception {}".format(e)

        # 最后验证服务器证书
        store.add_cert(x5c_cert[1])
        try:
            store_ctx = crypto.X509StoreContext(store, x5c_cert[0])
            store_ctx.verify_certificate()
        except Exception as e:
            return "verify server certification exception {}".format(e)

        # 最终验证成功
        return ""


    @classmethod
    def decode_base64_data(cls, encode_data):
        """
        对数据进行base64解码
        :param encode_data:
        :return:
        """
        if not (encode_data.endswith("=") or encode_data.endswith("==")):
            encode_data += "=="
        decode_data = json.loads(base64.b64decode(encode_data))
        return decode_data
