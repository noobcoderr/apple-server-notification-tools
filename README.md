# 苹果开发者服务器通知v2-JWS验证处理方法

## App Store Server Notifications
苹果支持开发者服务端回调模式，其中v2版本使用JWS数据格式回传，该格式包含了**数据**、**证书链**、**签名算法**、**签名结果**。
需要我们在本地完成数据的正确性和合法性：  

1、合法性：验证证书链的正确性。  
2、正确性：使用证书链中的服务器证书内的公钥验证数据和签名。

## 使用
苹果服务端通知的结构为  
`{"signedPayload": "The payload in JSON Web Signature (JWS) format, signed by the App Store"}`

直接将苹果返回的`signedPayload`使用以下方法进行验证并解析即可
```python
from jws_verify import AppleIapTools
jws_data, err = AppleIapTools.verify_jws(signedPayload)
```
如果解析并验证成功，则返回解析后的结果，否则返回空字典，err返回对应的错误信息。


## 参考
[StoreKit2【附源码】JWS X.509证书链验证](https://juejin.cn/post/7039970403770433544)   
[JWS-X.509 Certificate Chain](https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.6)
