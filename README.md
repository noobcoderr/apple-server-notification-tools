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

## 可能出现的问题，及解决办法
1. 每次验签都去打开G3根证书文件，比较消耗IO，可以改为程序启动时先预加载好，验签时直接使用即可
    
2. G3根证书有有效期，所以程序内可以加一个过期报警, x509格式的证书有`has_expired()`方法，可以加载完`apple_root_cert`后进行一次`apple_root_cert.has_expired()`过期判断，但是此时该证书疑似仍然可用，所以不要直接退出，影响正常的业务请求

3. 不同版本Python下的的`crypto.X509Store()`对`add_cert()`方法有不同的要求，pypy60和pypy70有些差异，70允许添加同一个证书进入，而60则不允许, x5c内的根证书(第三个)其实就是苹果证书页下载的G3根证书，所以这里只添加一次就行。
即 `store.add_cert(apple_root_cert)`添加了完根证书并完成了根证书的验证之后，不要再执行`store.add_cert(x5c_cert[2])`了

## 参考
[StoreKit2【附源码】JWS X.509证书链验证](https://juejin.cn/post/7039970403770433544)   
[JWS-X.509 Certificate Chain](https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.6)
