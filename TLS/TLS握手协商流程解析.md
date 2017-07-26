
## Hello 协商加密套件与密码套件
在 `Client Hello` 报文中，客户端告诉服务器自己支持的 **TLS Version**、**Cipher Suites**、**Compression Methods** 和 **Extension**(server_name,elliptic_curves,ec_point_formats(Elliptic curves point formats),signature_algorithms,ALPN Protocol,Extended Master Secret) 等信息。

服务器收到 `Client Hello` 后，会结合双方支持的加密基础设施（proposed by the client and supported by the server），给客户端回应  `Server Hello` 反馈（in response to）选择的 TLS 版本以及密码套件（common Cipher Suite）。

在 Packet 8 `Server Hello`  中包含 elliptic_curves 和 signature_algorithms 等 Extension，协商出的 Cipher Suite 为 *`TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`*。

[**TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256**](http://www.iana.org/go/rfc5289) 解构如下：

1. **ECDHE_RSA**：密钥协商交换算法

	- **[ECDHE](https://security.stackexchange.com/questions/14731/what-is-ecdhe-rsa)**：使用基于椭圆曲线签密方案（EC, Elliptic Curve）的 Diffie-Hellman（DH）密钥协商协议。尾部的 <kbd>E</kbd> 为 Ephemeral 首字母，表示协商的是**临时**会话密钥。相对每次会话协商的临时密钥，证书中的公钥则是永久的（long-term）。  
	- **RSA**：证书公钥加密算法，用于对证书数据部分的散列值进行签密、对  ECDHE 交换参数（的 HASH 值）进行签密。可能替换值为 ECDSA（椭圆曲线数字签名算法）。  

	> rfc4492 & rfc5289 定义了该 CipherSuite 的具体实现。  
	> the long term authenticity is confirmed via the server cert's **RSA** signature but the transient keys are **derived** via ephemeral EC keys (which then generate the symmetric key)  
	> **ECDHE**-RSA uses Diffie-Hellman on an *elliptic curve* group while **DHE**-RSA uses Diffie-Hellman on a *modulo-prime* group.

2. **AES_128_GCM**：传输会话（对称）加解密使用 GCM 模式的 AES-128 算法。

	- **AES_128**：使用128位的会话对称加密算法，双方通过 ECDHE 交换参数协商出对称密钥。  
	- **GCM**：Galois计数器模式（[Galois/Counter Mode](https://en.wikipedia.org/wiki/Galois/Counter_Mode)）。消息认证码（MAC，Message Authentication Code）用于保障消息的**完整性**，防止各种伪造。AES-CMAC 使用分组密码，取代 HMAC 的加密散列函数。Galois 消息认证码（GMAC）则采用了 AES 算法的一种特殊模式。  

	> 主流加密算法趋势是 AES（128/256），加密模式的趋势是 GCM。  
	> GCM 是一种特殊的称为 AEAD 的加密模式，不需要配合 MAC。  

3. **SHA256**：消息认证码算法，基于有密钥的加密散列函数，用于创建消息摘要/指纹。

	> 使用安全散列算法2（SHA-2）生成256字节的摘要，确保消息的完整性（没有被篡改）。

## 客户端基于 Certificate 和 Server Key Exchange 计算对称密钥
客户端首先要校验服务端下发证书（`Certificate`）的合法性（validates the certificate chain）：

1. 证书路径信任链逐级校验通过（证书确由可信 CA 认证签发）；  
2. 签名解密成功（确系证书持有者亲笔）；  
3. 从签名解析出的摘要和证书公开内容的摘要一致（证书内容完整，未被篡改）；  
4. 主题 CN 子域（Subject.CN）与 URL 中的 HOST 一致，综上确保访问的网站是来自预期目标服务器且非劫持或钓鱼。  

然后，客户端在接收到 `Server Key Exchange` 报文后，首先需要使用证书中的公钥对签名进行 RSA 解密并校验散列值。如果解密校验通过，则基于 ECDH[^ECDH] 参数中的 Pubkey（the server's ephemeral ECDH public key） 通过一定的算法计算出 ***Pre-Master Secret***（resultant shared secret）。

@img ![Server_Key_Exchange.png](pcapng/github/github-未登录(tcp.port==55104&55109)-Server_Key_Exchange.png)

紧接着，客户端将基于 Client Hello、Server Hello 中的 2 个 28 bytes 随机数（Random）和这个 Pre-Master Secret 计算出用于派生后续传输所用对称密钥的种子—— ***Master Secret***（Shared Secret）。

> 两个 Hello 随机数都是明文透传。  
> ECDH 参数（EC Diffie-Hellman Server Params）携带了  Signatue，需要 Certificate 中的公钥进行 RSA 解密和 HASH 校验，从而保证整个握手协商的安全性。

Master Secret 作为数据加解密相关的 secret 的 Key Material 的一部分。  
**[Key Material](http://www.rosoo.net/a/201409/17053.html)** 的计算跟 Master Secret(Key) 的计算类似，只不过计算的次数要多。
Key Material需要计算12次，从而产生12个hash值。产生12个hash之后，紧接着就可以从这个 Key Material 中获取 ***Session Secret*** 了。

![TLS-KEYS](http://sean-images.qiniudn.com/tls-keys.svg)

- Client/Server write MAC key：用来对数据完整性进行验证；  
- Client/Server write encryption key：用来对数据进行加解密的 **Session Secret**（Session Key）。  

---

在收到 `Server Hello Done` 且客户端已成功协商计算出 Session Secret 之后，客户端向服务器发送 `Client Key Exchange`、`Change Cipher Spec` 和 `Encryted Handshake Message` 报文 。  

1. 发送 `ChangeCipherSpec`，表示客户端确认接受 Server Hello 中服务器选定的 Cipher Suite。  
2. 发送 `Client Key Exchange`，这样服务器也能基于 `Server Hello` 指定的 Cipher Suite 和 Client Hello、Server Hello 中的 2 个 28 bytes 随机数以及 Client Key Exchange 中的 ECDH 参数最终协商出 Session Secret。  
3. 发送 `Encryted Handshake Message`，表示客户端基于计算出的会话密钥加密一段数据（verify_data，Finished message），在正式传输应用数据之前对握手协商的会话加解密通道进行验证。

	> 服务器只有确保收到了 `Change Cipher Spec`、`Client Key Exchange` 报文并成功协商出了 Session Secret，才能解密（验证）加密的 Finished message。  

## 服务端基于 Client Key Exchange 计算对称密钥
服务器在收到客户端的 `ChangeCipherSpec` 报文后，也回应一个 `ChangeCipherSpec`  告知客户端确定使用双方都支持确认的 Cipher Suite。

服务端在接收到 `Client Key Exchange` 报文后，基于 ECDH 参数中的 Pubkey 通过一定的算法计算出 ***Pre-Master Secret***（resultant shared secret）。

@img ![Client_Key_Exchange.png](pcapng/github/github-未登录(tcp.port==55104&55109)-Client_Key_Exchange.png)

然后，服务端再基于 Client Hello、Server Hello 中的 2 个 28 bytes 随机数（Random）和这个 Pre-Master Secret 计算出用于派生后续传输所用对称密钥的种子—— ***Master Secret***（Shared Secret）。

> ECDH 参数（EC Diffie-Hellman Client Params）使用 Certificate 中的公钥加密，需要使用对应的私钥解密——只有持有证书的服务器才能解开，确保了交换参数的安全性。  

Master Secret 作为数据加解密相关的 secret 的 Key Material 的一部分，最终从 Key Material 中获取用于会话加密的对称密钥 ***Session Secret***（Session Key）。

---

服务端在接收到客户端发过来的 `Encryted Handshake Message` 后，若使用 Session Secret 能解密出原始校验数据（verify_data，Finished message），则表明 C->S 方向的加解密通道就绪。  
同时，服务器也会给客户端发送一份使用 Session Secret 加密的校验数据报文 `Encryted Handshake Message`。若客户端也能正确解密，则表明 S->C 方向的加解密通道就绪。

至此，基于非对称加解密（私钥签名公钥解密，公钥加密私钥解密）和 ECDHE 协商出来的对称会话密钥，已被 C=S 双向通道验证，TLS HandShake 成功。

## HTTP over TLS（HTTPs）
接下来，双方可以使用协商计算出的 Session Secret 和 ALPN Protocol 来进行应用数据（**Application Data**）的加密传输。

具体来说，双方以 Session Secret 为对称密钥，使用 AES 对称加密算法对 HTTP  Request/Response 报文进行加密传输。

所谓 ***HTTPs*** 全称为 Hyper Text Transfer Protocol over Secure Socket Layer，意即 over TLS 的 Secure HTTP。

## 参考
[SSL/TLS协议运行机制的概述](http://www.ruanyifeng.com/blog/2014/02/ssl_tls.html)  
[**图解SSL/TLS协议**](http://www.ruanyifeng.com/blog/2014/09/illustration-ssl.html)  

[How HTTPS Secures Connections](https://blog.hartleybrody.com/https-certificates/) / [HTTPS是如何保证连接安全](http://blog.jobbole.com/45530/)  
[**The First Few Milliseconds of an HTTPS Connection**](http://www.moserware.com/2009/06/first-few-milliseconds-of-https.html)  

[HTTPS 工作原理和 TCP 握手机制](http://blog.jobbole.com/105633/)  
[**也许，这样理解HTTPS更容易**](http://blog.jobbole.com/110354/)  
[**一个故事讲完https**](http://www.sohu.com/a/157872667_467808)  

[百度全站 HTTPS 实践](http://blog.csdn.net/luocn99/article/details/45460673)  
[**TLS 协议分析**](http://blog.csdn.net/zhangtaoym/article/category/6948696) by 微信后台团队(微信号：gh_93b1115dc96f)  
