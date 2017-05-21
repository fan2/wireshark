<!--TOC-->

《TCP/IP 详解 卷1：协议》 第2版 第18章 安全

## TLS rfc
rfc2246: [The TLS Protocol Version 1.0](https://tools.ietf.org/html/rfc2246)

rfc3546: [Transport Layer Security (TLS) Extensions](https://tools.ietf.org/html/rfc3546)

rfc4346: [The Transport Layer Security (TLS) Protocol Version 1.1](https://tools.ietf.org/html/rfc4346)

rfc4680: [TLS Handshake Message for Supplemental Data](https://tools.ietf.org/html/rfc4680)

	1. Message Flow with SupplementalData  
	2. Double Handshake to Protect Supplemental Data  

rfc4681: [TLS User Mapping Extension](https://tools.ietf.org/html/rfc4681)

rfc5746: [Transport Layer Security (TLS) Renegotiation Indication Extension](https://tools.ietf.org/html/rfc5746)

rfc7919: [Negotiated Finite Field Diffie-Hellman Ephemeral Parameters for Transport Layer Security (TLS)](https://tools.ietf.org/html/rfc7919)

## 数字证书及安全概述
### [理解SSL(https)中的对称加密与非对称加密](http://netsecurity.51cto.com/art/201407/444787.htm)
由早期密码学引入加密类型和加密算法。

### [数字签名和数字证书](http://blog.csdn.net/phunxm/article/details/16344837)
图解数字签名和数字证书基本概念。

### [白话数字签名](http://www.cnblogs.com/1-2-3/category/106003.html)
通俗易懂地讲解数字签名的原理和应用方法。
最后给出一个 B/S 信息系统使用数字签名技术的 Demo。

### [数字证书的基础知识](http://www.enkichen.com/2016/02/26/digital-certificate-based/)
- 对称加密(常见算法)  
- 非对称加密(常见算法)  
- 摘要算法(常见算法)  
- 数字签名  
- 数字证书(组成、验证、授权链)  

### [公钥、秘钥、对称加密、非对称加密总结](http://my.oschina.net/shede333/blog/359290)
网摘大杂烩。

### [和安全有关的那些事](http://blog.csdn.net/bluishglc/article/details/7585965)
安全技术堆栈。

[非对称加密原理解析](http://blog.csdn.net/wzzvictory/article/details/9015155)  
[非对称加密的设计原理是什么？](https://www.zhihu.com/question/23879943)  欧拉定理  
[如何用通俗易懂的话来解释非对称加密?](https://www.zhihu.com/question/33645891)  

### Cipher Suite
[What's the GCM-SHA 256 of a TLS protocol?](https://crypto.stackexchange.com/questions/26410/whats-the-gcm-sha-256-of-a-tls-protocol)  
[decompose cipher suite: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256](https://crypto.stackexchange.com/questions/26410/whats-the-gcm-sha-256-of-a-tls-protocol)  
[Proposal to Change the Default TLS Ciphersuites Offered by Browsers](https://briansmith.org/browser-ciphersuites-01)  
[TLS 1.2 handshake problem?](http://grokbase.com/t/apache/users/126c3zespf/httpd-tls-1-2-handshake-problem)  

### RSA
RSA算法原理：[一](http://www.ruanyifeng.com/blog/2013/06/rsa_algorithm_part_one.html) [二](http://www.ruanyifeng.com/blog/2013/07/rsa_algorithm_part_two.html)

[RSA加解密原理](https://www.zhihu.com/question/33645891/answer/159643267)  
[RSA做密钥协商(密钥交换)时，是否可以防范中间人攻击？](https://www.zhihu.com/question/25116415)  

[What is ECDHE-RSA?](https://security.stackexchange.com/questions/14731/what-is-ecdhe-rsa)  

### SSH
SSH原理与运用：[一](http://www.ruanyifeng.com/blog/2011/12/ssh_remote_login.html) [二](http://www.ruanyifeng.com/blog/2011/12/ssh_port_forwarding.html)

## HTTPs 扫盲科普
### [图解HTTPS](http://limboy.me/tech/2011/02/19/https-workflow.html)
比较简单。

### [HTTPS科普扫盲帖](http://www.cnblogs.com/chyingp/p/https-introduction.html)
比较系统。

### [HTTPS 工作原理和 TCP 握手机制](http://blog.jobbole.com/105633/)  
浏览器与网站互相发送加密的握手消息（Encryted Handshake Message）并验证，目的是为了保证双方都获得了一致的密码，并且可以正常的加密解密数据，为后续真正数据的传输做一次测试。

### [How HTTPS Secures Connections](https://blog.hartleybrody.com/https-certificates/) / [HTTPS是如何保证连接安全](http://blog.jobbole.com/45530/)
由浅入深，通俗易懂。
解释了 Diffie-Hellman 算法的数学原理。

### [The First Few Milliseconds of an HTTPS Connection](http://www.moserware.com/2009/06/first-few-milliseconds-of-https.html)
结合 wireshark 抓包，全面完整地剖析了 TLS 运行机制和技术细节。

There are no more levels on the **trust chain**.   [Reflections on Trusting Trust](http://www.ece.cmu.edu/~ganger/712.fall02/papers/p761-thompson.pdf)  
you ultimately have to implicitly trust the built-in certificates.  
The top root Certificate was **signed by itself** which has been built into host system.  

One final check that we need to do is to verify that the host name on the certificate is what we expected. 

## HTTPs 安全机制

### HTTPS 那些事
[（一）HTTPS 原理](http://www.guokr.com/post/114121/)  
[（二）SSL 证书](http://www.guokr.com/post/116169/)  
[（三）攻击实例与防御](http://www.guokr.com/blog/148613/)  

常见的证书根据用途不同大致有以下几种：

1. SSL证书，用于加密HTTP协议，也就是HTTPS。  
2. 代码签名证书，用于签名二进制文件，比如Windows内核驱动，Firefox插件，Java代码签名等等。  
3. 客户端证书，用于加密邮件。  
4. 双因素证书，网银专业版使用的USB Key里面用的就是这种类型的证书。  

对于SSL证书来说，如果访问的网站与证书绑定的网站一致就可以通过浏览器的验证而不会提示错误。

---

证书以***证书链***的形式组织，在颁发证书的时候首先要有**根CA机构**颁发的根证书，再由根CA机构颁发一个**中级CA机构**的证书，最后由中级CA机构颁发具体的SSL证书。

根证书是最关键的一个证书，如果根证书不受信任，它下面颁发的所有证书都不受信任。操作系统在安装过程中会默认安装一些受信任的CA机构的根证书。

在验证证书的时候，浏览器会调用系统的证书管理器接口对证书路径（Certification Path）中的所有证书一级一级的进行验证，只有路径中所有的证书都是受信的，整个验证的结果才是受信。

---

SSL证书**验证失败**有以下三点原因：

1. SSL证书不是由受信任的CA机构颁发的  
2. 证书过期  
3. 访问的网站域名与证书绑定的域名不一致  

---

对HTTPS最常见的攻击手段就是SSL证书欺骗或者叫SSL劫持，是一种典型的中间人攻击。

### [HTTPS 是如何保证安全的？](http://www.jianshu.com/p/b894a7e1c779)
杂谈论述。

 CA 的安全性由操作系统或浏览器来认证。

### [HTTPS 为什么更安全](http://blog.jobbole.com/110373/)
比较完整，图解例证。

### [也许，这样理解HTTPS更容易](http://blog.jobbole.com/110354/)  
由浅入深，一步步解构还原 HTTPs 的设计过程。

### [HTTPS 背后的加密算法](http://insights.thoughtworkers.org/cipher-behind-https/)

### [百度全站 HTTPS 实践](http://blog.csdn.net/bd_zengxinxin/article/details/51115604)  

## TLS 机制
### [SSL/TLS协议运行机制的概述](http://www.ruanyifeng.com/blog/2014/02/ssl_tls.html)

	> 三个随机数，前2个和第3个的关系？

C->S：EncryptWithPubKey {Premaster secret},
S decrypt with private key.

session key = {Client random, Server random, Premaster secret}

@img ![TLS handshake](http://image.beekka.com/blog/201402/bg2014020502.png)

- `Server Key Exchange`：EC Diffie-Hellman Server Params  
- `Client Key Exchange`：EC Diffie-Hellman Client Params  
- `Encryted Handshake Message`：为 TLS Client Finished    
- `Encryted Handshake Message`：为 TLS Server Finished  

### [图解SSL/TLS协议](http://www.ruanyifeng.com/blog/2014/09/illustration-ssl.html)
基于 CloudFlare 提供的 Keyless 服务，来阐述 SSL 协议的握手过程 和 DH 算法的握手阶段。

### [安全协议系列（四）----SSL与TLS](http://www.cnblogs.com/efzju/p/3674058.html)
本文使用 OpenSSL 提供的子命令 s_server/s_client 进行 TLS 通信。
利用 OpenSSL 自带的调试功能，来观察运行的内部细节，起到事半功倍的作用。

[在CentOS[lnmp]上部署新版本SSL协议+ECDHE_RSA正向加密和预防BEAST攻击](https://xuanwobbs.com.cn/archives/2013-07/centos-lnmp-ecdhe_rsa-beast.html)

### [SSL/TLS原理详解](https://segmentfault.com/a/1190000002554673)
全面翔实地讲解了非对称加密协商和 Secret Keys 派生关系。

[Https(SSL/TLS)原理详解](http://www.codesec.net/view/179203.html)

#### Hello 协商加密套件与密码套件
在 `Client Hello` 报文中，客户端告诉服务器自己支持的 **Cipher Suites**、**Compression Methods** 和 **Extension**(server_name,elliptic_curves,ec_point_formats(Elliptic curves point formats),signature_algorithms,ALPN Protocol,Extended Master Secret) 信息。

服务器收到 `Client Hello` 后，会结合双方支持的加密基础设施，并给客户端回应  `Server Hello` 反馈协商的密码套件（Cipher Suite）。

在 **`github-未登录(tcp.port==55104&55109).pcapng`** 的 Packet 8 `Server Hello`  中包含 elliptic_curves 和 signature_algorithms 等 Extension，协商出的 Cipher Suite 为 *`TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`* (0xc02f)：

1. **ECDHE_RSA**：密钥协商交换算法

	- **[ECDHE](https://security.stackexchange.com/questions/14731/what-is-ecdhe-rsa)**：使用基于椭圆曲线签密方案（EC, Elliptic Curve）的 Diffie-Hellman（DH）密钥协商协议。尾部的 <kbd>E</kbd> 为 Ephemeral 首字母，表示协商的是**临时**会话密钥。相对每次会话协商的临时密钥，证书中的公钥则是永久的。  
	- **RSA**：证书公钥加密算法，用于对证书公开内容的散列值进行签密、加密  ECDHE 交换参数（的HASH值）。可能替换值为 ECDSA（椭圆曲线数字签名算法）。  

2. **AES_128_GCM**：传输会话（对称）加解密使用 GCM 模式的 AES-128 算法。

	- **AES_128**：使用128位的会话对称加密算法，双方通过 ECDHE 交换参数协商出对称密钥。  
	- **GCM**：Galois计数器模式（[Galois/Counter Mode](https://en.wikipedia.org/wiki/Galois/Counter_Mode)）。消息认证码（MAC，Message Authentication Code）用于保障消息的**完整性**，防止各种伪造。AES-CMAC 使用分组密码，取代 HMAC 的加密散列函数。Galois 消息认证码（GMAC）则采用了 AES 算法的一种特殊模式。  

3. **SHA256**：摘要/指纹哈希算法（加密散列函数）

	> 使用安全散列算法2（SHA-2）生成256字节的摘要，确保消息的完整性（没有被篡改）。

#### 客户端基于 Certificate 和 Server Key Exchange 计算对称密钥
客户端首先要校验服务端下发证书（`Certificate`）的合法性：

1. 证书路径信任链逐级校验通过（证书确有可信CA认证签发）；  
2. 签名解密成功（确系证书持有者亲笔）；  
3. 从签名解析出的摘要和证书公开内容的摘要一致（证书内容完整，未被篡改）。  

然后，客户端在接收到 `Server Key Exchange` 报文后，基于 ECDH[^ECDH] 参数中的 Pubkey 通过一定的算法计计算出 ***Pre-Master Secret***。  
紧接着，客户端将基于 Client Hello、Server Hello 中的 2 个 28 bytes 随机数（Random）和这个 Pre-Master Secret 计算出用于派生后续传输所用对称密钥的 ***Master Secret***（Shared Secret）。

> 两个 Hello 随机数都是明文透传。  
> ECDH 参数（EC Diffie-Hellman Server Params）携带了  Signatue，需要 Certificate 中的公钥进行 RSA 解密和 HASH 校验，从而保证整个握手协商的安全性。

Master Secret 作为数据加解密相关的 secret 的 Key Material 的一部分。  
**[Key Material](http://www.rosoo.net/a/201409/17053.html)** 的计算跟 Master Secret(Key) 的计算类似，只不过计算的次数要多。
Key Material需要计算12次，从而产生12个hash值。产生12个hash之后，紧接着就可以从这个 Key Material 中获取 ***Session Secret*** 了。

![TLS-KEYS](http://sean-images.qiniudn.com/tls-keys.svg)

- Client/Server write MAC key：用来对数据进行验证的；  
- Client/Server write encryption key：用来对数据进行加解密的 **Session Secret**（Session Key）。  

---

在收到 `Server Hello Done` 且客户端已成功协商计算出 Session Secret 之后，客户端向服务器发送 `Client Key Exchange`、`Change Cipher Spec` 和 `Encryted Handshake Message` 报文 。  

1. 发送 `ChangeCipherSpec`，表示客户端确认支持并接受 Server Hello 中服务器指定的 Cipher Suite。  
2. 发送 `Client Key Exchange`，这样服务器也能基于 `Server Hello` 指定的 Cipher Suite 和 Client Hello、Server Hello 中的 2 个 28 bytes 随机数以及 Client Key Exchange 中的 ECDH 参数协商出 Session Secret。  
3. 发送 `Encryted Handshake Message`，表示客户端基于计算出的会话密钥加密一段数据（verify_data，Finished message），在正式传输应用数据之前对握手协商的会话加解密通道进行验证。

	> 服务器只有确保收到了 `Change Cipher Spec`、`Client Key Exchange` 报文并成功协商出了 Session Secret，才能解密（验证）加密的 Finished message。  

#### 服务端基于 Client Key Exchange 计算对称密钥
服务器在收到客户端的 `ChangeCipherSpec` 报文后，也回应一个 `ChangeCipherSpec`  告知客户端确定使用双方都支持确认的 Cipher Suite。

服务端在接收到 `Client Key Exchange` 报文后，基于 ECDH 参数中的 Pubkey 通过一定的算法计计算出 ***Pre-Master Secret***。  
然后，服务端再基于 Client Hello、Server Hello 中的 2 个 28 bytes 随机数（Random）和这个 Pre-Master Secret 计算出用于派生后续传输所用对称密钥的 ***Master Secret***（Shared Secret）。

> ECDH 参数（EC Diffie-Hellman Client Params）使用 Certificate 中的公钥加密，需要使用对应的私钥解密——只有持有证书的服务器才能解开，确保了交换参数的安全性。  

Master Secret 作为数据加解密相关的 secret 的 Key Material 的一部分，最终从 Key Material 中获取用于会话加密的对称密钥 ***Session Secret***（Session Key）。

---

服务端在接收到客户端发过来的 `Encryted Handshake Message` 后，若使用 Session Secret 能解密出原始校验数据（verify_data，Finished message），则表明 C->S 加解密通道就绪。  
同时，服务器也会给客户端发送一份使用 Session Secret 加密的校验数据报文 `Encryted Handshake Message`。若客户端也能正确解密，则表明 S->C 加解密通道就绪。

至此，基于非对称加解密（私钥签名公钥解密，公钥加密私钥解密）和 ECDHE 协商出来的对称会话密钥，已被 C=S 双向通道验证，TLS HandShake 成功。

#### HTTP over TLS（HTTPs）
接下来，双方可以使用协商计算出的 Session Secret 和 ALPN Protocol 来进行应用数据（**Application Data**）的加密传输。

具体来说，双方以 Session Secret 为对称密钥，使用 AES 对称加密算法对 HTTP  Request/Response 报文进行加密传输。

所谓 ***HTTPs*** 全称为 Hyper Text Transfer Protocol over Secure Socket Layer，意即 over TLS 的 Secure HTTP。

## wireshark 抓包
[利用WireShark破解网站密码](http://www.freebuf.com/articles/network/59664.html)  
[逆向wireshark学习SSL协议算法](http://sanwen8.cn/p/27ebPa7.html)  
[使用wireshark观察SSL/TLS握手过程--双向认证/单向认证](http://blog.csdn.net/fw0124/article/details/40983787)  

[^ECDH]: [Elliptic curve Diffie–Hellman](https://en.wikipedia.org/wiki/Elliptic_curve_Diffie%E2%80%93Hellman) (ECDH) is an anonymous key agreement protocol that allows two parties, each having an elliptic curve **public–private** key pair, to establish a **shared secret** over an insecure channel.This shared secret may be *directly used* as a key, or *to derive another key*. The key, or the derived key, can then be used to encrypt subsequent communications using a ***symmetric key cipher***. It is a variant of the Diffie–Hellman protocol using elliptic curve cryptography.
