<!--TOC-->

《TCP/IP 详解 卷1：协议》 第2版 第18章 安全

## 密码学及安全技术栈
[密码学笔记](http://www.ruanyifeng.com/blog/2006/12/notes_on_cryptography.html)  
[【翻译】密码学一小时必知](https://blog.helong.info/blog/2015/04/12/translate-Everything-you-need-to-know-about-cryptgraphy-in-1-hour/)  
[现代密码学实践指南](https://blog.helong.info/blog/2015/06/06/modern-crypto/)  

### [理解SSL(https)中的对称加密与非对称加密](http://netsecurity.51cto.com/art/201407/444787.htm)
由早期密码学引入加密算法和加密类型（对称加密、非对称加密），进而阐述网站如何通过 SSL（安全套接层） 加密和用户安全通信。

SSL (Secure Sockets Layer) 是用来保障你的浏览器和网站服务器之间安全通信，免受网络“中间人”窃取信息。

SSL原理很简单：

1. 当你的浏览器向服务器请求一个安全的网页（通常是以 `https://` 开头），服务器就把它的**证书**和**公匙**发回来。  
2. 浏览器**检查**证书是不是由可以信赖的机构颁发的，校验证书有效和确认此证书是此网站的。  
3. 浏览器使用公钥**加密**了一个随机对称密钥，包括**加密**的URL一起发送到服务器。  
4. 服务器用自己的私匙**解密**了你发送的钥匙，然后用这把对称加密的钥匙给你请求的URL链接**解密**。  
5. 服务器用你发的对称钥匙给你请求的网页**加密**。你也有相同的钥匙就可以**解密**发回来的网页了。

第3步补充：

> 实际上SSL握手的过程比这篇文章描述的要复杂，实际过程中这一步发送的是一个“预主密钥”，实际加密报文用的“主密钥”是通过这个“预主密钥”和另外的随机数计算出来的。 

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

### RSA
RSA算法原理：[一](http://www.ruanyifeng.com/blog/2013/06/rsa_algorithm_part_one.html) [二](http://www.ruanyifeng.com/blog/2013/07/rsa_algorithm_part_two.html)

[RSA加解密原理](https://www.zhihu.com/question/33645891/answer/159643267)  
[RSA做密钥协商(密钥交换)时，是否可以防范中间人攻击？](https://www.zhihu.com/question/25116415)  

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

要解决身份认证问题，需要有配套的公钥基本设施，来核实用户的真实身份。
这些设施用来创建，管理，发布，收回数字证书。

简单说来，私钥是用来加密和解密，公钥用来确定信息是否真的来自某个人，而证书一般是第三方用来确认公钥的发行者？

---

从更高的层次来讲，**数字证书**是将机器上的公钥和身份信息绑在一起的_数字签名_。
数字签名`担保`某份公钥属于某个特定的组织和机构。

证书将域名（身份信息）和特定公钥关联起来，这就避免了窃听者将自己的服务器伪装成用户将要连接的服务器，并进行攻击的行为。

在上面打电话的例子中，攻击者可以尝试展示自己的公钥，装作是你的“朋友”，但是证书上面的签名信息便显示出：这份证书不是来自我信任的人的。

### [HTTPS 为什么更安全](http://blog.jobbole.com/110373/)
比较完整，图解例证。

### [也许，这样理解HTTPS更容易](http://blog.jobbole.com/110354/)
由浅入深，一步步解构还原 HTTPs 的设计过程。

### [HTTPS 背后的加密算法](http://insights.thoughtworkers.org/cipher-behind-https/)

[百度全站 HTTPS 实践](http://blog.csdn.net/luocn99/article/details/45460673)

## TLS 机制
[SSL and TLS Deployment Best Practices](https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices)  

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

### [SSL/TLS原理详解](https://segmentfault.com/a/1190000002554673)
全面翔实地讲解了非对称加密协商和 Secret Keys 派生关系。

[Https(SSL/TLS)原理详解](http://www.codesec.net/view/179203.html)  
[TLS协议分析 与 现代加密通信协议设计](https://blog.helong.info/blog/2015/09/07/tls-protocol-analysis-and-crypto-protocol-design/)  
