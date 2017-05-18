《TCP/IP 详解 卷1：协议》 第2版 第18章 安全

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

## HTTPs 扫盲科普
### [图解HTTPS](http://limboy.me/tech/2011/02/19/https-workflow.html)
比较简单。

### [HTTPS科普扫盲帖](http://www.cnblogs.com/chyingp/p/https-introduction.html)
比较系统。

### [HTTPS 工作原理和 TCP 握手机制](http://blog.jobbole.com/105633/)  

### [The First Few Milliseconds of an HTTPS Connection](http://www.moserware.com/2009/06/first-few-milliseconds-of-https.html)
结合 wireshark 抓包，全面完整地剖析了 TLS 运行机制和技术细节。

There are no more levels on the **trust chain**.   [Reflections on Trusting Trust](http://www.ece.cmu.edu/~ganger/712.fall02/papers/p761-thompson.pdf)  
you ultimately have to implicitly trust the built-in certificates.  
The top root Certificate was **signed by itself** which has been built into host system.  

One final check that we need to do is to verify that the host name on the certificate is what we expected. 

### [How HTTPS Secures Connections](https://blog.hartleybrody.com/https-certificates/) / [HTTPS是如何保证连接安全](http://blog.jobbole.com/45530/)
由浅入深，通俗易懂。
解释了 Diffie-Hellman 算法的数学原理。

## HTTPs 安全机制

### HTTPS 那些事
[（一）HTTPS 原理](http://www.guokr.com/post/114121/)  
[（二）SSL 证书](http://www.guokr.com/post/116169/)  
[（三）攻击实例与防御](http://www.guokr.com/blog/148613/)  

### [HTTPS 是如何保证安全的？](http://www.jianshu.com/p/b894a7e1c779)
杂谈论述。

### [HTTPS 为什么更安全](http://blog.jobbole.com/110373/)
比较完整，图解例证。

### [也许，这样理解HTTPS更容易](http://blog.jobbole.com/110354/)  
由浅入深，一步步解构还原 HTTPs 的设计过程。

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

### [Https(SSL/TLS)原理详解](http://www.codesec.net/view/179203.html)  
在 `ChangeCipherSpec` 传输完毕之后，**客户端**会使用之前协商好的加密套件和 session secret 加密一段 **_Finish_** 的数据（Encryted Handshake Message）传送给服务端，此数据是为了在正式传输应用数据之前对刚刚握手建立起来的加解密通道进行验证。

**服务端**在接收到客户端传过来的 PreMaster 加密数据之后，使用_私钥_对这段加密数据进行解密，并对数据进行验证，也会使用跟客户端同样的方式生成 session secret，一切准备好之后，会给客户端发送一个 `ChangeCipherSpec`，告知客户端已经切换到协商过的加密套件状态，准备使用加密套件和session secret加密数据了。
之后，服务端也会使用 session secret 加密后一段 **_Finish_** 消息（Encryted Handshake Message）发送给客户端，以验证之前通过握手建立起来的加解密通道是否成功。

根据之前的握手信息，如果客户端和服务端都能对 Finish 信息进行正常加解密且消息正确地被验证，则说明握手通道已经建立成功。
接下来，双方可以使用上面产生的session secret对数据进行加密传输了。

[TLS 1.2 handshake problem?](http://grokbase.com/t/apache/users/126c3zespf/httpd-tls-1-2-handshake-problem)

### [SSL/TLS原理详解](https://segmentfault.com/a/1190000002554673)

## wireshark 抓包
[利用WireShark破解网站密码](http://www.freebuf.com/articles/network/59664.html)  
[逆向wireshark学习SSL协议算法](http://sanwen8.cn/p/27ebPa7.html)  
[使用wireshark观察SSL/TLS握手过程--双向认证/单向认证](http://blog.csdn.net/fw0124/article/details/40983787)  
