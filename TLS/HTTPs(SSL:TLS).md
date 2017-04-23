《TCP/IP 详解 卷1：协议》 第2版 第18章 安全

## HTTPs 扫盲
### [图解HTTPS](http://limboy.me/tech/2011/02/19/https-workflow.html)  

### [HTTPS科普扫盲帖](http://www.cnblogs.com/chyingp/p/https-introduction.html)  

## TLS 概述
### [理解SSL(https)中的对称加密与非对称加密](http://netsecurity.51cto.com/art/201407/444787.htm)  

### [How HTTPS Secures Connections](https://blog.hartleybrody.com/https-certificates/) / [HTTPS是如何保证连接安全](http://blog.jobbole.com/45530/)  

### [和安全有关的那些事](http://blog.csdn.net/bluishglc/article/details/7585965)  

## TLS 机制
### [SSL/TLS协议运行机制的概述](http://www.ruanyifeng.com/blog/2014/02/ssl_tls.html)  

	> 三个随机数，前2个和第3个的关系？

C->S：EncryptWithPubKey {Premaster secret},
S decrypt with private key.

session key = {Client random, Server random, Premaster secret}

@img ![TLS handshake](http://image.beekka.com/blog/201402/bg2014020502.png)

### [图解SSL/TLS协议](http://www.ruanyifeng.com/blog/2014/09/illustration-ssl.html)  

### [Https(SSL/TLS)原理详解](http://www.codesec.net/view/179203.html)  
在 `ChangeCipherSpec` 传输完毕之后，**客户端**会使用之前协商好的加密套件和 session secret 加密一段 **_Finish_** 的数据（Encryted Handshake Message）传送给服务端，此数据是为了在正式传输应用数据之前对刚刚握手建立起来的加解密通道进行验证。

**服务端**在接收到客户端传过来的 PreMaster 加密数据之后，使用_私钥_对这段加密数据进行解密，并对数据进行验证，也会使用跟客户端同样的方式生成 session secret，一切准备好之后，会给客户端发送一个 `ChangeCipherSpec`，告知客户端已经切换到协商过的加密套件状态，准备使用加密套件和session secret加密数据了。
之后，服务端也会使用 session secret 加密后一段 **_Finish_** 消息（Encryted Handshake Message）发送给客户端，以验证之前通过握手建立起来的加解密通道是否成功。

根据之前的握手信息，如果客户端和服务端都能对 Finish 信息进行正常加解密且消息正确地被验证，则说明握手通道已经建立成功。
接下来，双方可以使用上面产生的session secret对数据进行加密传输了。

## wireshark 抓包
[利用WireShark破解网站密码](http://www.freebuf.com/articles/network/59664.html)  
[逆向wireshark学习SSL协议算法](http://sanwen8.cn/p/27ebPa7.html)  
[使用wireshark观察SSL/TLS握手过程--双向认证/单向认证](http://blog.csdn.net/fw0124/article/details/40983787)  
