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
1. SSL/TLS协议运行机制的概述

	> 三个随机数，前2个和第3个的关系？

C->S：EncryptWithPubKey {Premaster secret},
S decrypt with private key.

session key = {Client random, Server random, Premaster secret}

### [图解SSL/TLS协议](http://www.ruanyifeng.com/blog/2014/09/illustration-ssl.html)  

### [Https(SSL/TLS)原理详解](http://www.codesec.net/view/179203.html)  

## wireshark 抓包
[利用WireShark破解网站密码](http://www.freebuf.com/articles/network/59664.html)  
[逆向wireshark学习SSL协议算法](http://sanwen8.cn/p/27ebPa7.html)  
[使用wireshark观察SSL/TLS握手过程--双向认证/单向认证](http://blog.csdn.net/fw0124/article/details/40983787)  
