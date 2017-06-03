# OpenSSL
TLS/SSL 一共出过 5个版本：ssl2/ssl3/tls1.0/tls1.1/tls1.2 ，ssl2/ssl3 这两个版本漏洞太多，请务必禁用。

TLS1.2 是当前最新的 TLS 协议，定义在 rfc5246 中。

[TLS1.3](https://www.sslchina.com/introduction-to-tls1-3/) [概述](https://www.inforsec.org/wp/?p=1960)  [改进的握手：更多隐私更少延迟](http://www.linuxidc.com/Linux/2015-11/125288.htm)。

TLS 协议的实现有多种，如 openssl,gnutls,nss,libressl,cyassl,polarssl,botan 等等。  
openssl 的代码算是其中最混乱的，但是也是最久经考验的。 ( 请参见此打脸文： <http://blog.csdn.net/dog250/article/details/24552307>)

个人觉得 polarssl 和 botan 的架构最清晰，代码风格清新可爱，便于学习理解协议。但是不建议在生产环境下用，例如 polarssl 功能尚有欠缺。

## OpenSSL 参考
[OpenSSL 详解](http://blog.csdn.net/w1781806162/article/details/46358747)  
[OpenSSL 之命令详解](http://shjia.blog.51cto.com/2476475/1427138)  

[OpenSSL简介－指令cipher](http://www.blogjava.net/ycyk168/archive/2009/11/27/303934.html)  
[OpenSSL命令---ciphers](http://blog.csdn.net/as3luyuan123/article/details/13609819)   [@cnblogs](http://www.cnblogs.com/LiuYanYGZ/p/6004990.html)  

[iOS编译OpenSSL静态库](http://www.jianshu.com/p/27c3393054da)  
[iOS编译OpenSSL静态库(使用脚本自动编译)](http://www.jianshu.com/p/651513cab181)  

[Mac中如何用openssl生成RSA密钥文件](http://www.jianshu.com/p/b06669a90bc6)  
[使用OpenSSL生成pfx、cer、crt证书](http://www.jianshu.com/p/0578b16cb775)  
[SSL协议、openSSL及创建私有CA](http://www.jianshu.com/p/658a4eb4d09f)  
[Mac OSX 使用OpenSSL生成RSA公匙、私匙（pem）与DER文件](http://www.jianshu.com/p/bb2bd32e8794)  

[SSL/TLS协议及Openssl工具的实现](http://www.jianshu.com/p/da65e5cd552e)  
[利用OpenSSL建立PKI数字证书系统](http://www.jianshu.com/p/143698fd8551)  

## [安全协议系列（四）----SSL与TLS](http://www.cnblogs.com/efzju/p/3674058.html)
本文使用 OpenSSL 提供的子命令 s_server/s_client 进行 TLS 通信。
利用 OpenSSL 自带的调试功能，来观察运行的内部细节，起到事半功倍的作用。

[在CentOS[lnmp]上部署新版本SSL协议+ECDHE_RSA正向加密和预防BEAST攻击](https://xuanwobbs.com.cn/archives/2013-07/centos-lnmp-ecdhe_rsa-beast.html)  
[OpenSSL 建立CA，服务器证书请求及签发，客户端测试连接，加密签名工具 等的详细步骤](http://blog.chinaunix.net/uid-174325-id-3563721.html)  