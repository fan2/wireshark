# TLSPARAMS - Cipher Suites
Transport Layer Security (TLS) Parameters [@ietf](https://www.ietf.org/assignments/tls-parameters/tls-parameters.txt) [@iana](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml)

[SSL/TLS CipherSuite 介绍](https://blog.helong.info/blog/2015/01/23/ssl_tls_ciphersuite_intro/)  

> In SSL, the key exchange, symmetric encryption and MAC algorithm are all **grouped** together into a single aggregate notion called a [***cipher suite***](https://en.wikipedia.org/wiki/Cipher_suite).

> Before TLS version 1.3, a cipher suite is a named **combination** of authentication, encryption, message authentication code (MAC) and key exchange algorithms used to negotiate the security settings. The format of cipher suites is modified since TLS 1.3. In the current TLS 1.3 draft document, cipher suites are only used to negotiate encryption and HMAC algorithms.

## Cipher Suite 构成
每个 CipherSuite 分配有 2 字节的短整型来标识，[TLS Cipher Suite Registry](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4)  定义了 Value 对应的 Description：

Value |	Description  |	DTLS-OK |	Reference 
------|--------------|----------|--------------------------------
0xC0,0x2F |	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 |	Y |	[[RFC5289](http://www.iana.org/go/rfc5289)]

```C
CipherSuite TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256    = {0xC0,0x2F};
```

每个 Cipher Suite 是由4个算法原语组合而成：

- Key Exchange (Kx)：密钥交换协商协议。主流有两种：DH 和 ECDH。

	> 自从斯诺登爆料了 NSA 的 HTTPs 破解方案以后，现在的密钥交换算法，普遍流行 **PFS**（Perfect Forward Secrecy），把 DH, ECDH 变成 DHE,ECDHE 。  

- Authentication (Au)：非对称认证算法，常见有三种：DSA/RSA/ECDSA。  

	> 目前最主流的是 **RSA** ( 2048 bit 及以上)；ECDSA 是新兴趋势，例如 gmail，facebook 都在迁移到 ECDSA；DSA 由于只能提供1024bit，已被建议禁用。

- Encryption(Enc)：对称加密算法，主流趋势是使用 **AES**。

	> 其他的有：DES（已被淘汰）；RC4（不建议使用）；3DES（不建议使用）；Camellia（貌似日本人搞的） 等。

- Message Authentication Code(MAC)：消息认证码算法，主流有 SHA1、SAH256、SHA384 等。  

	> TLS 中使用了 **HMAC** 模式，而不是原始的 SHA1、SHA256 等；google 已在淘汰 MD5 了。  

通过 `openssl ciphers -v` 命令可以列举 OpenSSL 支持的所有 ciphers：

![openssl-ciphers](images/openssl-ciphers-v.png)

## 参考
[How do browsers negotiate SSL/TLS connection parameters?](https://security.stackexchange.com/questions/94799/how-do-browsers-negotiate-ssl-tls-connection-parameters)  
[What is ECDHE-RSA?](https://security.stackexchange.com/questions/14731/what-is-ecdhe-rsa)  
[What's the GCM-SHA 256 of a TLS protocol?](https://crypto.stackexchange.com/questions/26410/whats-the-gcm-sha-256-of-a-tls-protocol)  
[decompose cipher suite: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256](https://crypto.stackexchange.com/questions/26410/whats-the-gcm-sha-256-of-a-tls-protocol)  
[Proposal to Change the Default TLS Ciphersuites Offered by Browsers](https://briansmith.org/browser-ciphersuites-01)  
[TLS 1.2 handshake problem?](http://grokbase.com/t/apache/users/126c3zespf/httpd-tls-1-2-handshake-problem)  
[TLS Version specific cipher suites](https://security.stackexchange.com/questions/130136/tls-version-specific-cipher-suites)  

[密码学笔记](http://www.ruanyifeng.com/blog/2006/12/notes_on_cryptography.html)  [密码学一小时必知](https://blog.helong.info/blog/2015/04/12/translate-Everything-you-need-to-know-about-cryptgraphy-in-1-hour/)  
[数字签名和数字证书](http://blog.csdn.net/phunxm/article/details/16344837)  [数字证书的基础知识](http://www.enkichen.com/2016/02/26/digital-certificate-based/)  

[公钥、秘钥、对称加密、非对称加密总结](http://my.oschina.net/shede333/blog/359290)  
[和安全有关的那些事](http://blog.csdn.net/bluishglc/article/details/7585965)  

[现代密码学实践指南](https://blog.helong.info/blog/2015/06/06/modern-crypto/) [byronhe@tencent](http://www.gad.qq.com/article/detail/12527)  
[TLS协议分析 与 现代加密通信协议设计](https://blog.helong.info/blog/2015/09/07/tls-protocol-analysis-and-crypto-protocol-design/) [byronhe@tencent](http://www.gad.qq.com/article/detail/12531)  