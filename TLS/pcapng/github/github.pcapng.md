
@img ![TLS handshake](http://image.beekka.com/blog/201402/bg2014020502.png)

## github-未登录(tcp.port==55104&55109).pcapng

1. C->S：Client Hello  
2. S->C：Server Hello  
3. S->C：Certificate, Server Key Exchange, Server Hello Done  
4. C->S：Client Key Change  
5. C->S：Change Cipher Spec  
6. C->S：Encryted Handshake Message  
7. S->C：Change Cipher Spec, Encryted Handshake Message  
8. C->S/S->C：Application Data  

---

在 Wireshark 解析树中，TLS 为 Secure Sockets Layer。

[A TLS message may span multiple TLS records](http://www.networksorcery.com/enp/protocol/tls.htm).

第 1、2、3、4、6、7.2 步均为 TLSv1.2 Record Layer 中的 ***Handshake Protocol***，  
第 5、7.1 步为 TLSv1.2 Record Layer 中的 ***Change Cipher Spec Protocol***，  
第 8 步为 TLSv1.2 Record Layer 中的 ***Application Data Protocol***: `http-over-tls`。

- **`1.Client Hello`**：
	- TLS Version  
	- Random  
	- [Cipher Suites](http://www.networksorcery.com/enp/protocol/tls.htm)  
	- Compression Methods  
	- Extension: server_name(Server Name Indication extension)  
	- Extension: elliptic_curves  
	- Extension: ec_point_formats(Elliptic curves point formats)  
	- Extension: signature_algorithms  
	- Extension: next_protocol_negotiation  
	- Extension: Application Layer Protocol Negotiation(ALPN Protocol)  
	- Extension: signed_certificate_timestamp  
	- Extension: Extended Master Secret  

- **`2.Server Hello`**：
	- TLS Version  
	- Random  
	- **Session ID**,  (黑体新增)  
	- *Cipher Suite*,  (斜体协定)  
	- *Compression Method*  
	- Extension: renegotiation_info  
	- Extension: server_name(Server Name Indication extension)  
	- **Extension**: ec_point_formats(Elliptic curves point formats)  
	- Extension: *Extended Master Secret*  
	- Extension: Application Layer Protocol Negotiation(*ALPN Next Protocol: http/1.1*)  

	> 该报文(#8) Server Hello 之后开始发送服务器证书，其中包含 `DigiCert Inc1.0`、`www.digicert.com`、`DigiCert SHA2` 等字样。  
> 报文(#9)为证书的部分内容，直到报文(#10)证书才发送完。  
> 报文(#10)证书后面，还一起发送了 Server Key Exchange 和 Server Hello Done 握手协议。  

- **`3.Server Key Exchange`**：EC Diffie-Hellman Server Params
	- TLS Version  
	- Curve Type: named_curve  
	- Named Curve: secp256r1  
	- Pubkey  
	- Signature Hash Algorithm(Hash: SHA512, Signature: RSA)  
	- Signature  

- **`3.Server Hello Done`**：
	- TLS Version  
	- Curve Type: named_curve  

- **`4.Client Key Exchange`**：EC Diffie-Hellman Client Params  
	- TLS Version  
	- Pubkey  

- **`5.Change Cipher Spec`**：  
	- TLS Version  
	- Change Cipher Spec Message  

- **`6.Encryted Handshake Message`**：为 TLS Client Finished  
	- TLS Version  
	- Encrypted Handshake Message  

- **`7.Change Cipher Spec`**：  
	- TLS Version  
	- Change Cipher Spec Message  

- **`7.Encryted Handshake Message`**：为 TLS Server Finished  
	- TLS Version  
	- Encrypted Handshake Message  

## github-SignIn-1(tcp.port==54284).pcapng

1. C->S：Client Hello  
2. S->C：Server Hello  
3. S->C：Certificate, Server Key Exchange, Server Hello Done  
4. C->S：Client Key Change, Change Cipher Spec, Hello Request, Hello Request  
5. S->C：Change Cipher Spec, Encryted Handshake Message  
6. C->S/S->C：Application Data  

第4步为 TLSv1.2 Record Layer: Handshake Protocol: Multiple Handshake Messages

