
@img ![TLS handshake](http://image.beekka.com/blog/201402/bg2014020502.png)

## github-未登录(tcp.port==55104&55109).pcapng

1. C->S：Client Hello  
2. S->C：Server Hello  
3. S->C：CertificateServer Key Exchange, Server Hello Done  
4. C->S：Client Key Change  
5. C->S：Change Cipher Spec  
6. C->S：Encryted Handshake Message  
7. S->C：Change Cipher Spec, Encryted Handshake Message  

Application Data  

- `1.Client Hello`：
	- TLS Version,  
	- Random,  
	- Cipher Suites,  
	- Compression Methods,  
	- Extension: server_name(Server Name Indication extension)；  
	- Extension: elliptic_curves  
	- Extension: signature_algorithms  
- `2.Server Hello`：
	- TLS Version,  
	- Random,  
	- **Session ID**,  (黑体新增)  
	- _Cipher Suite_,  (斜体协定)  
	- _Compression Method_,  
	- Extension: server_name(Server Name Indication extension),   
	- **Extension**: ec_point_formats；  
- `3.Server Key Exchange`：EC Diffie-Hellman Server Params
	- Curve Type  
	- Named Curve  
	- Pubkey  
	- Signature Hash Algorithm  
	- Signature  
- `4.Client Key Exchange`：EC Diffie-Hellman Client Params  
	- Pubkey  
- `6.Encryted Handshake Message`：为 TLS Client Finished  
- `7.Encryted Handshake Message`：为 TLS Server Finished  

## github-SignIn-1(tcp.port==54284).pcapng

1. C->S：Client Hello  
2. S->C：Server Hello  
3. S->C：CertificateServer Key Exchange, Server Hello Done  
4. C->S：Client Key Change, Change Cipher Spec, Hello Request, Hello Request  
5. S->C：Change Cipher Spec, Encryted Handshake Message  

Application Data  
