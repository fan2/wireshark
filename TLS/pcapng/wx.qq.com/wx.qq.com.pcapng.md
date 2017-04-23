
@img ![TLS handshake](http://image.beekka.com/blog/201402/bg2014020502.png)

## wx.qq.com(tcp.port==57672&57676).pcapng

1. C->S：Client Hello  
	- TLS Version,  
	- Random,  
	- Cipher Suites,  
	- Compression Methods,  
	- Extension: server_name(Server Name Indication extension)；  
	- Extension: elliptic_curves  
	- Extension: signature_algorithms  
2. S->C：Server Hello  
	- TLS Version,  
	- Random,  
	- **Session ID**,  (黑体新增)  
	- _Cipher Suite_,  (斜体协定)  
	- _Compression Method_,  
	- Extension: server_name(Server Name Indication extension),   
	- **Extension**: ec_point_formats；  
3. S->C：Certificate  
4. S->C：Server Key Exchange(`EC Diffie-Hellman Server Params`), Server Hello Done  
	- Curve Type  
	- Named Curve  
	- Pubkey  
	- Signature Hash Algorithm  
	- Signature  
5. C->S：Client Key Change：`EC Diffie-Hellman Client Params`  
	- Pubkey  
6. C->S：Change Cipher Spec  
7. C->S：Encryted Handshake Message  
	- TLS Client Finished  
8. S->C：Change Cipher Spec, Encryted Handshake Message  
	- TLS Server Finished  

Application Data  

`github-未登录(tcp.port==55104&55109).pcapng` 中将 3 和 4 合为一个包。
