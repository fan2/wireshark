
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

6 为 TLS Client Finished；7 为 TLS Server Finished。

## github-SignIn-1(tcp.port==54284).pcapng

1. C->S：Client Hello  
2. S->C：Server Hello  
3. S->C：CertificateServer Key Exchange, Server Hello Done  
4. C->S：Client Key Change, Change Cipher Spec, Hello Request, Hello Request  
5. S->C：Change Cipher Spec, Encryted Handshake Message  

Application Data  
