
@img ![TLS handshake](http://image.beekka.com/blog/201402/bg2014020502.png)

## wx.qq.com(tcp.port==57672&57676).pcapng

1. C->S：Client Hello  
2. S->C：Server Hello  
3. S->C：Certificate  
4. S->C：Server Key Exchange, Server Hello Done  
5. C->S：Client Key Change  
6. C->S：Change Cipher Spec  
7. C->S：Encryted Handshake Message  
8. S->C：Change Cipher Spec, Encryted Handshake Message  

Application Data  

`github-未登录(tcp.port==55104&55109).pcapng` 中将 3 和 4 合为一个包。

7 为 TLS Client _Finished_；8 为 TLS Server _Finished_。
