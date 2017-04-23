## How HTTPS Secures Connections.pcapng

1. C->S：Client Hello  
2. S->C：Server Hello  
3. S->C：Certificate  
4. S->C：Server Key Exchange, Server Hello Done  
5. C->S：Client Key Change  
6. C->S：Change Cipher Spec  
7. C->S：Encryted Handshake Message  
8. S->C：Change Cipher Spec, Encryted Handshake Message  

Application Data  

同 `wx.qq.com(tcp.port==57672&57676).pcapng`。