[数字证书及CA的扫盲介绍](http://kb.cnblogs.com/page/194742/)  
[数字证书及其认证过程](http://blog.csdn.net/cyy089074316/article/details/9071951)  

数字证书的内部格式是由CCITT X.509国际标准所规定的

所谓根证书是神马？证书的信任链条是环环相扣的，根证书就是一开始就被信任的证书。

根证书是被严格限制和确认的，根证书的颁发者被称之为Certificate Authority，简称CA。其实信任的根证书不如说是信任CA罢了。

操作系统里都会内置一份可信的根证书列表，（Firefox的根证书列表是独立于操作系统之外的），这个列表里的证书会被严格的审核以确保安全与可靠。

可以运行“certmgr.msc”打开证书控制台。然后从控制台窗口左侧的控制台树中依次进入“证书-当前用户”→“受信任的根证书颁发机构”→“证书”，随后右侧的窗口中会显示本机预置的所有根证书颁发机构。

写得很棒，有个小错误：“某家根证书颁发机构被黑客攻破，导致这些大企业所用的证书私钥被窃取。”大企业的私钥毋须告知CA，实际上攻击者盗走的是CA的私钥，并利用其签发假冒的google证书实现中间人攻击。详见http://en.wikipedia.org/wiki/DigiNotar

## 12306
[网上购票由于安全警告无法登录问题说明](http://www.12306.cn/mormhweb/kyfw/question/201505/t20150511_16459.html)

用户在点击客运服务后常出现IE浏览器报出的安全警告，“Internet Explore已阻止此12306.cn网站显示有安全证书错误的内容”、“内容被阻止，因为该内容没有签署有效的安全证书”等。其原因是没有导入12306.cn网站客运首页所载的根证书。为了保证用户顺利进行12306.cn网站的使用，请先将根证书按说明进行导入即可。

[12306.cn 购票为什么要安装根证书？](https://www.zhihu.com/question/19974739)  
[为什么在12306买火车票要装根证书？](http://www.williamlong.info/archives/3461.html)  
[在线买火车票为什么要安装根证书？](http://www.williamlong.info/archives/3461.html)

## [U盾](http://baike.baidu.com/item/u%E7%9B%BE)
### [boc](http://www.boc.cn/)
[中国银行网银证书安全使用常识大汇总](http://www.southmoney.com/touzilicai/yinhang/586305.html)

### [icbc](http://www.icbc.com.cn/icbc/)
[中国工商银行 网上银行客户证书使用指南](http://www.icbc.com.cn/icbc/html/download/xitongqudong/aqkj1.htm)  
[中国工商银行 U盾(个人客户)](http://www.icbc.com.cn/ICBC/%E7%94%B5%E5%AD%90%E9%93%B6%E8%A1%8C/%E7%94%B5%E5%AD%90%E9%93%B6%E8%A1%8C%E4%BA%A7%E5%93%81/%E5%AE%89%E5%85%A8%E6%9C%8D%E5%8A%A1/u%E7%9B%BE%E4%B8%AA%E4%BA%BA%E5%AE%A2%E6%88%B7/)

USBKey客户证书技术是2003年由工商银行率先推出的，并已经获得了国家专利，可以真正确保网上银行的安全性。客户信息一经下载到USBKey客户证书的智能芯片内，便是唯一的不可复制的身份证明。

### [cmb](http://www.cmbchina.com/)
[招商银行 数字证书的概念](http://www.cmbchina.com/cmbpb/PFHelpURL/v60/HelpPage/206/02011.htm)  
[招商银行 证书申请及使用指南](http://www.cmbchina.com/personal/netbank/NetbankInfo.aspx?guid=7d5da554-96b0-4296-bcc1-aab6cc1a5658)

招商银行个人网上银行专业版采用标准数字证书体系和精尖加密技术，以“优KEY”（一种USB智能存储设备）作为数字证书的存储介质，为您提供高级别的安全保障。

## [银行的USB KEY里面包含的是什么？](https://zhidao.baidu.com/question/346115551.html)

USB Key是一种USB接口的硬件设备。它内置单片机或智能卡芯片，有一定的存储空间，可以存储用户的私钥以及数字证书，利用USB Key内置的公钥算法实现对用户身份的认证。由于用户私钥保存在密码锁中，理论上使用任何方式都无法读取，因此保证了用户认证的安全性。
USB Key是指硬件数字证书载体。

USB Key主要用于网络认证，锁内主要保存数字证书和用户私钥。
USB KEY也叫UKEY、USBKey、USB Token，国内习惯翻译成 U盾 或者 优盾。
工行的USB Key产品为“U盾”，招行的USB Key产品为“优Key”。

一般来说，USBKey有：
1、一个唯一的序列号（SN）。
2、有您的数字证书，数字证书含有您的公钥信息和CA对该证书的签名值。
3、您数字证书对应的私钥。

CA 的公钥一般不保存在 USBKey 里，而在安装包程序里，在安装的时候，安装包会向系统注册您数字证书的 CA 的证书。

用户登录网银一般是做的双向认证，CA 会给网银服务器颁发一个服务器证书，客户端首先会验证服务器证书，再用客户端证书与服务器协商一个SSL通讯用的对称密钥，来保证数据数据通讯过程的安全。

## RSA SecureID token
[RSA SecurID 动态令牌的原理是什么？](https://www.zhihu.com/question/20603471)  
[app与后台的token、sessionId、RSA加密登录认证与安全解决方案](http://blog.csdn.net/jack85986370/article/details/51362278)

