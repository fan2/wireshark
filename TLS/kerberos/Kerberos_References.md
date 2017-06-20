SSO 是在多个应用系统中，用户只需要登录一次就可以访问所有相互信任的应用系统。

## SSO([Single sign-on](https://en.wikipedia.org/wiki/Single_sign-on))
Single sign-on (SSO) is a property of access control of **multiple** related, yet independent, software systems. With this property, a user logs in with a single ID and password to gain access to a connected system or systems *without* using different usernames or passwords, or in some configurations seamlessly sign on at each system. This is typically accomplished using the [Lightweight Directory Access Protocol](https://en.wikipedia.org/wiki/Lightweight_Directory_Access_Protocol) (LDAP) and stored LDAP databases on (directory) servers.[1] A simple version of single sign-on can be achieved over IP networks using *cookies* but only if the sites share a common DNS parent domain.[2]

For clarity, it is best to refer to systems requiring authentication for each application but using the ***same credentials*** from a directory server as `Directory Server` Authentication and systems where a single authentication provides access to multiple applications by passing the ***authentication token*** seamlessly to configured applications as Single Sign-On.

Conversely, single sign-off is the property whereby a single action of signing out terminates access to multiple software systems.

As different applications and resources support different [authentication](https://en.wikipedia.org/wiki/Authentication) mechanisms, single sign-on must internally **store** the credentials used for initial authentication and *translate* them to the credentials required for the different mechanisms.

Other shared authentication schemes include [OAuth](https://en.wikipedia.org/wiki/OAuth), [OpenID](https://en.wikipedia.org/wiki/OpenID), [OpenID Connect](https://en.wikipedia.org/wiki/OpenID_Connect) and [Facebook Connect](https://en.wikipedia.org/wiki/Facebook_Connect). However, these authentication schemes require the user to enter their login credentials each time they access a different site or application so they are not to be confused with SSO.

To be precise, OAuth is not strictly an authentication scheme but an [authorization](https://en.wikipedia.org/wiki/Authorization) protocol: it provides a way for the users to ***grant access*** on their own behalf to other websites or applications using some access keys. The main purpose of the protocol is to exchange the access credentials required for the authentication and not the authentication itself.

### Benefits
Benefits of using single sign-on include:

- Mitigate risk for access to 3rd-party sites (user passwords not stored or managed externally)  
- Reduce password fatigue from different user name and password combinations  
- Reduce time spent re-entering passwords for the same identity  
- Reduce IT costs due to lower number of IT help desk calls about passwords[3]  

SSO ***shares*** centralized authentication servers that all other applications and systems use for authentication purposes and combines this with techniques to ensure that users do not have to actively enter their credentials more than once.

## SAML
[SAML](https://en.wikipedia.org/wiki/Security_Assertion_Markup_Language)（Security Assertion Markup Language）即安全声明标记语言， 它是一个基于XML的标准，用于在不同的安全域(security domain)之间交换认证和授权数据。

@img ![Single sign-on using SAML in a Web browser](https://upload.wikimedia.org/wikipedia/en/0/04/Saml2-browser-sso-redirect-post.png)

### Jive [Configuring SSO with SAML](https://docs.jivesoftware.com/jive/6.0/community_admin/index.jsp?topic=/com.jivesoftware.help.sbs.online_6.0/admin/UnderstandingSSOKerberos.html)

### AWS [身份提供商和联合](http://docs.aws.amazon.com/zh_cn/IAM/latest/UserGuide/id_roles_providers.html)

### [Dev Overview of SAML](https://developers.onelogin.com/saml)
@img ![SAML SSO Flow](https://developers.onelogin.com/assets/img/pages/saml/sso-diagram.svg)

## Kerberos
### [Understanding Kerberos concepts](https://docs.typo3.org/typo3cms/extensions/ig_ldap_sso_auth/SSO/Kerberos.html)
@img ![kerberos-ticket-exchange](https://docs.typo3.org/typo3cms/extensions/ig_ldap_sso_auth/_images/kerberos-ticket-exchange.png)

### SSO Configuring
#### [Sun OpenSSO](https://docs.oracle.com/cd/E19681-01/820-3746/6nf8qcvgh/index.html)
Chapter 18 Using the Windows Desktop Single Sign-On Authentication Module

![Figure 18–1 Deployment Architecture for OpenSSO Windows Desktop SSO Authentication Module](https://docs.oracle.com/cd/E19681-01/820-3746/images/WSSO2.gif)  

![Figure 18–2 Process Flow for Windows Desktop SSO Authentication](https://docs.oracle.com/cd/E19681-01/820-3746/images/WSSOFlow.gif)  

#### [Single Sign-On in Windows 2000 Networks](https://msdn.microsoft.com/en-us/library/bb742456.aspx)
![Figure 1: Basic Transactions in the Kerberos Protocol](https://msdn.microsoft.com/en-us/library/bb742456.ntks01_big(l=en-us).gif)  

![Figure 2: Cross-Realm Referrals](https://i-msdn.sec.s-msft.com/dynimg/IC15653.gif)

#### Cisco [Configuring Active Directory Single Sign-On](http://www.cisco.com/c/en/us/td/docs/security/nac/appliance/configuration_guide/49/cas/49cas-book/s_adsso.html)
![Figure 8-1 General Process for Kerberos Ticket Exchange](http://www.cisco.com/c/dam/en/us/td/i/100001-200000/180001-190000/183001-184000/183467.ps/_jcr_content/renditions/183467.jpg)

#### 华为 [SSO集成](http://support.huawei.com/enterprise/docinforeader!loadDocument1.action?contentId=DOC1000093079&partNo=10052)

![图2-1 SSO系统逻辑结构图](http://support.huawei.com/enterprise/product/images/be1ed5d611e948538dd05ab5791e0954)

#### [How To Configure Browser-based SSO with Kerberos/SPNEGO and Oracle WebLogic Server](http://www.oracle.com/technetwork/articles/idm/weblogic-sso-kerberos-1619890.html)
@img ![Figure 1: Machine Configuration for SPNEGO/Kerberos scenario](http://www.oracle.com/ocom/groups/public/@otn/documents/digitalasset/1619913.jpg)

## [Alfresco & CAS SSO](http://www.seedim.com.au/content/alfresco-cas-sso)
![CAS flow](http://www.seedim.com.au/sites/default/files/images/casblog.png)

## SlideShare
[A Survey on SSO Authentication protocols: Security and Performance](https://www.slideshare.net/MohammadAminSaghizad/a-survey-on-sso-authentication-protocols-security-and-performance)  
[Access Control Authentication Methods](https://www.slideshare.net/hawa143/week3-lecture)  
![SSO: Kerberos Steps](https://image.slidesharecdn.com/week3-lecture-130129073718-phpapp01/95/week3-lecture-33-638.jpg?cb=1359445181)  

## blog
[Kerberos简介](http://www.cnblogs.com/idior/archive/2006/03/20/354027.html)  
[SSO单点登录系列](http://blog.csdn.net/ae6623/article/category/1402098)  
[CAS 实现单点登录（SSO）](http://blog.csdn.net/hejingyuan6/article/details/44277023)  

[基于Cookie实现的SSO服务源码分析](https://my.oschina.net/kanlianhui/blog/393276)

![CAS Browser Single-Signon Sequence Diagram](https://static.oschina.net/uploads/img/201511/04073455_iD5D.png)

[Kerberos单点登录实现过程](http://dsw.iteye.com/blog/333351)  
[SSO的一个实例就是Kerberos](http://blog.sina.com.cn/s/blog_43b0f8650100pa1a.html)  
[kerberos认证原理](http://blog.csdn.net/wulantian/article/details/42418231)  
[SSO(Single Sign-on) in Action(上篇)](http://www.blogjava.net/security/archive/2006/10/02/sso_in_action.html)  

## OAuth
[OAuth2.0简介](http://wiki.open.qq.com/wiki/mobile/OAuth2.0%E7%AE%80%E4%BB%8B) [OAuth2.0开发文档](http://wiki.open.qq.com/wiki/mobile/OAuth2.0%E5%BC%80%E5%8F%91%E6%96%87%E6%A1%A3)  
[QQ登录（OAuth2.0）](http://www.cnblogs.com/wu-jian/p/3134959.html)  
[使用OAuth2.0协议的github、QQ、weibo第三方登录接入总结](http://www.cnblogs.com/gabrielchen/p/5800225.html)  
