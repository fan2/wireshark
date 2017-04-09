## [Packet capture library (libpcap)](https://wiki.wireshark.org/libpcap)
Wireshark/TShark uses libpcap to capture live network data.

As capture filter strings are directly passed from Wireshark/TShark to libpcap, the available capture filter syntax depends on the libpcap version installed.

More information can be found at the [**tcpdump**](http://www.tcpdump.org/) project page; libpcap and tcpdump are both developed by `tcpdump.org`.

On most modern UN*X platforms libpcap is available. It comes as part of most non-specialized Linux distributions, the free-software BSDs, and Mac OS X; it's installed by default on the BSDs and OS X, and it might be installed by default on the Linux distributions as well. (Specialized Linux distributions such as those for small embedded boxes might omit it.)

A Windows version of libpcap is also available which is named [WinPcap](https://wiki.wireshark.org/WinPcap).

The libpcap file format description can be found at: [Development/LibpcapFileFormat](https://wiki.wireshark.org/Development/LibpcapFileFormat)

### [libpcap](https://github.com/the-tcpdump-group/libpcap)
the LIBpcap interface to various kernel packet capture mechanism

[linux下libpcap抓包分析](http://www.cnblogs.com/Seiyagoo/archive/2012/04/28/2475618.html)

[libpcap使用](http://blog.csdn.net/htttw/article/details/7521053)

## [Windows Packet Capture (WinPcap)](https://wiki.wireshark.org/WinPcap)
WinPcap is the Windows version of the [libpcap](http://www.tcpdump.org/) library; it includes a driver to support capturing packets.

Wireshark uses this library to capture live network data on Windows.

See [CaptureSetup/CapturePrivileges](https://wiki.wireshark.org/CaptureSetup/CapturePrivileges) for information about using the [WinPcap](http://www.winpcap.org/) driver with Wireshark.

General information about the WinPcap project can be found at the [**WinPcap**](http://www.winpcap.org/)/WinDump web site.

The libpcap/WinPcap file format description can be found at: [Development/LibpcapFileFormat](https://wiki.wireshark.org/Development/LibpcapFileFormat)

### [WinPcap](http://baike.baidu.com/item/winpcap)
The industry-standard windows packet capture library

WinPCap(windows packet capture)是windows平台下一个免费，公共的网络访问系统。开发winpcap这个项目的目的在于为win32应用程序提供访问网络底层的能力。

[WinPcap，NDIS 和 NPF](http://www.cnblogs.com/zhcncn/articles/2864341.html)

[WinPcap开发（一）：零基础入门](http://www.freebuf.com/articles/system/103526.html)
