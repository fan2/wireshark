## tcpdump

```Shell
faner@THOMASFAN-MB0:~|⇒  tcpdump --help
tcpdump version tcpdump version 4.9.0 -- Apple version 79.60.1
libpcap version 1.8.1 -- Apple version 67.60.1
LibreSSL 2.2.7
Usage: tcpdump [-aAbdDefhHIJKlLnNOpqStuUvxX#] [ -B size ] [ -c count ]
		[ -C file_size ] [ -E algo:secret ] [ -F file ] [ -G seconds ]
		[ -i interface ] [ -j tstamptype ] [ -M secret ] [ --number ]
		[ -Q in|out|inout ]
		[ -r file ] [ -s snaplen ] [ --time-stamp-precision precision ]
		[ --immediate-mode ] [ -T type ] [ --version ] [ -V file ]
		[ -w file ] [ -W filecount ] [ -y datalinktype ] [ -z postrotate-command ]
		[ -Z user ] [ expression ]

```

前三句输出对应 `tcpdump --version`，依次为 **tcpdump** 的版本号，及其依赖的 **libpcap** 和 **LibreSSL** 的版本号。

## references

[**调试利器之tcpdump详解**](https://yq.aliyun.com/articles/27292?spm=5176.100239.blogcont27268.24.PcGo7W)

[**聊聊 tcpdump 与 Wireshark 抓包分析**](http://www.jianshu.com/p/a62ed1bb5b20)

[Linux使用tcpdump命令抓包保存pcap文件wireshark分析](http://www.cnblogs.com/bass6/p/5819928.html)

[使用WinPcap和libpcap类库读写pcap文件（001）开发环境配置](http://blog.csdn.net/qpeity/article/details/46716323)  
[使用WinPcap和libpcap类库读写pcap文件（002）PCAP文件格式](http://blog.csdn.net/qpeity/article/details/46717799)  

