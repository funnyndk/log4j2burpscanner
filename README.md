# 本工具仅为企业测试漏洞使用，严禁他人使用本工具攻击
本插件基于 https://github.com/f0ng/log4j2burpscanner/ 进行改造，在此感谢f0ng师傅在本项目上做出的贡献。

f0ng师傅的readme在https://github.com/funnyndk/log4j2burpscanner/README-f0ng.md

## 如何食用？
### dns_mothed
本插件支持3个dns平台：
	https://dns.xn--9tr.com/(默认使用)
	http://ceye.io/
	http://www.dnslog.cn/(由于延迟较高不建议使用)
本插件支持自定义dns平台

### log4j2burpscanner.properties
插件第一次运行时，会在burp目录下创建log4j2burpscanner.properties配置文件。其中的各项含义如下：
log_method=0		默认使用第0个dns平台

passivepattern=false		配合burp自带的被动扫描功能，默认关闭

ceyetoken=xxxxxx		ceye.io的用户token

ceyednslog=xxxx.ceye.io	ceye.io的用户dns地址

privatedns=xxxxxx		用户自定义dns地址

isuseUserAgentTokenXff=true	是否测试请求中的UA头/token头

isuseXfflists=false		是否测试Xff(X-forwarded-for)等请求头

isuseAllCookie=true		是否测试cookie

isuseRefererOrigin=false	是否测试Referer

isuseContenttype=false	是否测试Content-type

isuseAccept=false		是否测试useAccept

custom_dnslog_protocol=jndi:ldap:	ayload中"jndi:ladp:"的位置字段，可以自定义"jndi:"的bypass方式,例如输入${lower:j}ndi${::-:}lda${lower:p}:

dnslog_protocol_index=1		payload中"jndi:ladp:"的位置字段的一些默认提供项，设置为0就可使用上一项自定义的custom_dnslog_protocol，设置8为最强bypass

whitelists=*.gov.cn *.edu.cn	不进行测试的host名单

customlists=X-Client-IP X-Requested-With X-Api-Version	需要额外添加并测试的请求头，用空格分隔

config中有save configuration，load configuration，test dnslog三个按钮，分别用于保存当前设定的properties，加载properties文件和测试当前选择的dns平台是否可用。


### output
插件加载完成后，应当出现如下字样

[+]               load successful!      

[+]        log4j2burpscanner v0.22.funny  

[+] https://github.com/f0ng/log4j2burpscanner

[+]                 recode by funnyndk      

[+]using log.xn--9tr.com now!

[+]dns address : XXXxxxXXX

[+]dns token : xxx

[+]You also can request to    XXXxxxXXX    to see dnslog

其中dns address为payload中请求的域名，xxx 可以人为查看解析记录

### menu
对请求包右键的菜单栏中，新增了"Send to log4j2 Scanner"选项，点击后将对包进行注入改造并且测试。完成dns询问后，会在log4j2 RCE栏中展示恶意请求和结果等等

### payload

真正的payload格式如下

"${"+jndiparam+dnsldaprmi+"//"+random+"."+chosen_dnslog+"}"

pyload将根据设定和请求类型，注入所有的请求头或GET参数或POST参数中(存在特殊情况无法识别)


## FAQ

Q：为什么安装插件失败，提示java.lang.ClassFoundException: burp.BurpExtender

A：请使用jdk1.8，本插件开发环境为jdk1.8，测试环境为Burp Suite Pro 1.7.31。如果已使用jdk1.8，请更新jdk小版本。开发机版本为jdk1.8.0_291，请至少与之一致，

Q：为什么点了"Send to log4j2 Scanner"选项，log4j2 RCE栏中没有出结果

A：由于网络延迟，扫描可能较慢。或是请求包出现问题，没有相应返回，请检查是否被防火墙等设备封禁。

Q：为什么加载插件显示"load ERROR"

A：一般由于选择的dns平台无法正常访问，也有可能配置文件出现异常。

## dev or update note

0.19.funny dev note

20220617 dev list

add a "dnslog.cn" dnslog platfrom chocie            done!

make it to a slowly passively auto-detection

more methods to bypass                              update continually...

more position in request to inject log4j2 payload   done!

20220623 dev list

fix the code bug                                    done!

test all program	                            done!

0.20.funny update note

20220629 update list 

fix the bug - cant send request without response to log4j2 scanner

update the feature - log4j2 scanner will show the records even though of which the request doesnt get a response

0.21.funny update note

20220704 update list 

update the feature - change how the plugin modifies custom_dnslog_protocol

0.22.funny update note

20220801 update list

optimize the code - use "Abstract Factory" to dnslog platforms list, make it more easy to maintain current platforms or increase a new one

update the feature - add a random bypass mode like j => ${"random_str":"random_str":"random_str"... - j}

update the feature - support privatedns mode

0.23.funny update note

20220818 update list

fix the bug - print massage with a lot of "null" when dnslog platform is failed 

fix the bug - X-forward-for can be disabled

fix the bug - a test println forgot to delete

20230320 update list

optimize the code - change all chinese comment to english comment 

optimize the code - optimize the function askDnslogRecordOnce

fix the bug - dnslog.cn cant work, because the missing cookie of request