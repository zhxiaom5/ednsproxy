# ednsproxy

## 简介

基于https://github.com/slene/dnsproxy稍作变动
go实现的dns反向代理
* 支持多个上游dns服务器
* 自带本地缓存，成功的响应缓存在本地，下次客户端请求，有效期内，可以直接响应给用户
* 支持普通dns请求到ecs dns请求的转换
* 单机性能>3万qps，满足单机dns缓存代理的性能要求

## 使用方法

Usage of ./dnsproxy:
#默认跳过ipv6解析
-6    skip ipv6 record query AAAA (default true)  
#是否开始缓存，默认不开启  
-cache
        enable go-cache 
#debug level，默认不开启  
-debug int
        debug level    
#上游dns服务器，可以支持udp和tcp 
-dns ,
        dns address, use , as sep (default "114.114.114.114:53:udp,119.29.29.29:53:udp")  
#ecs ip的地址
-ecsip string
        ecs ip address (default "127.0.0.1") 
#ecs ip的netmask
-ecsnetmask int
        ecs netmask (default 32) 
#缓存过期时间
-expire int
        default cache expire seconds, -1 means use doamin ttl time (default 60) 
#缓存文件
-file string
        cached file (default "cache.dat") #
#监听地址
-local string
        local listen address (default ":53")
#失败响应不缓存
-negcache
        enable negcache
#超时时间
-timeout int
        read/write timeout in ms (default 200)

## 运行示例

./dnsproxy -dns 119.29.29.29:53:udp -cache=true -negcache=true -ecsip 121.9.212.177 -ecsnetmask 32
