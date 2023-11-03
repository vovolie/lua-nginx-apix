API网关加密
================

**lua-nginx-apix** 是一个加密http请求的中间件网关，其工作原理是客户端把http请求的header和body通过xxtea进行加密，发送到nginx，再由nginx对内容进行还原代理到真实后端。
同理，发送也是通过xxtea加密后发送。

## 加密原理
设置固定密钥
md5后取随机位数作为xxtea 的key（自行定义）
把 加密体 + key + 随机位置(10, 20) 发送



