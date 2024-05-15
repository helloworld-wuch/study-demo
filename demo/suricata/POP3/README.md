#### code source
```
https://github.com/decanio/suricata-np/blob/dev-pop3-v3
```

#### how to do
  1）python3 scripts/setup-app-layer.py POP3
  2）update POP3ParseRequest、POP3ParseResponse、JsonPOP3Logger
  3）当前POP3.patch只是简单解析针对retr命令返回的邮件信息, 可自行扩展记录登录用户名密码或者其他命令之类的
