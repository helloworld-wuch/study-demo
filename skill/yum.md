#### 如何用yum只下载rpm包，并下载在指定路径
```
yumdownloader tcpdump --resolve --destdir=/download_path/
使用--resolve选项时，会将该包的所有依赖包也下载下来
```
