#### 如何利用tcpreplay重放包到指定目的mac(gg:hh:ii:jj:kk:mm)
```
tcprewrite --enet-smac=aa:bb:cc:dd:ee:ff --enet-dmac=gg:hh:ii:jj:kk:mm  -i a.pcap -o b.pcap
tcpreplay b.pcap
```

#### 如何利用tcpreplay重放包到指定目的ip(192.168.0.11)
```
tcprewrite  --endpoints=192.168.0.1:192.168.0.11  -i a.pcap -o b.pcap
tcpreplay b.pcap
```

#### 如何利用tcprewrite去掉包的vlan tag
```
tcprewrite --enet-vlan=del -i a.pcap -o b.pcap
```
