# atk_mysql_spy
一个捕获MySQL数据包并处理的工具
目前只支持监听TCP

## 参数说明
bpf: Berkeley Packet Filter, 流量监听的过滤规则, 目前只支持TCP协议, 请务必添加"tcp"限制, 避免不必要的限制
dev: 指定监听的网卡
interval: 输出流量统计信息的间隔时间, 单位 秒 (raw-utf8模式无效)
limit: 每次输出的统计信息的条数
server-ip: 指定mysql实例的ip (sql模式必填)
server-port: 指定mysql实例的port (sql模式必填)
stype: 模式类型, 目前包括3种模式

## 3种模式
1. sql
  根据sql特征统计数据库流量
  必须指定 server-ip 和 server-port 参数, 标记mysql实例的地址
  e.g.:
  ./atk_mysql_spy --bpf="tcp port 3306" --dev=eth0 --server-ip=127.0.0.1 --server-port=3306 --stype=sql
2. conn
  根据建立的连接统计每个连接使用的流量
  e.g.:
  ./atk_mysql_spy --bpf="tcp" --dev=eth0 --stype=conn
3. raw-utf8
  直接以utf-8编码解析监听到的流量, 相当于实时的抓包查看
  e.g.:
  ./atk_mysql_spy --bpf="tcp" --dev=eth0 --stype=raw-utf8
