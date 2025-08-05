# ezfirewall

make all  // 编译文件得到 firewall.ko 模块

sudo insmod firewall.ko  // 加载内核模块

dmesg -w // 查看内核缓冲区日志，可以看到 firewall.ko 是否成功加载

sudo rmmod firewall // 卸载模块

make clean // 清理文件



该模块运行后在 /proc/ 下创建一个 firewall 目录，其中有 rules 文件。

echo "ip protocol号 action"  // 添加规则

action 1 禁止 

action 0 允许



卸载模块时自动清理规则。