obj-m += firewall.o
firewall-objs := main.o func/func_filter_Protocol.o rule_proc_interface/firewall_rules.o
KDIR := /lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean