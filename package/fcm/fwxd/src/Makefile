OBJS:=fwx_user.o fwx_netlink.o fwx_ubus.o fwx_stat.o fwx_config.o fwx_utils.o main.o  fwx_app_filter.o fwx_mac_filter.o fwx_record.o fwx_common.o fwx_system.o fwx_network.o fwx_wireless.o check_main.o
EXEC:=fwxd
all: $(OBJS)
	$(CC) -o $(EXEC) $(OBJS) $(LIBS)
clean:
	rm $(EXEC) *.o
