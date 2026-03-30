OBJS:=fwx_uci.o
LIB_NAME:=libfwx_common.so
all: $(OBJS)
	$(CC) -o $(LIB_NAME) $(OBJS) $(LIBS) -shared
%.o:%.c 
	@$(CC) -c -o $@ $< $(CFLAGS) -fPIC
clean:
	rm $(LIB_NAME) *.o
