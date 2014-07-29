CC_CMD=gcc -fPIC -DNET_SSL -D_REENTRANT -DSOLARIS -D_POSIX_PTHREAD_SEMANTICS
LD_SHAREDCMD=gcc -shared
LD=/usr/ccs/bin/ld -L/etc/lib -ldl
LDSO=$(LD) -G
 
all:
prepare:
 
NS_HOME=/apps/develop/apps/SUNWwbsvr
INCLUDEDIR=$(NS_HOME)/plugins/include
#EXTRA_LDDEFINES=-lssl -lcrypto -R'$$ORIGIN'/lib
EXTRA_LDDEFINES=-lcurl -R'$$ORIGIN'/../lib
 
 
OBJS = holistic35.o
 
INCLUDE_FLAGS=-I$(INCLUDEDIR) -I$(INCLUDEDIR)/base -I$(INCLUDEDIR)/frame -I$(INCLUDEDIR)/nspr -I$(HOME)/usr/local/include
COMMON_DEFS=-DMCC_HTTPD -DXP_UNIX -DSPAPI20
 
 
all: holistic35.so holistic35
 

holistic35:
	$(CC_CMD) -D_TEST_CASES_ holistic35.c -o holistic35 $(COMMON_DEFS) $(INCLUDE_FLAGS) $(EXTRA_LDDEFINES) -lpthread
	
holistic35.so: $(OBJS)
	$(MAKE) prepare
	$(LDSO) $(OBJS) -o holistic35.so $(EXTRA_LDDEFINES)
 
$(OBJS): 
	$(CC_CMD) -D_BUILD_NSAPI_ $(COMMON_DEFS) $(INCLUDE_FLAGS) -c *.c
 
clean:
	rm $(OBJS) holistic35.so holistic35 $(EXTRA_CLEAN)
