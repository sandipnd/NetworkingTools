CC =     g++
CFLAGS = -g -Wall
OBJ =    trcServer.o util.o

TARG =   tracerouteServer

%.o: %.c
	$(CC) $(CFLAGS) -I.   -c -o  $@ $< 

$(TARG): $(OBJ)
	$(CC) $(CFLAGS) -o $(TARG)  $^ -lpthread

clean:
	rm -f *.o $(TARG) 
