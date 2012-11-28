CC =     g++
CFLAGS = -g -Wall
OBJ =    opt.o portScanner.o util.o 

TARG =   portScanner

%.o: %.c
	$(CC) $(CFLAGS) -I.   -c -o  $@ $< 

$(TARG): $(OBJ)
	$(CC) $(CFLAGS) -o $(TARG)  $^  -lpthread -lm

clean:
	rm -f *.o $(TARG) 
