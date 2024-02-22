
TARGETBIN=ot_example

MYCFLAGS:=-Wall -O

SRCFILES=ot_example.c

OBJS=$(SRCFILES:.c=.o)

all: $(TARGETBIN)

%.o: %.c
	$(CC) $(MYCFLAGS) -o $@ -c $<

$(TARGETBIN): $(OBJS)
	$(CC) -o $(TARGETBIN) $(OBJS) $(LDFLAGS) -lpthread

clean:
	rm -f *.o $(TARGETBIN)
