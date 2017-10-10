
FLAGS=-g -lcapstone -lpthread

omnitrace:	omnitrace.c
	gcc omnitrace.c $(FLAGS) -o omnitrace

clean:
	rm -f omnitrace *.o
