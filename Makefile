main: main.o
	gcc -o main main.o -lpcap
main.o: main.c
	gcc -c main.c 
clean: rm -f main.o main
