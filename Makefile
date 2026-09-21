libs=$(shell pkg-config --libs --cflags gpgme)

build:
	rm ./main -f
	gcc main.c $(libs) -o main
	echo "-------------------------------"
	./main
	rm ./main -f
