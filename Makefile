build:
	rm ./main -f
	gcc main.c -o main
	echo "-------------------------------"
	./main
