build:
	nasm -f elf32 strfind.asm -o strfind.o
	gcc -m32 -c test.c -o test.o
	gcc -m32 test.o strfind.o -o test
	./test