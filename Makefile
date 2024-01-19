GCC_FLAGS = -Wextra -Werror -Wall -Wno-gnu-folding-constant

all: primitive_test.o userfs.o
	gcc $(GCC_FLAGS) primitive_test.o userfs.o

primitive_test.o: primitive_test.c
	gcc $(GCC_FLAGS) -c primitive_test.c -o primitive_test.o

test.o: test.c
	gcc $(GCC_FLAGS) -c test.c -o test.o -I ../utils

userfs.o: userfs.c
	gcc $(GCC_FLAGS) -c userfs.c -o userfs.o
