#include <stdio.h>
#include <stdlib.h>
#include <time.h>


int main() {

	srand(time(0));

	char secret[504];

	for (int i = 0; i < 0x32; i++) {
		int sec = rand() % 100;
		printf("%d\n", sec);
	}
	return 0;
}
