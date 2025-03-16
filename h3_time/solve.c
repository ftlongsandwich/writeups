#include <stdio.h>
#include <stdlib.h>
#include <time.h>


int main() {
	int seed = time(0);
	srand(seed);
	unsigned int secret = rand();
	printf("%u\n", secret);

	return 0;
}
