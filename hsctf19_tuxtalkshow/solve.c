#include <stdio.h>
#include <stdlib.h>
#include <time.h>


int main() {
	srand(time(0));

	int array[6] = {0x79, 0x12c97f, 0x135f0f8, 0x74acbc6, 0x56c614e, 0xffffffe2};

	for (int i = 0; i < 6; i++) {
		int num = rand();
		array[i] = array[i] - (num % 10 - 1);
	}
	int sum = 0;
	for (int i = 0; i < 6; i++) {
		sum+= array[i];
	}

	printf("%d\n",sum);
 	return 0;

}
