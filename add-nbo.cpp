#include<stdio.h>
#include<stdint.h>
#include<stddef.h>
#include<netinet/in.h>

int main(int argc, char **argv)
{
	FILE *fp1 = fopen(argv[1], "r"); 
	FILE *fp2 = fopen(argv[2], "r");
	
	uint32_t a, b, sum;

	fread(&a, 4, 1, fp1);
	fread(&b, 4, 1, fp2);
	a = ntohl(a);
	b = ntohl(b);
	sum = a + b;
	printf("%d(0x%x) + %d(0x%x) = %d(0x%x)\n", a, a, b, b, sum, sum);

	fclose(fp1);
	fclose(fp2);
}

	
