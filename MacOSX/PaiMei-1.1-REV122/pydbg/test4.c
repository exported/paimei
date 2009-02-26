
float foo(int x){
	printf("Fooing %d\n", x);
	float y = (float) 1/(x-6);
	return y;
}

int main(int argc, char *argv[]){
	sleep(15);
	printf("%f\n", foo(atoi(argv[1])));
}

