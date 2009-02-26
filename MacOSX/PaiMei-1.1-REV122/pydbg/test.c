int main(){
	int x=0;
	printf("x is at %x\n", &x);
	while(1){
		printf("%d\n", x);
		x++;
		sleep(1);
	}
}
