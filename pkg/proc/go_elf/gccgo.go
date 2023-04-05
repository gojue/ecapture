package main

/*
extern void eprint(int i);

void foo(void) {
	int i;
	for (i=0;i<10;i++) {
		eprint(i);
	}
}
*/
import "C"

func Foo() {
	C.foo()
}

func main() {
	Foo()
}
