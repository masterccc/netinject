# Add -DX64 flag if x86_64

netinject: netinject.o design.o
	gcc -o netinject netinject.o design.o

netinject.o: netinject.c
	gcc -DX64 -c netinject.c

design.o: design.c
	gcc -c design.c

clean:
	rm *.o

