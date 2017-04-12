all : hasecc lscurveparams
hasecc : hasecc.o
	gcc -std=c11 -o hasecc hasecc.o -lssl -lcrypto
hasecc.o : hasecc.c
	gcc -std=c11 -c hasecc.c
lscurveparams : lscurveparams.o
	gcc -std=c11 -o lscurveparams lscurveparams.o -lssl -lcrypto
lscurveparams.o : lscurveparams.c
	gcc -std=c11 -c lscurveparams.c
clean :
	rm lscurveparams lscurveparams.o
	rm hasecc hasecc.o
