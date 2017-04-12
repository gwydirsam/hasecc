all : hasecc lscurveparams
hasecc : hasecc.o
	gcc -std=c11 -L/usr/local/opt/openssl@1.1/lib -I/usr/local/opt/openssl@1.1/include -o hasecc hasecc.o -lssl -lcrypto
hasecc.o : hasecc.c
	gcc -std=c11 -L/usr/local/opt/openssl@1.1/lib -I/usr/local/opt/openssl@1.1/include -c hasecc.c
lscurveparams : lscurveparams.o
	gcc -std=c11 -L/usr/local/opt/openssl@1.1/lib -I/usr/local/opt/openssl@1.1/include -o lscurveparams lscurveparams.o -lssl -lcrypto
lscurveparams.o : lscurveparams.c
	gcc -std=c11 -L/usr/local/opt/openssl@1.1/lib -I/usr/local/opt/openssl@1.1/include -c lscurveparams.c
clean :
	rm lscurveparams lscurveparams.o
	rm hasecc hasecc.o
