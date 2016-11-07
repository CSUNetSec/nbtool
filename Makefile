all:	build

build: 
	go build nbtool.go;

clean:
	rm -f nbtool;
