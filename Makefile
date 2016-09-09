all:	download build

download: netbrane-shared

netbrane-shared:
	git clone git@github.com:jreumann/netbrane-shared;

build: netbrane-shared/capture/flow-records/flow-record.pb.go
	go build nbtool.go;

netbrane-shared/capture/flow-records/flow-record.pb.go:
	protoc --go_out=. netbrane-shared/capture/flow-records/flow-record.proto
		
clean:
	rm -rf netbrane-shared;
	rm -rf nbtool;
