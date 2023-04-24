MKCERT := $(shell command -v mkcert 2> /dev/null)
127.0.0.1.nip.io.pem 127.0.0.1.nip.io-key.pem:
ifndef MKCERT
	$(error "mkcert not installed. try 'bew install mkcert'")
endif
	mkcert 127.0.0.1.nip.io

server: *.go
	go build -o server .

.PHONY: run
run: server 127.0.0.1.nip.io.pem 127.0.0.1.nip.io-key.pem
	./server
