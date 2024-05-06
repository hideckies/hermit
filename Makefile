pb_dir = "pkg/protobuf"
common_proto = "commonpb/common.proto"
rpc_proto = "rpcpb/rpc.proto"

.PHONY: default
default:
	@ echo "[x] Not enough argument. Specify the target:"
	@ echo "  C2 server => 'make server'"
	@ echo "  C2 client => 'make client'"
	@ echo "  Both      => 'make all'"

_compile_protobufs:
	@ echo "Compiling protobufs..."
	@ go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.28
	@ go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.2
	@ cd "$(pb_dir)"; protoc -I=. --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative $(common_proto)
	@ cd "$(pb_dir)"; protoc -I=. --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative $(rpc_proto)

.PHONY: all
all: server client

.PHONY: server
server:
	@ echo "[*] Building the C2 server..."
	@ chmod +x install.sh; ./install.sh server
	$(MAKE) _compile_protobufs
	@ echo "[*] Compiling the Go project..."
	@ go build -ldflags="-s -w" -trimpath -o ./hermit pkg/server/main.go
	@ sudo setcap 'cap_net_bind_service=+ep' ./hermit
	@ echo "[+] Done."
	@ echo ""
	@ echo "Run './hermit --help'"

.PHONY: client
client:
	@ echo "[*] Building the C2 client..."
	@ chmod +x install.sh; ./install.sh client
	$(MAKE) _compile_protobufs
	@ echo "[*] Compiling the Go project..."
	@ go build -ldflags="-s -w" -trimpath -o ./hermit-client pkg/client/main.go
	@ sudo setcap 'cap_net_bind_service=+ep' ./hermit-client
	@ echo "[+] Done."
	@ echo ""
	@ echo "Run './hermit-client --help'"

.PHONY: server-clean
server-clean:
	@ echo "[*] Cleaning up the C2 server..."
	@ rm -rf $(HOME)/.hermit/server
	@ rm -f ./hermit
	@ echo "[+] Done."

.PHONY: client-clean
client-clean:
	@ echo "[*] Cleaning up the C2 client..."
	@ rm -rf $(HOME)/.hermit/client
	@ rm -f ./hermit-client
	@ echo "[+] Done."

.PHONY: clean
clean: server-clean client-clean
	@ rm -rf $(HOME)/.hermit
