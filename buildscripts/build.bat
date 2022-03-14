set CGO_ENABLED=0
go build -o frogbot.exe -ldflags "-w -extldflags -static" main.go
