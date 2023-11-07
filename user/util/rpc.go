package util

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
)

func StartRpcServer(stopper chan os.Signal, sockPath string) {
	os.Remove(sockPath)

	uaddr, err := net.ResolveUnixAddr("unix", sockPath)
	if err != nil {
		fmt.Println(err)
		return
	}

	l, err := net.ListenUnix("unix", uaddr)
	if err != nil {
		fmt.Println("Error listening:", err)
		return
	}

	defer l.Close()

	os.Chmod(sockPath, 0o777)

	go func() {
		<-stopper
		fmt.Println("\nReceived Ctrl+C, shutting down...")
		_ = l.Close()
		_ = os.Remove(sockPath)
		os.Exit(0)
	}()

	fmt.Println("Server waiting for client...")

	for {
		conn, err := l.Accept()
		if err != nil {
			fmt.Println("Error accepting:", err)
			return
		}

		fmt.Println("Client connected.")

		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	for {
		var size uint32 = 0
		err := binary.Read(conn, binary.LittleEndian, &size)
		if err != nil {
			return
		}
		fmt.Println("size", size)

		buffer := make([]byte, size)
		err = binary.Read(conn, binary.LittleEndian, &buffer)
		if err != nil {
			return
		}

		message := string(buffer)
		fmt.Println("Received message:", message)

		resp_len := uint32(len(buffer))
		err = binary.Write(conn, binary.LittleEndian, resp_len)
		if err != nil {
			return
		}
		resp_payload := buffer
		err = binary.Write(conn, binary.LittleEndian, resp_payload)
		if err != nil {
			return
		}
		fmt.Println("resp ->", string(resp_payload))
	}
}
