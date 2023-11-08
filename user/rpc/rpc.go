package rpc

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"stackplz/user/config"
	"stackplz/user/event"
	"stackplz/user/module"
	"stackplz/user/util"
	"strconv"
	"strings"
)

var Logger *log.Logger
var Ctx context.Context
var Gconfig *config.GlobalConfig

func SetupRpc(ctx context.Context, logger *log.Logger, gconfig *config.GlobalConfig) {
	Logger = logger
	Ctx = ctx
	Gconfig = gconfig
}

type RespMsg struct {
	Status string `json:"status"`
	Msg    string `json:"msg"`
}

// {"brk_pid":3695,"brk_len":4,"brk_type":"x","brk_addr":"0x79e16b0890"}

type BrkOptions struct {
	BrkPid  int
	BrkLen  uint64
	BrkType uint32
	BrkAddr uint64
}

type BrkOptionsRaw struct {
	BrkPid  int    `json:"brk_pid"`
	BrkLen  uint64 `json:"brk_len"`
	BrkType string `json:"brk_type"`
	BrkAddr string `json:"brk_addr"`
}

func BrkIt(opts *BrkOptions) {
	event.CacheMaps(uint32(opts.BrkPid))
	mod := module.GetModuleByName(module.MODULE_NAME_BRK)
	var mconfig = config.NewModuleConfig()
	mconfig.Debug = Gconfig.Debug
	mconfig.ExternalBTF = findBTFAssets()
	mconfig.Buffer = Gconfig.Buffer
	mconfig.ManualStack = Gconfig.ManualStack
	mconfig.UnwindStack = Gconfig.UnwindStack
	mconfig.StackSize = Gconfig.StackSize
	mconfig.ShowRegs = Gconfig.ShowRegs
	mconfig.GetOff = Gconfig.GetOff
	mconfig.BrkPid = opts.BrkPid
	mconfig.BrkAddr = opts.BrkAddr
	mconfig.BrkLen = opts.BrkLen
	mconfig.BrkType = opts.BrkType
	mconfig.BrkKernel = false
	mod.Init(Ctx, Logger, mconfig)
	err := mod.Run()
	if err != nil {
		Logger.Printf("%s\tmodule Run failed, [skip it]. error:%+v", mod.Name(), err)
		os.Exit(1)
	}
}

func findBTFAssets() string {
	lines, err := util.RunCommand("uname", "-r")
	if err != nil {
		panic(fmt.Sprintf("findBTFAssets failed, can not exec uname -r, err:%v", err))
	}
	btf_file := "a12-5.10-arm64_min.btf"
	if strings.Contains(lines, "rockchip") {
		btf_file = "rock5b-5.10-arm64_min.btf"
	}
	Logger.Printf("findBTFAssets btf_file=%s", btf_file)
	return btf_file
}

func ParseMsg(payload []byte) (*BrkOptions, error) {
	brk := new(BrkOptions)
	brk_raw := new(BrkOptionsRaw)
	err := json.Unmarshal(payload, brk_raw)
	if err != nil {
		return nil, err
	}
	brk.BrkPid = brk_raw.BrkPid
	brk.BrkLen = brk_raw.BrkLen

	switch brk_raw.BrkType {
	case "r":
		brk.BrkType = util.HW_BREAKPOINT_R
	case "w":
		brk.BrkType = util.HW_BREAKPOINT_W
	case "x":
		brk.BrkType = util.HW_BREAKPOINT_X
	case "rw":
		brk.BrkType = util.HW_BREAKPOINT_RW
	default:
		return nil, errors.New(fmt.Sprintf("breakpoint type:%s is not supported", brk_raw.BrkType))
	}
	addr, err := strconv.ParseUint(strings.TrimPrefix(brk_raw.BrkAddr, "0x"), 16, 64)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("parse for %s failed, err:%v", brk_raw.BrkAddr, err))
	}
	brk.BrkAddr = addr
	return brk, nil
}

func StartRpcServer(stopper chan os.Signal, rpcPath string) {
	addr, err := net.ResolveTCPAddr("tcp4", rpcPath)
	if err != nil {
		Logger.Println("Error ResolveTCPAddr:", err)
		return
	}

	l, err := net.ListenTCP("tcp4", addr)
	if err != nil {
		Logger.Println("Error ListenTCP:", err)
		return
	}

	defer l.Close()

	go func() {
		<-stopper
		Logger.Println("\nReceived Ctrl+C, shutting down...")
		_ = l.Close()
		os.Exit(0)
	}()

	Logger.Println("Server waiting for client...")

	for {
		conn, err := l.Accept()
		if err != nil {
			Logger.Println("Error accepting:", err)
			return
		}

		Logger.Println("Client connected.")

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

		buffer := make([]byte, size)
		err = binary.Read(conn, binary.LittleEndian, &buffer)
		if err != nil {
			return
		}

		msg := RespMsg{}

		brk_options, err := ParseMsg(buffer)
		if err != nil {
			msg.Status = "error"
			msg.Msg = fmt.Sprintf("ParseMsg failed, err:%v", err)
		} else {
			Logger.Println("Received message:", string(buffer))
			BrkIt(brk_options)
			msg.Status = "ok"
			msg.Msg = "register breakpoint success"
		}

		resp, err := json.Marshal(msg)
		err = binary.Write(conn, binary.LittleEndian, uint32(len(resp)))
		if err != nil {
			return
		}
		err = binary.Write(conn, binary.LittleEndian, resp)
		if err != nil {
			return
		}
		Logger.Println("resp ->", string(resp))
	}
}
