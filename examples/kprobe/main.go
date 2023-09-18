package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/aws/aws-ebpf-sdk-go/pkg/elfparser"
	"github.com/aws/aws-ebpf-sdk-go/pkg/events"
	"github.com/aws/aws-ebpf-sdk-go/pkg/kprobe"
)

const bpfFile = "kprobe/bpf/kprobe.bpf.elf"
const pinPath = "global"
const progPath = "/sys/fs/bpf/globals/aws/programs/global_handle_kprobe"
const funcName = "do_unlinkat"

var printHeader = func() {
	fmt.Printf(
		"%-20s %3.3s %6s %-16.4s %32s\n",
		"Timestamp", "CPU", "PID", "COMM", "Filename",
	)
}

func printData(data []byte) {
	ts := binary.LittleEndian.Uint64(data[0:8])
	pid := binary.LittleEndian.Uint64(data[8:16])
	cpuId := binary.LittleEndian.Uint32(data[20:24])

	n := bytes.Index(data[24:40], []byte{0})
	comm := string(data[24 : n+24])

	n = bytes.Index(data[40:], []byte{0})
	filename := string(data[40 : n+40])

	fmt.Printf("%-20d %03d %6d %-16s %s\n", ts, cpuId, pid, comm, filename)
}

func signalHandler() chan os.Signal {
	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGHUP, syscall.SIGINT)
	return sig
}

func main() {
	elfc := elfparser.New()
	bpfdata, bpfmap, err := elfc.LoadBpfFile(bpfFile, pinPath)
	if err != nil {
		log.Fatalf("failed to load ELF file: %s", err)
	}

	prog := bpfdata[progPath].Program
	kprobeClient := kprobe.New(prog.ProgFD, "", funcName)
	if err := kprobeClient.KprobeAttach(); err != nil {
		log.Fatalf("failed to attach kprobe: %s", err)
	}

	event := bpfmap["event"]
	ring := events.New()
	ch, err := ring.InitRingBuffer([]int{int(event.MapFD)})
	if err != nil {
		log.Fatalf("failed init ringbuf: %s", err)
	}

	printHeader()
	for {
		select {
		case data := <-ch[int(event.MapFD)]:
			printData(data)
		case <-signalHandler():
			kprobeClient.KprobeDetach()
			os.Exit(0)
		}
	}
}
