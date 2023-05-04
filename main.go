package main

import (
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf xdp.c -- -I../headers

type backend struct {
	saddr   uint32
	daddr   uint32
	hwaddr  [6]uint8
	ifindex uint16
}

func main() {
	var srcIfaceName = flag.String("sif", "eth1", "The name of the source network interface")
	var srcIfaceIPAddr = flag.String("sip", "10.0.0.10", "The ip address of the source network interface")
	var dstIfaceName = flag.String("dif", "br0", "The name of the destination interface")
	var bridgeIPAddr = flag.String("bip", "172.16.0.1", "The ip address of the virtual bridge")
	var conIPaddr = flag.String("cip", "172.16.0.2", "The ip address of the container where the server runs")
	var conMAC = flag.String("cmac", "02:42:ac:11:00:02", "The mac address of the container where the server is running")

	flag.Parse()

	mandatoryFlags := []string{"sif", "sip", "dif", "cip", "cmac", "bip"}
	mandatoryFlagsSet := make(map[string]bool)
	flag.Visit(func(f *flag.Flag) {
		mandatoryFlagsSet[f.Name] = true
	})

	for _, f := range mandatoryFlags {
		if !mandatoryFlagsSet[f] {
			fmt.Printf("Error: flag -%s is mandatory\n", f)
			flag.Usage()
			os.Exit(1)
		}
	}

	iface, err := net.InterfaceByName(*srcIfaceName)
	if err != nil {
		log.Fatalf("lookup network iface %q: %s", *srcIfaceName, err)
	}
	ifaceDest, err := net.InterfaceByName(*dstIfaceName)
	if err != nil {
		log.Fatalf("lookup network iface %q: %s", *dstIfaceName, err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer func(objs *bpfObjects) {
		err := objs.Close()
		if err != nil {

		}
	}(&objs)

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpProgFunc,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("could not attach XDP program: %s", err)
	}
	defer func(l link.Link) {
		err := l.Close()
		if err != nil {

		}
	}(l)

	l2, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.BpfRedirectPlaceholder,
		Interface: ifaceDest.Index,
	})
	if err != nil {
		log.Fatalf("could not attach XDP program: %s", err)
	}
	defer func(l2 link.Link) {
		err := l2.Close()
		if err != nil {

		}
	}(l2)

	log.Printf("Attached XDP program to iface %q (index %d) and iface %q (index %d)", iface.Name, iface.Index, ifaceDest.Name, ifaceDest.Index)
	log.Printf("Press Ctrl-C to exit and remove the program")

	b := backend{
		saddr:   ip2int(*bridgeIPAddr),
		daddr:   ip2int(*conIPaddr),
		hwaddr:  hwaddr2bytes(*conMAC),
		ifindex: uint16(ifaceDest.Index),
	}

	if err := objs.Backends.Update(ip2int(*srcIfaceIPAddr), b, ebpf.UpdateAny); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
	flag.Parse()

	select {}
}

func ip2int(ip string) uint32 {
	ipaddr := net.ParseIP(ip)
	return binary.LittleEndian.Uint32(ipaddr.To4())
}

func hwaddr2bytes(hwaddr string) [6]byte {
	parts := strings.Split(hwaddr, ":")
	if len(parts) != 6 {
		panic("invalid hwaddr")
	}

	var hwaddrB [6]byte
	for i, hexPart := range parts {
		bs, err := hex.DecodeString(hexPart)
		if err != nil {
			panic(err)
		}
		if len(bs) != 1 {
			panic("invalid hwaddr part")
		}
		hwaddrB[i] = bs[0]
	}

	return hwaddrB
}
