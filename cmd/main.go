package main

import (
	"fmt"
	"github.com/Myriad-Dreamin/coredns-plugin-ifv6/core"
)

func main() {
	fmt.Println(core.GetPublicIPs("enp7s0"))
}
