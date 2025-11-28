package main

import (
	"RIPEMD/attacks"
	"fmt"

	"golang.org/x/crypto/ripemd160"
)

func main() {
	fmt.Println("Starting RIPEMD-160 attacks...")
	var pib = "RadkevichKyrylMykolayovich"
	msg := []byte(pib)

	h := ripemd160.New()
	h.Write(msg)
	fmt.Printf("RIPEMD-160 of original message(hash of %s): %x\n", msg, h.Sum(nil))
	//attacks.Attack1v1(pib)
	//attacks.Attack1v2(pib)
	//attacks.Attack2v1(pib)
	//attacks.Attack2v2(pib)
	attacks.RunAttackStats()

}
