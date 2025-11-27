package attacks

import (
	"fmt"

	"golang.org/x/crypto/ripemd160"
)

func Attack1() {
	msg := []byte("hello world")

	h := ripemd160.New()
	h.Write(msg)
	sum := h.Sum(nil)

	fmt.Printf("RIPEMD-160: %x\n", sum)
}
