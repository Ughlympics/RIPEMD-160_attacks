package attacks

import (
	"fmt"

	"golang.org/x/crypto/ripemd160"
)

func Attack1v1() bool {
	res := false
	msg := []byte("RadkevichKyrylMykolayovich")

	h := ripemd160.New()
	h.Write(msg)
	var pib = h.Sum(nil)
	target1 := pib[len(pib)-2]
	target2 := pib[len(pib)-1]

	for i := 0; res == false || i < 2^17; i++ {
		str := fmt.Sprintf("%d", i)
		msg := []byte("RadkevichKyrylMykolayovich" + str)

		h2 := ripemd160.New()
		h2.Write(msg)
		sum := h2.Sum(nil)

		if sum[len(sum)-2] == target1 && sum[len(sum)-1] == target2 {
			fmt.Printf("Found collision suffix: +%s\n", str)
			fmt.Printf("Colliding hash: %x\n", sum)
			res = true
		}
	}

	fmt.Printf("RIPEMD-160: %x\n", pib)
	return res
}
