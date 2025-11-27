package attacks

import (
	"fmt"
	"math/rand"
	"time"

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

func randomModify(s string) string {
	rand.Seed(time.Now().UnixNano())

	replacements := map[rune][]rune{
		'a': {'4', '@'},
		'A': {'4', '@'},
		'e': {'3', '€'},
		'E': {'3', '€'},
		'i': {'1', '!'},
		'I': {'1', '!'},
		'o': {'0', '°'},
		'O': {'0', '°'},
		'l': {'1', '|'},
		'y': {'Y'},
		'K': {'X'},
		'v': {'V'},
		'c': {'C', '¢', '4'},
		'h': {'H'},
		'r': {'R'},
	}

	runes := []rune(s)

	for i, ch := range runes {
		if rand.Float64() < 0.3 {
			if opts, ok := replacements[ch]; ok {
				runes[i] = opts[rand.Intn(len(opts))]
			}
		}
	}

	return string(runes)
}

func Attack1v2() bool {
	res := false
	msg := []byte("RadkevichKyrylMykolayovich")

	h := ripemd160.New()
	h.Write(msg)
	var pib = h.Sum(nil)
	target1 := pib[len(pib)-2]
	target2 := pib[len(pib)-1]

	for i := 0; res == false || i < 2^17; i++ {
		str := fmt.Sprintf("%d", i)
		msg := []byte(randomModify("RadkevichKyrylMykolayovich"))

		h2 := ripemd160.New()
		h2.Write(msg)
		sum := h2.Sum(nil)

		if sum[len(sum)-2] == target1 && sum[len(sum)-1] == target2 {
			fmt.Printf("Found collision suffix: +%s\n", str)
			fmt.Printf("Colliding hash: %x\n", sum)
			res = true
		}
	}

	return res
}
