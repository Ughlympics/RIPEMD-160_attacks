package attacks

import (
	"fmt"
	"math"
	"math/rand"
	"time"

	"golang.org/x/crypto/ripemd160"
)

func Attack1v1(s string) int {
	msg := []byte(s)

	h := ripemd160.New()
	h.Write(msg)
	var pib = h.Sum(nil)

	target1 := pib[len(pib)-2]
	target2 := pib[len(pib)-1]

	for i := 0; i < (1 << 18); i++ {
		str := fmt.Sprintf("%d", i)
		msg := []byte(s + str)

		h2 := ripemd160.New()
		h2.Write(msg)
		sum := h2.Sum(nil)

		// if i < 30 {
		// 	fmt.Printf("Trying suffix: +%s => hash: %x\n", str, sum)
		// }

		if sum[len(sum)-2] == target1 && sum[len(sum)-1] == target2 {
			fmt.Printf("Found collision suffix: +%s\n", str)
			fmt.Printf("Colliding hash: %x\n", sum)
			fmt.Printf("count i: %x\n", i)
			return i
		}
	}

	fmt.Printf("RIPEMD-160: %x\n", pib)
	return -1
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

func Attack1v2(s string) int {
	msg := []byte(s)

	h := ripemd160.New()
	h.Write(msg)
	var pib = h.Sum(nil)
	target1 := pib[len(pib)-2]
	target2 := pib[len(pib)-1]

	for i := 0; i < (1 << 18); i++ {
		//str := fmt.Sprintf("%d", i)
		msg := []byte(randomModify("RadkevichKyrylMykolayovich"))

		h2 := ripemd160.New()
		h2.Write(msg)
		sum := h2.Sum(nil)

		// if i < 30 {
		// 	fmt.Printf("Trying suffix: +%s => hash: %x\n", str, sum)
		// }

		if sum[len(sum)-2] == target1 && sum[len(sum)-1] == target2 {
			//fmt.Printf("Found collision suffix: +%s\n", str)
			//fmt.Printf("Colliding hash: %x\n", sum)
			return i

		}
	}

	return -1
}

func Attack2v1(s string) int {
	base := s

	seen := make(map[[4]byte]string)

	for i := 0; i < (1 << 17); i++ {
		suffix := fmt.Sprintf("%d", i)
		msg := []byte(base + suffix)

		h := ripemd160.New()
		h.Write(msg)
		sum := h.Sum(nil)

		last4 := [4]byte{
			sum[len(sum)-4],
			sum[len(sum)-3],
			sum[len(sum)-2],
			sum[len(sum)-1],
		}

		// if i < 30 {
		// 	fmt.Printf("Trying suffix: +%s => hash last 4 bytes: %x\n", suffix, last4)
		// }

		if prev, ok := seen[last4]; ok {
			fmt.Println("=====================================")
			fmt.Println("COLLISION FOUND!")
			fmt.Printf("String 1: %s\n", prev)
			fmt.Printf("String 2: %s\n", base+suffix)
			fmt.Printf("Hash last 4 bytes: %x\n", last4)
			fmt.Println("=====================================")
			return i
		}

		seen[last4] = base + suffix
	}

	fmt.Println("No collisions found.")
	return -1
}

func Attack2v2(s string) int {
	base := s

	h := ripemd160.New()
	h.Write([]byte(base))
	baseHash := h.Sum(nil)

	target := [4]byte{
		baseHash[len(baseHash)-4],
		baseHash[len(baseHash)-3],
		baseHash[len(baseHash)-2],
		baseHash[len(baseHash)-1],
	}

	seen := make(map[[4]byte]string)

	seen[target] = base

	for i := 0; i < (1 << 17); i++ {

		msg := randomModify(base)

		if msg == base {
			continue
		}

		h2 := ripemd160.New()
		h2.Write([]byte(msg))
		sum := h2.Sum(nil)

		last4 := [4]byte{
			sum[len(sum)-4],
			sum[len(sum)-3],
			sum[len(sum)-2],
			sum[len(sum)-1],
		}

		// if i < 30 {
		// 	fmt.Printf("Trying message: %s => hash last 4 bytes: %x\n", msg, last4)
		// }

		if prevMsg, ok := seen[last4]; ok {
			if prevMsg != msg {
				fmt.Println("=====================================")
				fmt.Println("COLLISION FOUND!")
				fmt.Printf("Message 1: %s\n", prevMsg)
				fmt.Printf("Message 2: %s\n", msg)
				fmt.Printf("Hash last 4 bytes: %x\n", last4)
				fmt.Println("=====================================")
				return i
			}
		}

		seen[last4] = msg
	}

	fmt.Println("No collision found.")
	return -1
}

func RunAttackStats() {
	const runs = 100
	iterations := make([]float64, 0, runs)

	for i := 0; i < runs; i++ {
		k := i * 6
		pib := "RadkevichKyrylMykolayovich" + fmt.Sprintf("%d", k)
		fmt.Printf("Run %d/%d: attacking pib='%s'\n", i+1, runs, pib)

		//pib := "RadkevichKyrylMykolayovich"

		it := Attack2v2(pib)
		if it != -1 {
			iterations = append(iterations, float64(it))
		}
	}

	var sum float64
	for _, v := range iterations {
		sum += v
	}
	m_expectation := sum / float64(len(iterations))

	var diffsq float64
	for _, v := range iterations {
		diffsq += (v - m_expectation) * (v - m_expectation)
	}
	variance := diffsq / float64(len(iterations))
	stddev := math.Sqrt(variance)

	n := float64(len(iterations))
	ciLow := m_expectation - 1.96*(stddev/math.Sqrt(n))
	ciHigh := m_expectation + 1.96*(stddev/math.Sqrt(n))

	fmt.Println("============ STATISTICS ============")
	fmt.Printf("Runs:                %d\n", len(iterations))
	fmt.Printf("MATH EXPECTATION:    %.2f\n", m_expectation)
	fmt.Printf("Dispersion:          %.2f\n", variance)
	fmt.Printf("Std deviation:       %.2f\n", stddev)
	fmt.Printf("95%% CI:              [%.2f ; %.2f]\n", ciLow, ciHigh)
	fmt.Println("====================================")
}
