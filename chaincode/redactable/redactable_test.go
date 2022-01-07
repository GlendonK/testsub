package reductable

import (
	"testing"

	// "github.com/bithinalangot/kyber/pairing"
	"github.com/stretchr/testify/require"
	"go.dedis.ch/kyber/v3/pairing"
)

func TestRedactable(t *testing.T) {
	var aggreMsg [][]byte
	msg := []byte("Hello Redactable Signature")
	aggreMsg = append(aggreMsg, msg)
	suite := pairing.NewSuiteBn256()
	private, public, _ := RKeyGen(suite, 1)
	sig, err := RSign(suite, private, aggreMsg)
	require.Nil(t, err)
	err = RVerify(suite, public, aggreMsg, sig)
	require.Nil(t, err)
}

func TestFailRedactable(t *testing.T) {
	var aggreMsg [][]byte
	msg := []byte("Hello Redactable Signature")
	aggreMsg = append(aggreMsg, msg)
	suite := pairing.NewSuiteBn256()
	private, public, _ := RKeyGen(suite, 1)
	sig, err := RSign(suite, private, aggreMsg)
	require.Nil(t, err)
	sig[0][0] ^= 0x01
	if RVerify(suite, public, aggreMsg, sig) == nil {
		t.Fatal("Redactable Signature Succeeded Unexpectedly")
	}
}

func TestDeriveReductable(t *testing.T) {
	suite := pairing.NewSuiteBn256()

	PriKey, PubKey, _ := RKeyGen(suite, 4)
	var aggreMsg [][]byte

	msg1 := []byte("message 1")
	msg2 := []byte("message 2")
	msg3 := []byte("message 3")
	msg4 := []byte("message 4")
	aggreMsg = append(aggreMsg, msg1)
	aggreMsg = append(aggreMsg, msg2)
	aggreMsg = append(aggreMsg, msg3)
	aggreMsg = append(aggreMsg, msg4)

	signature, err := RSign(suite, PriKey, aggreMsg)
	require.Nil(t, err)

	var I []int
	I = append(I, 1)
	I = append(I, 2)
	I = append(I, 3)
	I = append(I, 4)

	reductSign, err := RDerive(suite, PubKey, signature, aggreMsg, I)
	require.Nil(t, err)
	reductMsg := make(map[int][]byte)
	for _, i := range I {
		reductMsg[i] = aggreMsg[i-1]
	}

	err = DVerify(suite, PubKey, reductMsg, reductSign)
	require.Nil(t, err)
}

func TestFailDeriveReductable(t *testing.T) {
	suite := pairing.NewSuiteBn256()

	PriKey, PubKey, _ := RKeyGen(suite, 4)
	var aggreMsg [][]byte

	msg1 := []byte("message 1")
	msg2 := []byte("message 2")
	msg3 := []byte("message 3")
	msg4 := []byte("message 4")
	aggreMsg = append(aggreMsg, msg1)
	aggreMsg = append(aggreMsg, msg2)
	aggreMsg = append(aggreMsg, msg3)
	aggreMsg = append(aggreMsg, msg4)

	signature, err := RSign(suite, PriKey, aggreMsg)
	require.Nil(t, err)

	var I []int
	I = append(I, 1)
	I = append(I, 2)
	reductSign, err := RDerive(suite, PubKey, signature, aggreMsg, I)
	require.Nil(t, err)
	reductMsg := make(map[int][]byte)
	for _, i := range I {
		reductMsg[i] = aggreMsg[i-1]
	}
	reductSign[0][0] ^= 0x01
	if DVerify(suite, PubKey, reductMsg, reductSign) == nil {
		t.Fatal("Derived Signature Verification Succeed Unexpectedly!")
	}
}

func BenchmarkReductableSign(b *testing.B) {
	var aggreMsg [][]byte
	msg := []byte("Hello Redactable Signature")
	aggreMsg = append(aggreMsg, msg)
	suite := pairing.NewSuiteBn256()
	private, _, _ := RKeyGen(suite, 1)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		RSign(suite, private, aggreMsg)
	}
}

func BenchmarkReductableVerify(b *testing.B) {
	var aggreMsg [][]byte
	msg := []byte("Hello Redactable Signature")
	aggreMsg = append(aggreMsg, msg)
	suite := pairing.NewSuiteBn256()
	private, public, _ := RKeyGen(suite, 1)
	sig, _ := RSign(suite, private, aggreMsg)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		RVerify(suite, public, aggreMsg, sig)
	}
}

func BenchmarkDeriveReductable(b *testing.B) {
	suite := pairing.NewSuiteBn256()

	PriKey, PubKey, _ := RKeyGen(suite, 4)
	var aggreMsg [][]byte

	msg1 := []byte("message 1")
	msg2 := []byte("message 2")
	msg3 := []byte("message 3")
	msg4 := []byte("message 4")
	aggreMsg = append(aggreMsg, msg1)
	aggreMsg = append(aggreMsg, msg2)
	aggreMsg = append(aggreMsg, msg3)
	aggreMsg = append(aggreMsg, msg4)

	signature, _ := RSign(suite, PriKey, aggreMsg)

	var I []int
	I = append(I, 1)
	I = append(I, 2)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		RDerive(suite, PubKey, signature, aggreMsg, I)
	}
}

func BenchmarkDeriveReductableVerify(b *testing.B) {
	suite := pairing.NewSuiteBn256()

	PriKey, PubKey, _ := RKeyGen(suite, 10)
	var aggreMsg [][]byte

	msg1 := []byte("message 1")
	msg2 := []byte("message 2")
	msg3 := []byte("message 3")
	msg4 := []byte("message 4")
	msg5 := []byte("message 5")
	msg6 := []byte("message 6")
	msg7 := []byte("message 7")
	msg8 := []byte("message 8")
	msg9 := []byte("message 9")
	msg10 := []byte("message 10")
	aggreMsg = append(aggreMsg, msg1)
	aggreMsg = append(aggreMsg, msg2)
	aggreMsg = append(aggreMsg, msg3)
	aggreMsg = append(aggreMsg, msg4)
	aggreMsg = append(aggreMsg, msg5)
	aggreMsg = append(aggreMsg, msg6)
	aggreMsg = append(aggreMsg, msg7)
	aggreMsg = append(aggreMsg, msg8)
	aggreMsg = append(aggreMsg, msg9)
	aggreMsg = append(aggreMsg, msg10)

	signature, _ := RSign(suite, PriKey, aggreMsg)

	var I []int
	I = append(I, 1)
	I = append(I, 2)

	reductSign, _ := RDerive(suite, PubKey, signature, aggreMsg, I)
	reductMsg := make(map[int][]byte)
	for _, i := range I {
		reductMsg[i] = aggreMsg[i-1]
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DVerify(suite, PubKey, reductMsg, reductSign)
	}
}
