package reductable

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"sort"

	kyber "go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/util/random"
	// "github.com/bithinalangot/kyber/pairing"
	// "github.com/bithinalangot/kyber/util/random"
)

// NewKeyPair creates a new PS signature signing key pair with private keys(x, y)
// which is scalar and public key (X, Y) which is a point on the curve G2.
func RKeyGen(suite pairing.Suite, n int) (map[int]kyber.Scalar, []map[int]kyber.Point, error) {
	PriKey := make(map[int]kyber.Scalar)
	var PubKey []map[int]kyber.Point

	// selecting two random group elements g and g_tild
	g := suite.G1().Point().Pick(suite.RandomStream())
	g_tild := suite.G2().Point().Pick(suite.RandomStream())
	pubParam := make(map[int]kyber.Point)
	pubParam[1] = g
	pubParam[2] = g_tild

	// selecting two random scalar elements x and y
	x := suite.G1().Scalar().Pick(random.New())
	y := suite.G1().Scalar().Pick(random.New())

	PriKey[1] = x
	PriKey[2] = y

	// X_tild = g_tild^x
	X_tild := suite.G2().Point().Mul(x, g_tild)
	pubParam[3] = X_tild
	PubKey = append(PubKey, pubParam)

	// Y_tild_i = g_tild^y^i for 1 <= i <= n

	Y_tild := make(map[int]kyber.Point)

	var y_t kyber.Scalar
	for i := 1; i <= n; i++ {
		y_t = y
		yTemp := suite.G1().Scalar().MulT(y_t, i)
		Y_tild[i] = suite.G2().Point().Mul(yTemp, g_tild)
	}

	PubKey = append(PubKey, Y_tild)

	var setN []int
	for i := 1; i <= n; i++ {
		setN = append(setN, i)
	}

	for i := n + 2; i <= 2*n; i++ {
		setN = append(setN, i)
	}

	Y := make(map[int]kyber.Point)
	for _, val := range setN {
		ytemp := y
		yTemp := suite.G1().Scalar().MulT(ytemp, val)
		Y[val] = suite.G1().Point().Mul(yTemp, g)
	}
	PubKey = append(PubKey, Y)

	return PriKey, PubKey, nil
}

func RSign(suite pairing.Suite, priKey map[int]kyber.Scalar, msgs [][]byte) ([][]byte, error) {
	var signature [][]byte
	sigma1 := suite.G1().Point().Pick(suite.RandomStream())
	binSigma1, err := sigma1.MarshalBinary()
	if err != nil {
		return nil, err
	}
	signature = append(signature, binSigma1)
	y := suite.G1().Scalar()

	for i, msg := range msgs {
		yTemp := priKey[2]
		t_temp := suite.G1().Scalar().MulT(yTemp, i+1)
		msgScalar := suite.G1().Scalar().SetBytes(msg)
		y.Add(y, suite.G1().Scalar().Mul(t_temp, msgScalar))
	}
	x := suite.G1().Scalar().Add(priKey[1], y)
	sigma2 := suite.G1().Point().Mul(x, sigma1)
	binSigma2, err := sigma2.MarshalBinary()
	if err != nil {
		return nil, err
	}
	signature = append(signature, binSigma2)
	return signature, nil
}

// Getting a derived signature from S
func RDerive(suite pairing.Suite, pubKey []map[int]kyber.Point, sig [][]byte, msgs [][]byte, I []int) ([][]byte, error) {
	var dSig [][]byte
	n := len(msgs)

	sort.Ints(I)

	// picking two random scalar r and t
	r := suite.G1().Scalar().Pick(random.New())
	t := suite.G1().Scalar().Pick(random.New())

	s0 := suite.G1().Point()
	if err := s0.UnmarshalBinary(sig[0]); err != nil {
		return nil, err
	}
	sigma1D := suite.G1().Point().Mul(r, s0)

	s1 := suite.G1().Point()
	if err := s1.UnmarshalBinary(sig[1]); err != nil {
		return nil, err
	}
	sigma2R := suite.G1().Point().Mul(r, s1)

	sigma1DT := suite.G1().Point().Mul(t, sigma1D)
	sigma2D := suite.G1().Point().Add(sigma2R, sigma1DT)

	binSigma1D, err := sigma1D.MarshalBinary()
	if err != nil {
		return nil, err
	}
	dSig = append(dSig, binSigma1D)

	binSigma2D, err := sigma2D.MarshalBinary()
	if err != nil {
		return nil, err
	}
	dSig = append(dSig, binSigma2D)

	Ytild := suite.G2().Point()
	for i, msg := range msgs {
		if !intInSet(i+1, I) {
			msgScalar := suite.G2().Scalar().SetBytes(msg)
			Ytild.Add(Ytild, suite.G2().Point().Mul(msgScalar, pubKey[1][i+1]))
		}
	}

	gT := suite.G2().Point().Mul(t, pubKey[0][2])
	sigmaD := suite.G2().Point().Add(Ytild, gT)
	sigConcat := sigma1D.String() + sigma2D.String() + sigmaD.String()

	redactList, _ := json.Marshal(&I)
	encodeList := base64.StdEncoding.EncodeToString(redactList)
	sigConcat = sigConcat + encodeList

	c := make(map[int]kyber.Scalar)
	for _, i := range I {
		hash := suite.Hash()
		hash.Write([]byte(sigConcat + string(rune(i))))
		c[i] = suite.G1().Scalar().SetBytes(hash.Sum(nil))
	}

	sigma3D := suite.G1().Point()
	for _, i := range I {
		Yi := suite.G1().Point().Mul(t, pubKey[2][n+1-i])
		Yj := suite.G1().Point()
		for j, msg := range msgs {
			if !intInSet(j+1, I) {
				msgScalar := suite.G1().Scalar().SetBytes(msg)
				Yj.Add(Yj, suite.G1().Point().Mul(msgScalar, pubKey[2][n+1-i+(j+1)]))
			}
		}
		Yi.Add(Yi, Yj)
		Yic := suite.G1().Point().Mul(c[i], Yi)
		sigma3D.Add(sigma3D, Yic)
	}

	binSigma3D, err := sigma3D.MarshalBinary()
	if err != nil {
		return nil, err
	}
	dSig = append(dSig, binSigma3D)

	binSigmaD, err := sigmaD.MarshalBinary()
	if err != nil {
		return nil, err
	}
	dSig = append(dSig, binSigmaD)

	return dSig, nil
}

func RVerify(suite pairing.Suite, pubKey []map[int]kyber.Point, msgs [][]byte, sig [][]byte) error {
	Y := suite.G2().Point()
	for i, msg := range msgs {
		msgScalar := suite.G2().Scalar().SetBytes(msg)
		Y.Add(Y, suite.G2().Point().Mul(msgScalar, pubKey[1][i+1]))
	}
	X := suite.G2().Point().Add(Y, pubKey[0][3])
	s1 := suite.G1().Point()
	if err := s1.UnmarshalBinary(sig[0]); err != nil {
		return err
	}
	left := suite.Pair(s1, X)

	s2 := suite.G1().Point()
	if err := s2.UnmarshalBinary(sig[1]); err != nil {
		return err
	}
	right := suite.Pair(s2, pubKey[0][2])

	if !left.Equal(right) {
		return errors.New("ps: invalid signature")
	}

	return nil
}

func DVerify(suite pairing.Suite, pubKey []map[int]kyber.Point, msgs map[int][]byte, sig [][]byte) error {
	Y := suite.G2().Point()
	//this should be the length of the whole message set
	n := 4
	for i, msg := range msgs {
		msgScalar := suite.G2().Scalar().SetBytes(msg)
		Y.Add(Y, suite.G2().Point().Mul(msgScalar, pubKey[1][i]))
	}
	s3 := suite.G2().Point()
	if err := s3.UnmarshalBinary(sig[3]); err != nil {
		return err
	}
	Y.Add(Y, s3)
	X := suite.G2().Point().Add(Y, pubKey[0][3])
	s0 := suite.G1().Point()
	if err := s0.UnmarshalBinary(sig[0]); err != nil {
		return err
	}
	left := suite.Pair(s0, X)

	s1 := suite.G1().Point()
	if err := s1.UnmarshalBinary(sig[1]); err != nil {
		return err
	}
	right := suite.Pair(s1, pubKey[0][2])

	if !left.Equal(right) {
		return errors.New("ps: invalid signature")
	}

	var I []int
	for i, _ := range msgs {
		I = append(I, i)
	}
	sort.Ints(I)

	sigConcat := s0.String() + s1.String() + s3.String()
	redactList, _ := json.Marshal(&I)
	encodeList := base64.StdEncoding.EncodeToString(redactList)
	sigConcat = sigConcat + encodeList

	c := make(map[int]kyber.Scalar)
	for _, i := range I {
		hash := suite.Hash()
		hash.Write([]byte(sigConcat + string(rune(i))))
		c[i] = suite.G1().Scalar().SetBytes(hash.Sum(nil))
	}

	Yc := suite.G1().Point()
	for _, i := range I {
		Yc.Add(Yc, suite.G1().Point().Mul(c[i], pubKey[2][n+1-i]))
	}

	s2 := suite.G1().Point()
	if err := s2.UnmarshalBinary(sig[2]); err != nil {
		return err
	}
	leftc := suite.Pair(s2, pubKey[0][2])
	rightc := suite.Pair(Yc, s3)

	if !leftc.Equal(rightc) {
		return errors.New("ps: invalid signature")
	}

	return nil
}

func intInSet(i int, I []int) bool {
	for _, j := range I {
		if i == j {
			return true
		}
	}
	return false
}
