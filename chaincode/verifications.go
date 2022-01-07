package main

/*
* This file contains all the verification methods.
* This is a Work in progress.
* The verification methods are independent of each other.
*
 */
import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/GlendonK/fabric-samples/own-chaincode/ps"
	reductable "github.com/GlendonK/fabric-samples/own-chaincode/redactable"
	"github.com/vocdoni/go-snark/parsers"
	"github.com/vocdoni/go-snark/verifier"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing"
)

/*
Verify a single message with redactable.go RVerify
*/
func VerifyRedactable(message []string, sig1 string, sig2 string) error {
	suite := pairing.NewSuiteBn256()

	n := len(message) // how many msg to aggre
	_, publicKeys := keysR(n)

	// msg := []byte("Hello Redactable Signature")
	msg := []byte(message[0])
	var aggreMsg [][]byte

	aggreMsg = append(aggreMsg, msg)

	// signature1, _ := hex.DecodeString("49d3338e13362120fcba8f740d01eb6f4ae7d3d10641d4ad958e25528cd88f00108e0b292d93ef98cba2d5c56f6661e9f01377513ea2f214856743175f6d8bec")
	// signature2, _ := hex.DecodeString("30a4a0eb81cb77d6686de7d0b1af1b026708d29209b26bb397674c90ca8d1dca8bc09d6f239f2c4fdaa715da9db55c61b3b50d6b5c22532b8deb596f2fc1515a")
	signature1, _ := hex.DecodeString(sig1)
	signature2, _ := hex.DecodeString(sig2)

	var sig [][]byte
	sig = append(sig, signature1)
	sig = append(sig, signature2)

	err := reductable.RVerify(suite, publicKeys, aggreMsg, sig)
	if err != nil {
		return err
	}
	return err

}

func VerifiyRedactableDerive(messages []string, sig1d string, sig2d string, sig3d string, sigd string) error {
	suite := pairing.NewSuiteBn256()

	_, PubKey := keysR(len(messages))
	var aggreMsg [][]byte

	for _, m := range messages {
		msg := []byte(m)
		aggreMsg = append(aggreMsg, msg)
	}

	// sigma1D := "655177dc1bd8d67057e90affeef2b3d1467d56f2eacdbc250c3cd39f8dd28ad57ae52f34b7affea00983978cc179b91143cc7c89dc299990987bd3a16a969a7d"
	// sigma2D := "5056156b7d6adee2b9644ee8b98933e3422633303d338c6aac0632ac19e5e23c87e0e550516a2d07a36a18dd5f1fff4ea09760135aee7c76c4ff949ae692bcbc"
	// sigma3D := "0fea0a58d2fad1e58e9d0de467222f187a4d67c2404f9718e6c060422b27c03882eb99c48d635e0aa46b3e0ac9f1726fed38b3bf92f8ed59652702f4b07b9bc1"
	// sigmaD := "0bbda50980dc89759342d4f9e98c39536dcad05a18088ab6514a0abf5611f8c17554bd3e34dea28e393265ca51c13a1726bd54ed699244d67c261bf98952acbf6a8d1f4c6ba0175f7d168145ac29e56a0c871070af5ba49a077effb6bd8283e019d638d037bfca3ea935ca2552dfc04baf202e7c24cd0e19c04b4e0e9a7c02f8"

	binSigma1d, _ := hex.DecodeString(sig1d)
	binSigma2d, _ := hex.DecodeString(sig2d)
	binSigma3d, _ := hex.DecodeString(sig3d)
	binSigmad, _ := hex.DecodeString(sigd)

	var reductSign [][]byte
	reductSign = append(reductSign, binSigma1d)
	reductSign = append(reductSign, binSigma2d)
	reductSign = append(reductSign, binSigma3d)
	reductSign = append(reductSign, binSigmad)

	var I []int
	I = append(I, 1)
	I = append(I, 2)

	reductMsg := make(map[int][]byte)
	for _, i := range I {
		reductMsg[i] = aggreMsg[i-1]
	}

	err := reductable.DVerify(suite, PubKey, reductMsg, reductSign)
	if err != nil {
		fmt.Errorf("error3")
	}
	return nil
}

/*
create the correct datatype for public key.
*/
func keysR(n int) (map[int]kyber.Scalar, []map[int]kyber.Point) {
	suite := pairing.NewSuiteBn256()

	xString := "2107abd9a612f2e98033a77b9d1cbff66deb5ca83eec74783222ac8d3e6fc051"
	xByte, _ := hex.DecodeString(xString)
	yString := "707b3e9ad709083fe288214140c184e59b5c264626320253fc931c8a3974632d"
	yByte, _ := hex.DecodeString(yString)

	PriKey := make(map[int]kyber.Scalar)
	x := suite.G1().Scalar()
	x.UnmarshalBinary(xByte)
	y := suite.G1().Scalar()
	y.UnmarshalBinary(yByte)
	PriKey[1] = x
	PriKey[2] = y

	gString := "2a5a4d26b516b5433c0b16340d33518921f13d0e2938414d46b8376294316b9e5d4dfcca2a0cfd04b60cff699e92b3cf80ad46326fc68d5af2093514b57312f3"
	gByte, _ := hex.DecodeString(gString)
	g_tildString := "57cd66e866ca3a4aa6b104c1e7e434ebda74a1513c09a81efb1d709c94cd81d773e0e513bbe3fbb8402979e80afb77b8ecf4aa498d329aee044209b066c3a3fd02374895b566deb8e60b4158f42650a197d60416abf896105ff0d4222e4141b48557cc90d0dcafc2da08235bd1ee3f86e7a75aa80bb41b2679a2212896ddd1ac"
	g_tildByte, _ := hex.DecodeString(g_tildString)

	var PubKey []map[int]kyber.Point
	pubParam := make(map[int]kyber.Point)
	g := suite.G1().Point()
	g.UnmarshalBinary(gByte)

	g_tild := suite.G2().Point()
	g_tild.UnmarshalBinary(g_tildByte)

	pubParam[1] = g
	pubParam[2] = g_tild

	X_tild := suite.G2().Point().Mul(x, g_tild)

	pubParam[3] = X_tild
	PubKey = append(PubKey, pubParam)

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

	return PriKey, PubKey

}

/*
	Verify using ps signature.
	The message is currently a simple string "hello".
*/
func VerifyPS(publicX, publicY, message, sigX, sigY string) error {
	suite := pairing.NewSuiteBn256()

	/*
		Create pub key data type and set the keys.
	*/
	var public []kyber.Point
	px := suite.Point()
	py := suite.Point()
	pubKeyX, err := hex.DecodeString(publicX)
	if err != nil {

		return err
	}
	pubKeyY, err := hex.DecodeString(publicY)
	if err != nil {
		return err
	}
	err = px.UnmarshalBinary(pubKeyX)
	if err != nil {
		return err
	}
	err = py.UnmarshalBinary(pubKeyY)
	if err != nil {
		return err
	}

	/*
		store pub keys in a list.
	*/

	public = append(public, px)
	public = append(public, py)

	/*
		store signatures in list of byte arr
	*/
	var s [][]byte
	sx, err := hex.DecodeString(sigX)
	if err != nil {
		return err
	}
	sy, err := hex.DecodeString(sigY)
	if err != nil {
		return err
	}

	s = append(s, sx)
	s = append(s, sy)

	msg := []byte(message)

	fmt.Printf("msg: %v\n", msg)

	valid := ps.Verify(suite, public, msg, s)

	if valid != nil {
		return valid
	} else {
		return nil
	}

}

/*
	Data structure for zk modeled as JSON.
*/

type VerificationKey struct {
	Protocol      string       `json:"protocol"`
	Curve         string       `json:"curve"`
	NPublic       int          `json:"nPublic"`
	VkAlpha1      []string     `json:"vk_alpha_1"`
	VkBeta2       [][]string   `json:"vk_beta_2"`
	VkGamma2      [][]string   `json:"vk_gamma_2"`
	VkDelta2      [][]string   `json:"vk_delta_2"`
	VkAlphabeta12 [][][]string `json:"vk_alphabeta_12"`
	IC            [][]string   `json:"IC"`
}

type Proof struct {
	PiA      []string   `json:"pi_a"`
	PiB      [][]string `json:"pi_b"`
	PiC      []string   `json:"pi_c"`
	Protocol string     `json:"protocol"`
	Curve    string     `json:"curve"`
}

/*
	Verify with ecdsa. ZK proof example is inside.
*/
func Verify(message, pubX, pubY, sig, hashString string) bool {

	/*
		verify with ZK proof
	*/
	validProof := VerifyProof()
	if !validProof {
		fmt.Println("cannot verify proof")
	}

	/*
		verify did with ecdsa
	*/
	// var did DID
	// err := json.Unmarshal(didJson, &did)
	// if err != nil {
	// 	panic("unable to unmarshal didJson")
	// }

	key := new(ecdsa.PrivateKey)
	key.PublicKey.Curve = elliptic.P256()

	x := new(big.Int)
	y := new(big.Int)

	xint, _ := x.SetString(pubX, 16)
	key.X = xint

	yint, _ := y.SetString(pubY, 16)
	key.Y = yint

	// document, err := json.Marshal(did.Document)
	// if err != nil {
	// 	panic("unable to marshal did.document")
	// }

	hash := sha256.Sum256([]byte(message))

	sigE, _ := hex.DecodeString(sig)

	valid := ecdsa.VerifyASN1(&key.PublicKey, hash[:], sigE[:])

	return valid
}

/*
	set and marshal verification_key.json.
*/
func setVerificationKey() ([]byte, error) {
	verificationKey := VerificationKey{Protocol: "groth16", Curve: "bn128", NPublic: 1, VkAlpha1: []string{"3059469284088355714770196374013890529939541639094221623621998906300411427511",
		"482793805017617914183486241832479692243612677918503295725023130367897679472", "1"},
		VkBeta2: [][]string{{"2649443729357236708782834711833575047836268824544894130956935552007554480257", "17712287767688181218052634192921184072168107350789895348296192446813906449892"},
			{"8004408151620360741977294075790432812640204548092214025055389293812328045654", "15949093204626244462607461299425140101327142094745244421105248143661452237030"},
			{"1", "0"}},
		VkGamma2: [][]string{{"10857046999023057135944570762232829481370756359578518086990519993285655852781", "11559732032986387107991004021392285783925812861821192530917403151452391805634"},
			{"8495653923123431417604973247489272438418190587263600148770280649306958101930", "4082367875863433681332203403145435568316851327593401208105741076214120093531"},
			{"1", "0"}},
		VkDelta2: [][]string{{"4098601936039810470781981469668590939777123676659789646074257285144422375419", "129646080283924079162933833404292433021869701255618908541777180997453317438"},
			{"13111954994654140613895952973982490584436264791864018126198951970831779268500", "633073153496351096684025845575255519909300013011400484564540226608863146174"},
			{"1", "0"}}, VkAlphabeta12: [][][]string{{{"3375398937228669271212383065353961544816542641030926113406052356383960400373", "10139824919063995242532992250560334606694781956016299233419326281920052922494"},
			{"19859396626501240889580652160635536008900603773076567894196795777355929143273", "13951791022622732729609030674961818053135098975193878950406710040124732233833"},
			{"8292011543658306857146272824153501086081032645214903395012880264222349383924", "13444223205002739623517145688760544366695016447870278848547574665674811804694"},
		}, {{"8516463582718704060590914737066320023915655771607181709618909856069650470660", "3095864295016126303302516042405803333304568952851135163910090698977461843026"},
			{"21846772879134719774412779512698004516094274400139499313707110180800657927067", "7417352849257569868853748909999441582876957447445877753474816613431304041712"},
			{"21619128951004518887491374369202560770046067475105094849809710025594090169434", "1132584972426666781763655900292707593825538476629967865996710381394709646071"}}},
		IC: [][]string{{"2730423239356261800072518077371118067600612925339175728183744842615341437178", "3880726219165985941112498917143532743153270054009551499564113302768188090453", "1"},
			{"20172471913149095482766494466739677980570992754801838156883060158026970322413", "12007129886820247309570700507053484175670034301265142490656509346369950877300", "1"},
			{"57176981664591259611525475668373634521696579166784634547580517596944275699", "10527545049401790695754010180664551748082099512412554030921799231936269411102", "1"},
			{"17598491605689925899522146379564711044299831365303840716985709791528881861827", "9094383955074729656554169187966153468519482127270564733879376054257110182796", "1"},
			{"885074190533602931362038959905768159637296931857089850250350997585448121581", "18241569701711739243034243214193640758667090227009640757017893663641458923010", "1"},
			{"14951856962393475238481216127478113920754672534580399291803225414854135569351", "8955515448836591700089177090410419805741302951170193817053921661819713399871", "1"},
			{"13328799150924154906853631293803271081227760371697945014892620100117138595531", "6347507455937829370604226021664602221876337747759312450058979566015405044373", "1"},
			{"21525978585113548457366286510552525579303845568661192685392617574312820695401", "14707983010057071377861766085346894193814681385688296059221188583638513509871", "1"},
			{"11279954057433444217253954788631698210694757721211538437163892670317389569468", "15348079621214061647222633631700161265043175311996291449715434257239833650872", "1"},
			{"15201024087721670435416076738642893426560789365640581154291998643838746650352", "21032525107782705590082446647120056722371821906554012992131937880437889251672", "1"},
			{"14906038977004334482177608516616894831291713180583018370303541613034146234455", "9637067948844381022314300846662386060078112050173028936529708531287533472154", "1"}}}

	verificationKeyJSON, err := json.Marshal(verificationKey)
	if err != nil {
		return nil, err
	}

	return verificationKeyJSON, nil

}

/*
	Set and marshal public.json
*/
func setPublic() []byte {
	public := []string{"15084950136729171756826375108266696120519173823909226408773470780193837013265",
		"1891156797631087029347893674931101305929404954783323547727418062433377377293",
		"14780632341277755899330141855966417738975199657954509255716508264496764475094",
		"16854128582118251237945641311188171779416930415987436835484678881513179891664",
		"8120635095982066718009530894702312232514551832114947239433677844673807664026",
		"17184842423611758403179882610130949267222244268337186431253958700190046948852",
		"14002865450927633564331372044902774664732662568242033105218094241542484073498",
		"1490516688743074134051356933225925590384196958316705484247698997141718773914",
		"18202685495984068498143988518836859608946904107634495463490807754016543014696",
		"605092525880098299702143583094084591591734458242948998084437633961875265263",
		"5467851481103094839636181114653589464420161012539785001778836081994475360535"}

	publicJSON, _ := json.Marshal(public)

	return publicJSON
}

/*
	Set and marshal proof.json contents
*/
func setProof() ([]byte, error) {
	proof := Proof{PiA: []string{"1145707449045941449097487498088833200711657511864610035291098185475411860243", "12289177413779563213064829914447914376931455652119581968825749829510011567043", "1"},
		PiB: [][]string{{"12488727751065214937156730404823458862090401765267267264216434819798572350200",
			"848157869247964529398557193203449097096258521168436043010131145951087592710"},
			{"7470758677462907198057306361279503593731617593755739462300875879565842735361",
				"12646580908550804401372681087400217345492962387560411033762298619735382993386"},
			{"1", "0"}},
		PiC: []string{"2401824499838361971382656832471436991160213873274219836777457312120693845058",
			"19911218764750460805915565322263546031288947008426715644931344376277877363239",
			"1"}, Protocol: "groth16", Curve: "bn128"}

	proofJSON, err := json.Marshal(proof)
	if err != nil {
		return nil, err
	}

	return proofJSON, nil
}

/*
	Verify with ZK proof.
	The proof, verification key, public is hardcoded.
*/
func VerifyProof() bool {

	proofJson, _ := setProof()
	vkJson, _ := setVerificationKey()
	publicJson := setPublic()

	// parse proof & verificationKey & publicSignals
	public, _ := parsers.ParsePublicSignals(publicJson)
	proof, _ := parsers.ParseProof(proofJson)
	vk, _ := parsers.ParseVk(vkJson)

	// verify the proof with the given verificationKey & publicSignals
	v := verifier.Verify(vk, proof, public)
	fmt.Println(v)

	return v

}
