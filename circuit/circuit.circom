include "./circomlib/circuits/eddsamimc.circom";
include "./circomlib/circuits/mimc.circom";

template VerifyTokens() {

    // token section
    signal   input counter;
    signal input tokenNew;
    // vrf section 
    signal  input PKx;
    signal  input PKy;
    signal  input R8xOld;
    signal  input R8yOld;
    signal  input SOld;
    signal  input R8xNew;
    signal  input R8yNew;
    signal  input SNew;

    // public keys and signatures of blockchain nodes
    signal input PKx1;
    signal input PKy1;
    signal  input R8x1;
    signal  input R8y1;
    signal  input S1;
    //
    signal input PKx2;
    signal input PKy2;
    signal  input R8x2;
    signal  input R8y2;
    signal  input S2;
    //
    signal input PKx3;
    signal input PKy3;
    signal  input R8x3;
    signal  input R8y3;
    signal  input S3;
    //
    signal input PKx4;
    signal input PKy4;
    signal  input R8x4;
    signal  input R8y4;
    signal  input S4;
    //
    signal input PKx5;
    signal input PKy5;
    signal  input R8x5;
    signal  input R8y5;
    signal  input S5;

    // recompute and verify old token (output to be used by sig verification)
    component vrfOld = EdDSAMiMCVerifier();   
    vrfOld.enabled <== 1;
    vrfOld.Ax <== PKx;
    vrfOld.Ay <== PKy;
    vrfOld.R8x <== R8xOld;
    vrfOld.R8y <== R8yOld;
    vrfOld.S <== SOld;
    vrfOld.M <== counter;
    // Hash vrfOld, the output will be used in checking node signatures
    component H1 = MiMC7(91);
    H1.x_in <== R8yOld;
    H1.k <== SOld;

    // ensure new token is produced from consecutive counter
    // first verify VrfNew
    component vrfNew = EdDSAMiMCVerifier();   
    vrfNew.enabled <== 1;
    vrfNew.Ax <== PKx;
    vrfNew.Ay <== PKy;
    vrfNew.R8x <== R8xNew;
    vrfNew.R8y <== R8yNew;
    vrfNew.S <== SNew;
    vrfNew.M <== counter + 1;
    // Make sure it produces tokenNew 
    component H2 = MiMC7(91);
    H2.x_in <== R8yNew;
    H2.k <== SNew;
    H2.out === tokenNew;
    
    // verify signatures
    component verifier1 = EdDSAMiMCVerifier();   
    verifier1.enabled <== 1;
    verifier1.Ax <== PKx1;
    verifier1.Ay <== PKy1;
    verifier1.R8x <== R8x1;
    verifier1.R8y <== R8y1;
    verifier1.S <== S1;
    verifier1.M <== H1.out;
    //
    component verifier2 = EdDSAMiMCVerifier();   
    verifier2.enabled <== 2;
    verifier2.Ax <== PKx2;
    verifier2.Ay <== PKy2;
    verifier2.R8x <== R8x2;
    verifier2.R8y <== R8y2;
    verifier2.S <== S2;
    verifier2.M <== H1.out;
    //
    component verifier3 = EdDSAMiMCVerifier();   
    verifier3.enabled <== 3;
    verifier3.Ax <== PKx3;
    verifier3.Ay <== PKy3;
    verifier3.R8x <== R8x3;
    verifier3.R8y <== R8y3;
    verifier3.S <== S3;
    verifier3.M <== H1.out;
    //
    component verifier4 = EdDSAMiMCVerifier();   
    verifier4.enabled <== 4;
    verifier4.Ax <== PKx4;
    verifier4.Ay <== PKy4;
    verifier4.R8x <== R8x4;
    verifier4.R8y <== R8y4;
    verifier4.S <== S4;
    verifier4.M <== H1.out;
    //
    component verifier5 = EdDSAMiMCVerifier();   
    verifier5.enabled <== 5;
    verifier5.Ax <== PKx5;
    verifier5.Ay <== PKy5;
    verifier5.R8x <== R8x5;
    verifier5.R8y <== R8y5;
    verifier5.S <== S5;
    verifier5.M <== H1.out;
}

component main {public [tokenNew, PKx1, PKy1, PKx2, PKy2, PKx3, PKy3, PKx4, PKy4, PKx5, PKy5]} = VerifyTokens();
