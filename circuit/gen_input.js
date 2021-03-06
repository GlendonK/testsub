const fs = require("fs");
//const bigInt = require("snarkjs").bigInt;
//const bigInt = require('big-integer');
const eddsa = require("circomlibjs/src/eddsa.js");
const mimc = require("circomlibjs/src/mimc7.js");

// Client keys and tokens
const counter = BigInt(123)
const prvKey = Buffer.from('0'.toString().padStart(64,'0'), "hex");
const pubKey = eddsa.prv2pub(prvKey);
const vrfOld = eddsa.signMiMC(prvKey, counter);
const tokenOld = mimc.hash(vrfOld['R8'][1], vrfOld['S']); // multihash with R8[0] ?
const counterNew = counter + BigInt(1)
const vrfNew = eddsa.signMiMC(prvKey, counterNew);
const tokenNew = mimc.hash(vrfNew['R8'][1], vrfNew['S']); // multihash with R8[0] ?
// The server receiving vrfNew and tokenNew, and verifies whether vrfNew is
// created by the client and whether it hashes to tokenNew

// Blockchain nodes' keypairs and signatures (over the old token)
const prvKey1 = Buffer.from('1'.toString().padStart(64,'0'), "hex");
const pubKey1 = eddsa.prv2pub(prvKey1);
const sig1 = eddsa.signMiMC(prvKey1, tokenOld);
const prvKey2 = Buffer.from('2'.toString().padStart(64,'0'), "hex");
const pubKey2 = eddsa.prv2pub(prvKey2);
const sig2 = eddsa.signMiMC(prvKey2, tokenOld);
const prvKey3 = Buffer.from('3'.toString().padStart(64,'0'), "hex");
const pubKey3 = eddsa.prv2pub(prvKey3);
const sig3 = eddsa.signMiMC(prvKey3, tokenOld);
const prvKey4 = Buffer.from('4'.toString().padStart(64,'0'), "hex");
const pubKey4 = eddsa.prv2pub(prvKey4);
const sig4 = eddsa.signMiMC(prvKey4, tokenOld);
const prvKey5 = Buffer.from('5'.toString().padStart(64,'0'), "hex");
const pubKey5 = eddsa.prv2pub(prvKey5);
const sig5 = eddsa.signMiMC(prvKey5, tokenOld);

// circut inputs
const inputs = {
    "counter": counter.toString(),
    "tokenNew": tokenNew.toString(),
    "PKx": pubKey[0].toString(),
    "PKy": pubKey[1].toString(),
    "R8xOld": vrfOld['R8'][0].toString(),
    "R8yOld": vrfOld['R8'][1].toString(),
    "SOld": vrfOld['S'].toString(),
    "R8xNew": vrfNew['R8'][0].toString(),
    "R8yNew": vrfNew['R8'][1].toString(),
    "SNew": vrfNew['S'].toString(),
    //
    "PKx1": pubKey1[0].toString(),
    "PKy1": pubKey1[1].toString(),
    "R8x1": sig1['R8'][0].toString(),
    "R8y1": sig1['R8'][1].toString(),
    "S1": sig1['S'].toString(),
    //
    "PKx2": pubKey2[0].toString(),
    "PKy2": pubKey2[1].toString(),
    "R8x2": sig2['R8'][0].toString(),
    "R8y2": sig2['R8'][1].toString(),
    "S2": sig2['S'].toString(),
    //
    "PKx3": pubKey3[0].toString(),
    "PKy3": pubKey3[1].toString(),
    "R8x3": sig3['R8'][0].toString(),
    "R8y3": sig3['R8'][1].toString(),
    "S3": sig3['S'].toString(),
    //
    "PKx4": pubKey4[0].toString(),
    "PKy4": pubKey4[1].toString(),
    "R8x4": sig4['R8'][0].toString(),
    "R8y4": sig4['R8'][1].toString(),
    "S4": sig4['S'].toString(),
    //
    "PKx5": pubKey5[0].toString(),
    "PKy5": pubKey5[1].toString(),
    "R8x5": sig5['R8'][0].toString(),
    "R8y5": sig5['R8'][1].toString(),
    "S5": sig5['S'].toString()
}

fs.writeFileSync(
    "./input.json",
    JSON.stringify(inputs),
    "utf-8"
);
