// import { KMS } from 'aws-sdk';
// import * as asn1 from 'asn1.js';
// import BN from 'bn.js';

const { KMS } = require('@aws-sdk/client-kms');
const asn1 = require('asn1.js');
const BN = require('bn.js');
const bs58check = require('bs58check')

let crypto;
try {
  crypto = require('node:crypto');
} catch (err) {
  console.error('crypto support is disabled!');
}
const hash = crypto.createHash('sha256');

console.log("Probando...")

const EcdsaPubKey = asn1.define('EcdsaPubKey', function() {
    // parsing this according to https://tools.ietf.org/html/rfc5480#section-2
    this.seq().obj( 
        this.key('algo').seq().obj(
            this.key('a').objid(),
            this.key('b').objid(),
        ),
        this.key('pubKey').bitstr()
    );
});

//const kmsKeyId = "arn:aws:kms:us-east-1:991486635649:key/4c7db894-65f3-4be2-bfce-11063c932cbc";
if (process.argv[2] == null) {
    console.log("Please use ARN as a parameter");
    process.exit(1);
} 
const kmsKeyId = process.argv[2]; //"arn:aws:kms:us-east-1:991486635649:key/3aa1299b-7099-42be-84f9-4e00d1f932d6";
const kms = new KMS({
    region: "us-east-1",
    apiVersion: "2014-11-01",
});

async function  getUncompressedPublicKey() {
    const pubKey = await kms
        .getPublicKey({
            KeyId: kmsKeyId,
        })
    const publicKeyBuffer = Buffer.from(pubKey.PublicKey, "utf-8");
    const res = EcdsaPubKey.decode(publicKeyBuffer, "der");
    return res.pubKey.data;
}

async function getCompressedPublicKey(){
    const uncompressed = await getUncompressedPublicKey();
    const header =
        parseInt(uncompressed.toString("hex").slice(uncompressed.length * 2 - 2, uncompressed.length * 2), 16) % 2 ? "03" : "02";
    return Buffer.from(header + uncompressed.toString("hex").slice(2,66), "hex");
}

async function addressBTCPlain(){
    const publicKey = await getCompressedPublicKey();
    const publicKeyHex = publicKey.toString("hex");
    console.log("Compressed Hex: " + publicKeyHex);
    const hash1 = crypto.createHash('sha256');
    const sha256PublicKeyHex =  hash1.update(Buffer.from(publicKeyHex, "hex")).digest('hex');
    console.log("Address BTC SHA: " + sha256PublicKeyHex);
    const hash2 = crypto.createHash('ripemd160');
    const ripemd160SHA256PK = hash2.update(Buffer.from(sha256PublicKeyHex, "hex")).digest('hex');
    console.log("Address BTC RIPEDM160: " + ripemd160SHA256PK);
    const base58CheckAddress = bs58check.encode(Buffer.from('00'+ripemd160SHA256PK, "hex"));
    console.log("Address BTC IN: " + base58CheckAddress);
    return base58CheckAddress;
}

const addressBTC = addressBTCPlain();
addressBTC.then(function(results){
    console.log("Address BTC OUT: " + results)
});