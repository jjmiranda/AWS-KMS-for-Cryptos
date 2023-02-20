// import { KMS } from 'aws-sdk';
// import * as asn1 from 'asn1.js';
// import BN from 'bn.js';

const { KMS } = require('@aws-sdk/client-kms');
const asn1 = require('asn1.js');
const BN = require('bn.js');

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
const kmsKeyId = "arn:aws:kms:us-east-1:991486635649:key/3aa1299b-7099-42be-84f9-4e00d1f932d6";
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

async function verCompressed(){
    const publicKey = await getCompressedPublicKey();
    console.log("Compressed Hex: " + publicKey.toString("hex"));
    const publicKeyHex = publicKey.toString("hex") + " + SHA256 + RIPEMD160 + prefix 00/6F + Base58Check Encode";
    console.log("publicKeyHex: " + publicKeyHex);
    return publicKeyHex;
}

verCompressed();