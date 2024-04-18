"use strict";

/********* External Imports ********/

const { stringToBuffer, bufferToString, encodeBuffer, decodeBuffer, getRandomBytes } = require("./lib");
const { subtle } = require('crypto').webcrypto;
const { randomBytes } = require('crypto');

/********* Constants ********/

const PBKDF2_ITERATIONS = 100000; // number of iterations for PBKDF2 algorithm
const MAX_PASSWORD_LENGTH = 64;   // we can assume no password is longer than this many characters
const PADDED_PASSWORD_LENGTH = 80; // we will pad passwords to this length
/********* Implementation ********/

function rawToPaddedArray(arr,padded_length){
  let arr_length = arr.length;
  let bytes = [];
  for(let i = 0; i < arr_length; i++){
    bytes.push(arr[i]);
  }
  bytes.push(1);
  for(let i = arr_length+1; i < padded_length; i++){
    bytes.push(0);
  }
  return bytes;
};

function paddedArrayToRaw(arr,padded_length){
  let arr_length = padded_length;
  for(let i = padded_length-1; i >= 0; i--){
    if(arr[i] == 1){
      arr_length = i;
      break;
    }
  }
  return arr.slice(0,arr_length);
};
class Keychain {
  /**
   * Initializes the keychain using the provided information. Note that external
   * users should likely never invoke the constructor directly and instead use
   * either Keychain.init or Keychain.load. 
   * Arguments:
   *  You may design the constructor with any parameters you would like. 
   * Return Type: void
   */
  constructor(kvs, salt, HMACkey_pos, HMACkey_signature, AESGCMkey_pos, AESGCMkey_signature, HMACkey, AESGCMkey) {
    this.data = { 
      /* Store member variables that you intend to be public here
         (i.e. information that will not compromise security if an adversary sees) */
    };
    this.secrets = {
      /* Store member variables that you intend to be private here
         (information that an adversary should NOT see). */
         kvs : kvs,
         salt : salt,
         HMACkey_pos : HMACkey_pos,//HMAC[masterkey, HMACkey_pos]
         HMACkey_signature : HMACkey_signature,
         AESGCMkey_pos : AESGCMkey_pos,
         AESGCMkey_signature : AESGCMkey_signature,
         HMACkey : HMACkey,
         AESGCMkey : AESGCMkey};
    this.data.version = "CS 255 Password Manager v1.0";
    this.ready = true; //Ready flag of password manager         
  };

  /** 
    * Creates an empty keychain with the given password.
    *
    * Arguments:
    *   password: string
    * Return Type: void
    */
  static async init(password) {
    //PBKDF2 key derivation
    let rawKey = await subtle.importKey("raw", stringToBuffer(password), "PBKDF2", false, ["deriveKey"]);
    let salt = randomBytes(16);
    let masterKey = await subtle.deriveKey(
      {
        name: "PBKDF2", salt: salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256"
      },
      rawKey,
      {
        name: "HMAC", hash: "SHA-256", length: 256
      },
      false,
      ["sign", "verify"]
    );

    //HMACKkey generation
    let HMACkey_pos = randomBytes(16);
    let HMACkey_signature = await subtle.sign(
      {
        name: "HMAC"
      },
      masterKey,
      HMACkey_pos
    );
    let HMACkey = await subtle.importKey("raw", HMACkey_signature, {name: "HMAC", hash: "SHA-256"}, false,["sign"]);
    //AESGCMkey generation
    let AESGCMkey_pos = randomBytes(16);
    let AESGCMkey_signature = await subtle.sign(
      {
        name: "HMAC"
      },
      masterKey,
      AESGCMkey_pos
    );
    let AESGCMkey = await subtle.importKey("raw", AESGCMkey_signature, {name: "AES-GCM", length: 256}, false,["encrypt", "decrypt"]);
    return new Keychain({}, salt, HMACkey_pos, HMACkey_signature, AESGCMkey_pos, AESGCMkey_signature, HMACkey, AESGCMkey);
  }

  /**
    * Loads the keychain state from the provided representation (repr). The
    * repr variable will contain a JSON encoded serialization of the contents
    * of the KVS (as returned by the dump function). The trustedDataCheck
    * is an *optional* SHA-256 checksum that can be used to validate the 
    * integrity of the contents of the KVS. If the checksum is provided and the
    * integrity check fails, an exception should be thrown. You can assume that
    * the representation passed to load is well-formed (i.e., it will be
    * a valid JSON object).Returns a Keychain object that contains the data
    * from repr. 
    *
    * Arguments:
    *   password:           string
    *   repr:               string
    *   trustedDataCheck: string
    * Return Type: Keychain
    */
  static async load(password, repr, trustedDataCheck) {
    if(trustedDataCheck !== undefined){
      let checksum = await subtle.digest("SHA-256", stringToBuffer(repr));
      if (bufferToString(checksum) !== trustedDataCheck){
        throw "Checksum is incorrect!";
      }
    }
    let contents = JSON.parse(repr);
    let salt = decodeBuffer(contents["salt"]);
    let HMACkey_pos = decodeBuffer(contents["HMACkey_pos"]);
    let HMACkey_signature = decodeBuffer(contents["HMACkey_signature"]);
    let AESGCMkey_pos = decodeBuffer(contents["AESGCMkey_pos"]);
    let AESGCMkey_signature = decodeBuffer(contents["AESGCMkey_signature"]);

    //password authentication
    let rawKey = await subtle.importKey("raw", stringToBuffer(password), "PBKDF2", false, ["deriveKey"]);
    let masterKey = await subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: salt,
        iterations: 100000,
        hash: "SHA-256"
      },
      rawKey,
      {
        name: "HMAC",
        hash: "SHA-256",
        length: 256},
      false,
      ["sign", "verify"]
    );
    let HMAC_verification = await subtle.verify(
      "HMAC",
      masterKey,
      AESGCMkey_signature,
      AESGCMkey_pos
    );
    if(HMAC_verification === false){
      throw "Password is incorrect!";
    }
    let HMACkey = await subtle.importKey("raw", HMACkey_signature, {name: "HMAC", hash: "SHA-256"}, false,["sign"]);
    let AESGCM_verification = await subtle.verify(
      "HMAC",
      masterKey,
      AESGCMkey_signature,
      AESGCMkey_pos
    );
    if(AESGCM_verification === false){
      throw "Password is incorrect!";
    }
    let AESGCMkey = await subtle.importKey("raw", AESGCMkey_signature, {name: "AES-GCM", length: 256}, false,["encrypt", "decrypt"]);
    return new Keychain(contents["kvs"], salt, HMACkey_pos, HMACkey_signature, AESGCMkey_pos, AESGCMkey_signature, HMACkey, AESGCMkey);
  };

  /**
    * Returns a JSON serialization of the contents of the keychain that can be 
    * loaded back using the load function. The return value should consist of
    * an array of two strings:
    *   arr[0] = JSON encoding of password manager
    *   arr[1] = SHA-256 checksum (as a string)
    * As discussed in the handout, the first element of the array should contain
    * all of the data in the password manager. The second element is a SHA-256
    * checksum computed over the password manager to preserve integrity.
    *
    * Return Type: array
    */ 
  async dump() {
    if (this.ready === false) {
      throw "Password manager is not ready!";
    }
    let contents = this.secrets;
    contents["HMACkey_signature"] = encodeBuffer(contents["HMACkey_signature"]);
    contents["AESGCMkey_signature"] = encodeBuffer(contents["AESGCMkey_signature"]);
    let repr = JSON.stringify(contents);
    let checksum = await subtle.digest("SHA-256", stringToBuffer(repr));
    return [repr, bufferToString(checksum)];
  };

  /**
    * Fetches the data (as a string) corresponding to the given domain from the KVS.
    * If there is no entry in the KVS that matches the given domain, then return
    * null.
    *
    * Arguments:
    *   name: string
    * Return Type: Promise<string>
    */
  async get(name) {
    if(this.ready === false){
      throw "Password manager is not ready!";
    }
    let key = await subtle.sign(
      {
        name: "HMAC"
      },
      this.secrets.HMACkey,
      stringToBuffer(name)
    );
    let hkey = await subtle.importKey(
      "raw",
      key,
      {
        name: "HMAC",
        hash: "SHA-256"
      },
      false,
      ["verify"]
    );
    key = encodeBuffer(key);
    let plaintext = null;
    if (this.secrets.kvs.hasOwnProperty(key)){
      let value = this.secrets.kvs[key];
      let iv = decodeBuffer(value[0]);
      let ciphertext = decodeBuffer(value[1]);
      let tag = decodeBuffer(value[2]);
      let verification = await subtle.verify(
        {
          name: "HMAC",
          hash: "SHA-256"
        },
        hkey,
        tag,
        ciphertext
      );
      if (verification === false){
        throw "Tampering is detected!";
      }
      plaintext = await subtle.decrypt(
        {
          name: "AES-GCM",
          iv: iv
        },
        this.secrets.AESGCMkey,
        ciphertext
      );
      plaintext = bufferToString(decodeBuffer(paddedArrayToRaw(encodeBuffer(plaintext), Keychain.PADDED_PASSWORD_LENGTH)));
      plaintext = plaintext.replace(/\u0001/g, '');
    }
    return plaintext;
  };

  /** 
  * Inserts the domain and associated data into the KVS. If the domain is
  * already in the password manager, this method should update its value. If
  * not, create a new entry in the password manager.
  *
  * Arguments:
  *   name: string
  *   value: string
  * Return Type: void
  */
  async set(name, value) {
    if(this.ready === false){
      throw "Password manager is not ready!";
    }

    let key = await subtle.sign(
      {
        name: "HMAC"
      },
      this.secrets.HMACkey,
      stringToBuffer(name)
    );
    let hkey = await subtle.importKey(
      "raw",
      key,
      {
        name: "HMAC",
        hash: "SHA-256"
      },
      false,
      ["sign"]
    );
    key = encodeBuffer(key);

    let iv = stringToBuffer(getRandomBytes(12));
    let ciphertext = await subtle.encrypt(
      {
        name: "AES-GCM",
        iv: iv
      },
      this.secrets.AESGCMkey,
      stringToBuffer(rawToPaddedArray(stringToBuffer(value), Keychain.PADDED_PASSWORD_LENGTH))
    );
    let tag = await subtle.sign(
      {
        name: "HMAC",
        hash: "SHA-256"
      },
      hkey,
      ciphertext
    );
    this.secrets.kvs[key] = [encodeBuffer(iv), encodeBuffer(ciphertext), encodeBuffer(tag)];
  };

  /**
    * Removes the record with name from the password manager. Returns true
    * if the record with the specified name is removed, false otherwise.
    *
    * Arguments:
    *   name: string
    * Return Type: Promise<boolean>
  */
  async remove(name) {
    if (this.ready === false) {
      throw "Password manager is not ready!";
    }
    let key = await subtle.sign(
      {
        name: "HMAC"
      },
      this.secrets.HMACkey,
      stringToBuffer(name)
    );
    key = encodeBuffer(key);

    if (this.secrets.kvs.hasOwnProperty(key)){
      delete this.secrets.kvs[key];
      return true;
    } else {
      return false;
    }
  };
};

module.exports = { Keychain }
