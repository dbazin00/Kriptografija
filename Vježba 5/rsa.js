const crypto = require("crypto");
const axios = require("axios");


//=====generate public/private RSA key pair=====
function generateRSAKeyPair(){
    const RSAKeyPairOptions = {
        // Generate 2048-bit RSA key pair
        modulusLength: 2048,
        publicKeyEncoding: {
            type: "pkcs1",
            format: "pem",
        },
        privateKeyEncoding: {
            type: "pkcs1",
            format: "pem",
        },
        };
        
        const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", RSAKeyPairOptions);

        return {privateKey, publicKey};
}

//=====Sign message using RSA=====
function signWithRSA(message, RSAPrivateKey) {
    const sign = crypto.createSign("RSA-SHA256");
    sign.write(message);
    sign.end();

    const signature = sign.sign(RSAPrivateKey, "hex");

    return signature;
}

//========================================
//  Verify RSA signature
//----------------------------------------
function verifyRSASignature(message, signature, RSAPublicKey) {
    const verify = crypto.createVerify("RSA-SHA256");
    verify.write(message);
    verify.end();
   
    if (
      !verify.verify(
        Buffer.from(RSAPublicKey, "hex").toString(),
        signature,
        "hex"
      )
    ) {
      throw Error("Invalid signature!");
    }
   
    return true;
  }

function generateDHKeyPair(){
    const DH = crypto.getDiffieHellman("modp15");
    DH.generateKeys();

    return {DH};
}

async function sendRSAPublicKey(
    key,
    url = "http://localhost:3000/asymmetric/rsa/client"
  ) {
    try {
      const response = await axios.post(url, { key });
      return response.data;
    } catch (error) {
      console.error(error.message);
    }
}

//========================================
//  Get the public RSA key from the server
//----------------------------------------
async function getRSAPublicKey(
    url = "http://localhost:3000/asymmetric/rsa/server"
  ) {
    try {
      const response = await axios.get(url);
      return response.data;
    } catch (error) {
      console.error(error.message);
    }
}

//========================================
//  Send signed public DH
//----------------------------------------
async function sendSignedDHPublicKey(
    key,
    signature,
    url = "http://localhost:3000/asymmetric/dh/client"
  ) {
    try {
      const response = await axios.post(url, { key, signature });
      return response.data;
    } catch (error) {
      console.error(error.message);
    }
}

//========================================
//  Get challenge from the server
//----------------------------------------
async function getChallenge(
    url = "http://localhost:3000/asymmetric/dh-challenge/server"
  ) {
    try {
      const response = await axios.get(url);
      return response.data;
    } catch (error) {
      console.error(error.message);
    }
}

//---------------------------------
// Decryptor
//---------------------------------
function decrypt({
    mode,
    key,
    iv = Buffer.alloc(0),
    ciphertext,
    padding = true,
    inputEncoding = "hex",
    outputEncoding = "utf8",
  }) {
    const decipher = crypto.createDecipheriv(mode, key, iv);
    decipher.setAutoPadding(padding);
    let plaintext = decipher.update(ciphertext, inputEncoding, outputEncoding);
    plaintext += decipher.final(outputEncoding);
    return { plaintext };
}

//=====Run everything=====
async function main () {
    const {publicKey: clientRSApublicKey, privateKey: clientRSAprivateKey} = generateRSAKeyPair();

    //print keys
    console.log(clientRSAprivateKey);
    console.log(clientRSApublicKey);

//     -----BEGIN RSA PRIVATE KEY-----
// MIIEpQIBAAKCAQEA6rlldeq0WZzx76m5dqtRfd+NUJCjYUDnfyUSiLefbSnlSdp7
// MewJhgCnQMRuPxJyFLBNYVCxZJ3injCEqbdRLBAY4rLWCAV0OzkXpnj7KRFlPNd6
// 6XrQWL5GKyjfvN43DeAGdrwUj2GVniZ09409EizPwFa/TGNkoHw2hfnH5DI/mbMi
// tU6/wN2ZgY14EpLpx5XFJSw0prd0slGot6cslE2Z2kaN+vF0ImWYsuQwDn0ts3/a
// Xyt3VLEZVqFFNImCP1gDM4GGkS6HpCzugPdYA6/fR49ZoVQXiySO4YRKiPZUNRbq
// Rc3Nzsx/8spYLWNJulfAE5zjxxQ/IYGGE93vHQIDAQABAoIBAQCRMGCcEbPBAp18
// W4XG662aqJ8myHDnBVisguf1/W71/UZA6o3tkU1KwDi0jUyMYwKB3ZPfsCQqUqcM
// poJI4IWrNcHO6EQP7h+5SlVgudDR1FrEyZzTsw4Q9pE8vSm4D9QKFxqocypcjkYX
// 7z3GqmyuQ122YXIu9AQYaPzo3lpQwbyi+DFvPOpZJDKh8xYP6uKKQxQSpaQis9Wj
// R6/oYNKj8Q/ObHugpa32becyTcnwNJWf8NU9wZaWglir7Lbmw3m/r3Z0lG5m8muc
// XNy5nUqTrte5GsJetx6IixJs2yT6olqOXF9Yq0c8W4/K5NcdGHfA8kPNpm1h83oX
// lgBY1qyBAoGBAP+oilJoP38tI3EMwXE406b9WB7hXB4pUvSaOQxRwciZC9TBxNB7
// 7aeWA1fvYmoxWxL22qd4IlWDdA4aaJdzjKhRti4mpwmfglLwy+pToHEuqn+FIGij
// EeSn7XDI6BYgk8LqQj3LUlDRzm4k6mH3zrhPkfgHN2zdbITPDev4+I1tAoGBAOsJ
// scwmOECToqRlDIqWzS0o9N9hSxmu3W6Bhig5yXvy2N2dMnKuR/j6/9DvbaOSs1oZ
// UoB/jUQrsIN/YTDiE4TlGWNagrCa7H1bW0z2JU1OigG6guACTa8uyKk3qGGWTLw0
// eDXf/9cEoO8edrPGdpDtnt0AmS2n1Yy1Pmq8nkpxAoGBAIb5TE3FjABwrE17FoXY
// IqX/Cw8Cm8ewuYM6CPRgFZb6diyVQHtxcj8QDCPY1nSKKjMQ8M+JtVbAV/06JA4R
// iykyOqSS8405EW0IhB/qlsIqiQlaF4omzcOShOEOsLk96cT2OJK3TXYtznaINtYS
// JqlYGRCBftmS7UAQsKDsiQzhAoGBAIWkLYR29uVBDOmMy2TB+kgDUbjyCVHBLAb5
// ft7AfOANZWIdT+IFVscrcOnMOfsYHwLMAy0tWZW5gdRDSXASHCckXRsxC75/WJiu
// qWtJSkx6q93vvxrANIu3fkE5dHSIkXkyHGgFxeLsrtVH7Rarch9V/U6MWIytMa+g
// Hq1yMk8BAoGAem948DU4UK27GHkGCoCVx6loHAUmFY8RLTIwprLg/uR2JX/eRjWX
// g3naoPX/w3chatzRE5PCUxjuPq6tEZcirAHI8vkHBE3nE8hKLjZw7bxFhlpbkXz0
// iMDJllkoOJVJVQu/+xQYzP2syZ6Pzho0UIzSP46F4dkSftIJYjHtrlU=
// -----END RSA PRIVATE KEY-----

// -----BEGIN RSA PUBLIC KEY-----
// MIIBCgKCAQEA6rlldeq0WZzx76m5dqtRfd+NUJCjYUDnfyUSiLefbSnlSdp7MewJ
// hgCnQMRuPxJyFLBNYVCxZJ3injCEqbdRLBAY4rLWCAV0OzkXpnj7KRFlPNd66XrQ
// WL5GKyjfvN43DeAGdrwUj2GVniZ09409EizPwFa/TGNkoHw2hfnH5DI/mbMitU6/
// wN2ZgY14EpLpx5XFJSw0prd0slGot6cslE2Z2kaN+vF0ImWYsuQwDn0ts3/aXyt3
// VLEZVqFFNImCP1gDM4GGkS6HpCzugPdYA6/fR49ZoVQXiySO4YRKiPZUNRbqRc3N
// zsx/8spYLWNJulfAE5zjxxQ/IYGGE93vHQIDAQAB
// -----END RSA PUBLIC KEY-----
    

    // Print DH details
    const {DH : clientDHKeyPair} = generateDHKeyPair();
    console.log("-----BEGIN DH KEYS/PARAMETERS-----");
    console.log("Group generator:", clientDHKeyPair.getGenerator("hex"));
    console.log("\nGroup prime:", clientDHKeyPair.getPrime("hex"));
    console.log("\nPrivate DH key:", clientDHKeyPair.getPrivateKey("hex"));
    console.log("\nPublic DH key:", clientDHKeyPair.getPublicKey("hex"));
    console.log("-----END DH KEYS/PARAMETERS-----\n");

//     -----BEGIN DH KEYS/PARAMETERS-----
// Group generator: 02

// Group prime: ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aaac42dad33170d04507a33a85521abdf1cba64ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7abf5ae8cdb0933d71e8c94e04a25619dcee3d2261ad2ee6bf12ffa06d98a0864d87602733ec86a64521f2b18177b200cbbe117577a615d6c770988c0bad946e208e24fa074e5ab3143db5bfce0fd108e4b82d120a93ad2caffffffffffffffff

// Private DH key: 5b1c48aa1ed7cd92155ff06b4514ae3a7c5984f2e7123ea5b27223af26f5900ff10624ce408204de34b265f94fd7840e808de20f033dcfd7703144a520671e033f9609d3e95d4a92c278023abdf3d1b7cd7fed7ab21d7dc83b5cf3f281c8e5a26c26ff05df3b5d85c0b2dc8c0f2495872f75933d558dc601ee179069f74c2d50e9cdf477b8658b513ad7a3f0c14fab376a63374b01cfa1a02f0fda193a4eb928396479e5e8ab555ae6737082d433e598d405dfdbbda3acedbb58ba264cea90ec8247d7989bac2c7a18afb6071880ab94c71653bfdf110bec2a5a4e5ce013a8efe6e5aa65f11998a1ec9e111d4f8ddee34d79139f514fc0fd358151200eb75c6ac877aa19b35c669447adeab648ab183bcb5aa13fda1a701635962cb1da1536f509a0fe171a35230762b21547830b019c45818b8ac6a015331a0e01e53e939ec4e46130cb0a79a8489953e319572cb5e229dfa8263ccbc0106a35a48375d01944de1f4c202c1435ba71362ef5b4432cd0074804eca1a7609b08641d7b91fc7574

// Public DH key: 0b7d6abcd9c8800657629464a0f96f1112fa8d97ea50ff56f2360a32d2a10bbace254e5dfb08df1df072b740ac97ed6fd448686dbc3e5ccf52b3f37ecfb48d5812f460707a40d6bc0ed4d4ed15819182b6bc1bc0e7810d7c09f92323257f32a226432a48765fc4c721647d3c2a221b9e43a2f3975a37ea0d7f08556cf3418693418fcb80cfdba063d0d705f312c429f4ad6661073a2822126dd5c3f25d550ecff81812866b786f704f48bc805d47890b70d078f78b81fa9831752d70cf2d9eac4078cb4854326da5779e74fe96617f8876627a2403980dd30479d41b0eb2a10b23654b2f025255221971de4189a53a8cf7410d3366a8c994568670158cb29068f0096ea77ead15a03d0e64975be00e9a40bb78b3bc23c3ecc3d243518cb7481618142cab2bd6db6d43de521e53e74453de489cfcbbda39ea1cf9f2b372e3544b80b816af0323d7ac0b63036fcb8cc068b7070163bc76c2170478f079272bbc7224b5b6a1d29585423216cb251ea4c4e5f9abecbe9b6acb0bee41e21647f4f8ae
// -----END DH KEYS/PARAMETERS-----

    
    //Step 1. (C->S: RSA pub,C)
    let response = await sendRSAPublicKey(
       Buffer.from(clientRSApublicKey).toString("hex")
    );

    //Step 2. (S->C: RSA pub,S)
    const {key: serverRSAPublicKey} = await getRSAPublicKey();
    console.log(serverRSAPublicKey);
    console.log(Buffer.from(serverRSAPublicKey, "hex").toString());
//     2d2d2d2d2d424547494e205055424c4943204b45592d2d2d2d2d0a4d494942496a414e42676b71686b6947397730424151454641414f43415138414d49494243674b43415145417457572b486f67516c3571734d4b5564354757346535704f5747756330626e3877465334414b326b7757395346744e627431714c784c44767a46453579325a2b732f3366335333493643426b445167435a31574d4f306d674d3147544d53742f46367242506a704b336c4755704263577145696d724c555a6e69333566396b436b547257566f536270484179726469596168425264364944613050485a5a5466596c4e566f4f354577376f44396363637a48612f6c75796d4d4a6c7746557879626764465a626d764475552f4d5a6a4b353373415168376b74516c515073465a5a3261564f394a636a5736506762374956464c6a41654954766a685643304c49596236572b484f535742695a74334f556a426c2b3355704d627a4b4768354237542b6d524a3263613072554d79786f464c785a4b52597a71496f5757434b744f5450593458497855486a67484c4b655669776d4a4b514944415141420a2d2d2d2d2d454e44205055424c4943204b45592d2d2d2d2d
// -----BEGIN PUBLIC KEY-----
// MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtWW+HogQl5qsMKUd5GW4e5pOWGuc0bn8wFS4AK2kwW9SFtNbt1qLxLDvzFE5y2Z+s/3f3S3I6CBkDQgCZ1WMO0mgM1GTMSt/F6rBPjpK3lGUpBcWqEimrLUZni35f9kCkTrWVoSbpHAyrdiYahBRd6IDa0PHZZTfYlNVoO5Ew7oD9ccczHa/luymMJlwFUxybgdFZbmvDuU/MZjK53sAQh7ktQlQPsFZZ2aVO9JcjW6Pgb7IVFLjAeITvjhVC0LIYb6W+HOSWBiZt3OUjBl+3UpMbzKGh5B7T+mRJ2ca0rUMyxoFLxZKRYzqIoWWCKtOTPY4XIxUHjgHLKeViwmJKQIDAQAB
// -----END PUBLIC KEY-----

    //Step 3. (C->S: DH pub,C || Sig(RSA priv,C , DH pub,C))
    let signature = signWithRSA(
        clientDHKeyPair.getPublicKey("hex"),
        clientRSAprivateKey
    );

    console.log(signature);
    // 9e5fe3c9b05286288e500c1c87e6889f9ba6367b7db8cf4e062b27506a915df977db39248b99b0d241f7334549544e7a8f2f3157f849a27635260c80a2e1c1eec2db9c8c6b2021fb12b005dd33db89fe162d2eb0931af3b61c252b4bd880f3d7b1e62ab6cb2b27f731817b86efc5246100d4d49dc1b5b02d3adc5f6ed26dd3368bf24a62e6f18c4bce9c1042824183811be318859f93949603d2cbbba4d4fdc1c746db46e893ce41ca6298b3c788dafe16c8c625ce6000b6d540aa87f489e0b2e79e5dfe2d3eb9a5606586f473f19ed67fa0afefe12f528d94b7cd6d8237e75ec0e9b90d0908a50b9bbeb9cc186db4814fe07f3d702df6b802f6ef74559cf73f

    response = await sendSignedDHPublicKey(
        clientDHKeyPair.getPublicKey("hex"),
        signature
    );

    console.log(response);

    //Step4. (S->C: DH pub,S || Sig(RSA priv,S , DH pub,S || DH pub,C) || AES-256-CTR(K, "...Chuck Norris..."))
    response = await getChallenge();
    console.log(response);
    // { key:
    //     '640c1efbd6e0097e1c748e19b8c7c150f7e509ba21521c2918c6298d2b76096bd0e9422884abd17cfdfa6633d73a0132e4fb8b4cbca1bceaf24e5e6fb8f4f3a9ef7b05aa4d8828bd892d47754e179d059d4ef56501f36de6b843313c5964c721d52c7f3b0bee3e64ef083301cfb3ede46241488e1f4395a1fb4efc9815c71afb755d91f6e4fb9021ac25b5e344e295e4454491799cb88ff3d8faad3f42c8666edab0f881b88519adcc34e2b018148c0f60f093ea770da689272335002dfaa5699782d65aafe032a84e2d854ab43d0ed5232b21433d92c0d18fe6b05e1cb2f14bf76d51a9c1a5df09ec4d10edaec4310b12fb29e955e1a014693880b69040381777b4c601b4012f1cfb37dbe8b8a0d4b2592dd4a77c70e8482381b8e2f569181c770b61aae5ed53f83e09689a59b7006b67619b9a98ab8007ed312cdfaa6a5d0baede8a5a78e3d05bf6cf7533019083b2247913de4343ba8befef920b438fc22c71d370cde6306e57bf9690d6a2fa97e547ce57bbfc5d862b83a4ef18e6a12ef2',
    //    signature:
    //     'a857c182c08376c4a04271ef12d4122bc4b70ea8ade41baeba7db7ded490f1676c333e0f92585d75316ded2c8106d7162229bba6fbb974e5ec541dec110ac79b7f43041eb97e97064a6fe1ae25a13748bb743442fdc40fb7a7d2fb9b3bf43950c2199fdb2f29873094822c73232150cd56efc8e69b3555e8806db22e3a74285e9156cf79565f042f7fc951aa5cc3c3bc8b3477938145848d03e29c074f2f92439085a99287e9c1c443a86548696b886421aae75193e479814285ae71040d4c869b2fc166ad0c42a11804a86f1b0bc4cea79f78049644c80474b2f603a8eb865f978361ca15df0bdd55f231f0411588066df17872122dcd48f38fc972f0504e54',
    //    challenge:
    //     { iv: '00000000000000000000000000000000',
    //       ciphertext:
    //        '6dd53777e04711218f7123ed4fb7b7b9c7d88ff715306e0a42fd3ebd575227e6bbc8e383d00e0e32231174943ddee9' } }

    const serverDHPublicKey = response.key;
    signature = response.signature;
    const challenge = response.challenge;

    verifyRSASignature(
        serverDHPublicKey + clientDHKeyPair.getPublicKey("hex"),
        signature,
        serverRSAPublicKey
    )
    const dhSharedKey = clientDHKeyPair.computeSecret(
        Buffer.from(serverDHPublicKey, "hex")
    );

    console.log(dhSharedKey.toString("hex"));

    // 1d93d918d57a7b51082325afe2e93e36aab5b8d296c5ac3ef89978e83f92c9ab4bdf5cce0343132fe23a7d33fd5a38b77a303f947c2c5f7a7aa9a8789ae2229f2272fe2315917cbd3d759b1a4ffc2ac9b6357c772841f872ef4ba8c69c831fdbafc342de82fb886bdb20edb199171be58216314e49ab46add8a9d54ff9cd332a316d3f264523500fb991f30b7833c14156cf97de8e334de6b9ce1232052714cb8d66193c84d47148352e3ee46bb54b1a37a9dd6376bb076b377c3c7debc66257dd890048c5e7ee7d781d7e896dc5ed2f04ec49f0f6b9a20d4cd1efe2af39a627439ef26b21608a9aa13c53ecc1cdb0cf5dcfbf93d03f0b184c9e3fb5aba66e7ae0b49fc1d87c65881dc4c1a291a3cd87d8263d473496d80473d3963e047f91e23e25a96a8e435ecb7cd475bdd7eb9f0f7c6cfb78a61e6c7cb9cb8b69904ed43ef653c225117386a473a52b602457e2ad1d27778399fcd3164ed2435720da19c37d7b05be3d81cd2b57e736288c7b29cbb9ca12df7a18d43c06b4a5629e15e0e9

    const derivedKey = crypto.pbkdf2Sync(
        dhSharedKey,
        "ServerClient",
        1,
        32,
        "sha512"
    );

    console.log(derivedKey);
    // <Buffer 05 24 0c 32 f9 51 b4 7f 0f 7c 24 53 a4 bf d6 69 4e f8 e8 f5 f8 04 5c e1 8b df bf c1 c0 a3 02 fb>

    const { plaintext } = decrypt({
        mode: "aes-256-ctr",
        iv: Buffer.from(challenge.iv, "hex"),
        key: derivedKey,
        ciphertext: challenge.ciphertext
    })
    console.log("Decrypted challenge: " + plaintext);
    // Decrypted challenge: ASYMM: Chuck Norris je zatvorio Otvoreni radio.
}
main();