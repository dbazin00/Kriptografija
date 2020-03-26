const axios = require("axios");

async function queryCryptoOracle({
  url = "http://localhost:3000/ecb",
  plaintext = ""
} = {}) {
  try {
    const response = await axios.post(url, {
      plaintext
    });

    return response.data.ciphertext;
  } catch (error) {
    console.error(error.message);
  }
}

// Multiple sequential oracle queries
async function main() {

  let initialPlaintext = "012345678901234";
  let data2 = null;
  let cookie = "";

  loop:
  for (j = 0; j < 16; j++) {  
    let pt = initialPlaintext;
     if(j > 0)
     pt = initialPlaintext.slice(0, -j);
     
     let data = await queryCryptoOracle({ plaintext: pt });
 
    for (let i = 0; i < 128; i++) {
      data2 = await queryCryptoOracle({
        plaintext: pt + cookie + String.fromCharCode(i)
      });
      if (data.slice(0, 32) === data2.slice(0, 32)) {
        cookie += String.fromCharCode(i);
        continue loop;
      }
    }
  }

  
  console.log("Cookie:\t" + cookie);
}

// call the main function
main();
