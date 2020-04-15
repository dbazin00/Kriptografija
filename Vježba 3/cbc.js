const assert = require("assert");
const axios = require("axios");
const MAX_32_INTEGER = Math.pow(2, 32) - 1;

function increment(bigint, addend = 1, offset = 12) {
    // assert(Number.isSafeInteger(addend), "Addend not a safe integer");
  
    if (offset < 0) return;
  
    const current = bigint.readUInt32BE(offset);
    const sum = current + addend;
  
    if (sum <= MAX_32_INTEGER) {
      return bigint.writeUInt32BE(sum, offset);
    }
  
    const reminder = sum % (MAX_32_INTEGER + 1);
    const carry = Math.floor(sum / MAX_32_INTEGER);
  
    bigint.writeUInt32BE(reminder, offset);
    incrementIv(bigint, carry, offset - 4);
  }

async function getWordlist({
	url = "http://localhost:3000/wordlist.txt"
} = {}) {
	try {
		const response = await axios.get(url);

		return response;
	} catch (error) {
		console.error(error.message);
	}
}

async function getChallenge({
	url = "http://localhost:3000/cbc/iv/challenge"
} = {}) {
	try {
		const response = await axios.get(url);

		return response.data;
	} catch (error) {
		console.error(error.message);
	}
}
function addPadding(plaintext) {
	assert(
		plaintext.length <= 16,
		`Plaintext block exceeds 16 bytes (${plaintext.length})`
	);
	const pad = 16 - plaintext.length;
	const sourceBuffer = Buffer.from(plaintext);
	const targetBuffer = pad > 0 ? Buffer.alloc(16, pad) : Buffer.alloc(32, 16);
	sourceBuffer.copy(targetBuffer, 0, 0);

	return targetBuffer.toString("hex");
}

async function getCiphertext(plaintext) {
	try {
		const response = await axios.post("http://localhost:3000/cbc/iv", {
			plaintext: plaintext
		});
		return response.data.ciphertext;
	} catch (error) {
		console.log(error);
	}
}

async function getIV(plaintext) {
	try {
		const response = await axios.post("http://localhost:3000/cbc/iv", {
			plaintext: plaintext
		});
		return response.data.iv;
	} catch (error) {
		console.log(error);
	}
}

function XOR(firstOperand, secondOperand, thirdOperand) {
	let result = Buffer.alloc(16);
	for (let i = 0; i < result.length; i++) {
		result[i] = firstOperand[i] ^ secondOperand[i] ^ thirdOperand[i];
	}
	return result;
}

async function main() {
    const response = await getWordlist();
    let wordArray = response.data.split("\r\n");
    
    const challenge = await getChallenge();
    let victimsCipherText = challenge.ciphertext;
    let victimsIV = challenge.iv;

    const initIv = Buffer.from(victimsIV, "hex")
    
    const firstWord = addPadding("firstword");
    const firstIV = await getIV(firstWord)
    const nextIV = Buffer.from(firstIV, "hex")
    
    
    
    // const iv = 
    for (let i = 0; i < wordArray.length; i++) {
        let testWord = Buffer.from(addPadding(wordArray[i]), "hex");
        increment(nextIV, 4);
        
        let plaintext = XOR(testWord, nextIV, initIv).toString("hex");

		let responseCiphertext = await getCiphertext(plaintext);
        let testCiphertext = responseCiphertext.slice(0, 32);
        
        if (testCiphertext === victimsCipherText) {
			console.log("\x1b[33mTražena riječ:\t\x1b[35m" + wordArray[i] + "\x1b[37m");

			return null;
        }
        
    }
    console.log("Nije pronađena nijedna riječ...")
}

main();