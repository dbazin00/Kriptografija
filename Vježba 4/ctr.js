const axios = require("axios");

async function getChallenge({
	url = "http://localhost:3000/ctr/challenge"
} = {}) {
	try {
		const response = await axios.get(url);

		return response.data.ciphertext;
	} catch (error) {
		console.error(error.message);
	}
}

async function getCiphertext(plaintext) {
	try {
		const response = await axios.post("http://localhost:3000/ctr", {
			plaintext: plaintext
		});
		return response.data.ciphertext;
	} catch (error) {
		console.log(error);
	}
}

function XOR(firstOperand, secondOperand, thirdOperand) {
	let result = Buffer.alloc(45);
	for (let i = 0; i < result.length; i++) {
		result[i] = firstOperand[i] ^ secondOperand[i] ^ thirdOperand[i];
	}
	return result.toString("utf-8");
}

async function main() {
    const challenge = await getChallenge();
	const myPlaintext = "68656c6c6f";
	
	const plaintextBuffer = Buffer.alloc(45, myPlaintext);
	const challengeBuffer = Buffer.from(challenge, "hex");
	
	let myCiphertext = await getCiphertext(plaintextBuffer);
	let ciphertextBuffer = Buffer.from(myCiphertext, "hex");

    let joke = XOR(challengeBuffer, ciphertextBuffer, plaintextBuffer);

    while(!joke.includes("Chuck"))
    {
        myCiphertext = await getCiphertext(plaintextBuffer);

        ciphertextBuffer = Buffer.from(myCiphertext, "hex");
        joke = XOR(challengeBuffer, ciphertextBuffer, plaintextBuffer);
    }

    console.log("Vrlo šaljivi vic\t->\t\x1b[32m" + joke +"\x1b[0m\n");
}

main();