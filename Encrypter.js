import * as encrypter from './encrypter.js';

export default class Encrypter {
	constructor(crypto, salt = this.randomSalt()) {
		this.crypto = crypto;
		this.salt = salt;
	}

	randomSalt() {
		return encrypter.encode(new Array(10).fill(null).map(() => `${Math.random()}`.slice(2)).join(''));
	}

	async encrypt(string, password, salt = this.salt, crypto = this.crypto) {
		const { cipher, iv } = await encrypter.encryptFromPassword(string, password, salt, crypto);
		return encrypter.toHex(iv, cipher);
	}

	async decrypt(string, password, salt = this.salt, crypto = this.crypto) {
		const [error, parsed] = encrypter.parseHex(string);
		if (error) {
			return [error];
		}

		const { cipher, iv } = parsed;
		return new Promise(resolve => {
			encrypter.decryptFromPassword(cipher, password, iv, salt, crypto).then(decrypted => {
				resolve([null, encrypter.decode(decrypted)]);
			}).catch(e => resolve([e]));
		});
	}

	destroy() {
		this.crypto = this.salt = null;
	}
}
