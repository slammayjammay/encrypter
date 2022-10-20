import * as cryptoApi from './crypto-api.js';

export default class Encrypter {
	constructor(crypto, salt = this.randomSalt()) {
		this.crypto = crypto;
		this.salt = salt;
	}

	randomSalt() {
		return cryptoApi.encode(new Array(10).fill(null).map(() => `${Math.random()}`.slice(2)).join(''));
	}

	async encrypt(string, password, salt = this.salt, crypto = this.crypto) {
		const { cipher, iv } = await cryptoApi.encryptFromPassword(string, password, salt, crypto);
		return cryptoApi.toHex(iv, cipher);
	}

	async decrypt(string, password, salt = this.salt, crypto = this.crypto) {
		const [error, parsed] = cryptoApi.parseHex(string);
		if (error) {
			return [error];
		}

		const { cipher, iv } = parsed;
		return new Promise(resolve => {
			cryptoApi.decryptFromPassword(cipher, password, iv, salt, crypto).then(decrypted => {
				resolve([null, cryptoApi.decode(decrypted)]);
			}).catch(e => resolve([e]));
		});
	}

	destroy() {
		this.crypto = this.salt = null;
	}
}
