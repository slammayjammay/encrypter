import * as cryptoApi from './crypto-api.js';

export default class Encrypter {
	constructor(crypto) {
		this.crypto = crypto;
	}

	async encrypt(string, password, crypto = this.crypto) {
		const { iv, cipher, salt } = await cryptoApi.encryptFromPassword(crypto, string, password);
		return cryptoApi.toHex(iv, salt, cipher);
	}

	async decrypt(string, password, crypto = this.crypto) {
		const [error, parsed] = cryptoApi.parseHex(string);
		if (error) {
			return [error];
		}

		const { iv, salt, cipher } = parsed;
		return new Promise(resolve => {
			cryptoApi.decryptFromPassword(crypto, cipher, password, iv, salt).then(decrypted => {
				resolve([null, cryptoApi.decode(decrypted)]);
			}).catch(e => resolve([e]));
		});
	}

	destroy() {
		this.crypto = null;
	}
}
