import * as cryptoApi from './crypto-api.js';

export default class Encrypter {
	constructor(crypto) {
		this.crypto = crypto;
	}

	async encrypt(string, password, _salt, crypto = this.crypto) {
		const { iv, cipher, salt } = await cryptoApi.encryptFromPassword(crypto, string, password, _salt);
		const chars = [...iv, ...salt, ...new Uint8Array(cipher)].map(n => String.fromCharCode(n));
		return `v3:${cryptoApi.toBase64(iv, salt, cipher)}`;
	}

	async decrypt(string, password, _salt, crypto = this.crypto) {
		const { iv, salt = _salt, cipher } = this.parse(string);

		return new Promise(resolve => {
			cryptoApi.decryptFromPassword(crypto, cipher, password, iv, salt || _salt).then(decrypted => {
				resolve([null, cryptoApi.decode(decrypted)]);
			}).catch(e => resolve([e]));
		});
	}

	parse(string) {
		if (/^v3:/.test(string)) {
			return cryptoApi.parseBase64(string);
		}

		let array;
		try {
			array = cryptoApi.parseHex(string);
		} catch(e) {
			return [e];
		}

		if (/^v2:/.test(string)) {
			return {
				iv: cryptoApi.arrayToTyped(array.slice(0, cryptoApi.ivLength)),
				salt: cryptoApi.arrayToTyped(array.slice(cryptoApi.ivLength, cryptoApi.ivLength + cryptoApi.saltLength)),
				cipher: cryptoApi.arrayToTyped(array.slice(cryptoApi.ivLength + cryptoApi.saltLength))
			};
		} else {
			return {
				iv: cryptoApi.arrayToTyped(array.slice(0, cryptoApi.ivLength)),
				cipher: cryptoApi.arrayToTyped(array.slice(cryptoApi.ivLength))
			};
		}
	}

	destroy() {
		this.crypto = null;
	}
}
