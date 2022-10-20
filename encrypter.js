export const encoder = new TextEncoder();
export const decoder = new TextDecoder();
export const encode = (...args) => encoder.encode(...args);
export const decode = (...args) => decoder.decode(...args);

export const arrayToTyped = (array, Typed = Uint8Array) => Typed.from(array);
export const typedToArray = (typed) => Array.from(typed);
export const bufferToArray = (typed, Typed = Uint8Array) => Array.from(new Typed(typed));

export const encrypt = async (data, key, iv, crypto) => {
	data = data instanceof Uint8Array ? data : encode(data);
	iv = iv || crypto.getRandomValues(new Uint8Array(12));

	const cipher = await crypto.subtle.encrypt(
		{ name: 'AES-GCM', iv },
		key,
		data
	);

	return { cipher, iv };
}

export const decrypt = async (data, key, iv, crypto) => {
	return crypto.subtle.decrypt(
		{ name: 'AES-GCM', iv },
		key,
		data
	);
}

export const generateKey = async (data, salt, crypto) => {
	data = data instanceof Uint8Array ? data : encode(data);

	const imported = await crypto.subtle.importKey(
		'raw',
		data,
		{ name: 'PBKDF2' },
		false,
		['deriveBits', 'deriveKey']
	);

	return crypto.subtle.deriveKey(
		{ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
		imported,
		{ name: 'AES-GCM', length: 256 },
		true,
		['encrypt', 'decrypt']
	);
}

export const encryptFromPassword = async (string, password, salt, crypto) => {
	const key = await generateKey(password, salt, crypto);
	return encrypt(string, key, undefined, crypto);
}

export const decryptFromPassword = async (data, password, iv, salt, crypto) => {
	const key = await generateKey(password, salt, crypto);
	return decrypt(data, key, iv, crypto);
}

export const numberToHex = (n) => n.toString(16).padStart(2, '0');

export const toHex = (iv, cipher) => {
	iv = iv instanceof Array ? iv : typedToArray(iv);
	cipher = cipher instanceof Array ? cipher : bufferToArray(cipher);
	return [...iv, ...cipher].map(n => numberToHex(n)).join('');
}

export const parseHex = (string) => {
	try {
		const array = string.match(/[\da-f]{2}/gi).map(n => parseInt(n, 16));

		return [null, {
			iv: arrayToTyped(array.slice(0, 12)),
			cipher: arrayToTyped(array.slice(12))
		}];
	} catch(e) {
		return [e];
	}
}
