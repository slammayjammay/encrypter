export const encoder = new TextEncoder();
export const decoder = new TextDecoder();
export const encode = (...args) => encoder.encode(...args);
export const decode = (...args) => decoder.decode(...args);

export const arrayToTyped = (array, Typed = Uint8Array) => Typed.from(array);
export const typedToArray = (typed) => Array.from(typed);
export const bufferToArray = (typed, Typed = Uint8Array) => Array.from(new Typed(typed));

export const ivLength = 12
export const saltLength = 16

export const getRandomValues = (crypto, n = saltLength) => {
	return crypto.getRandomValues(new Uint8Array(n));
}

export const encrypt = async (crypto, data, key, iv) => {
	data = data instanceof Uint8Array ? data : encode(data);
	iv = iv || getRandomValues(crypto, ivLength);

	const cipher = await crypto.subtle.encrypt(
		{ name: 'AES-GCM', iv },
		key,
		data
	);

	return { cipher, iv };
}

export const decrypt = async (crypto, data, key, iv) => {
	return crypto.subtle.decrypt(
		{ name: 'AES-GCM', iv },
		key,
		data
	);
}

export const generateKey = async (crypto, data, salt) => {
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

export const encryptFromPassword = async (crypto, string, password, salt = getRandomValues(crypto)) => {
	const key = await generateKey(crypto, password, salt);
	return { ...await encrypt(crypto, string, key), salt };
}

export const decryptFromPassword = async (crypto, data, password, iv, salt) => {
	const key = await generateKey(crypto, password, salt);
	return decrypt(crypto, data, key, iv);
}

export const numberToHex = (n) => n.toString(16).padStart(2, '0');

export const toHex = (iv, salt, cipher) => {
	iv = iv instanceof Array ? iv : typedToArray(iv);
	salt = salt instanceof Array ? salt : typedToArray(salt);
	cipher = cipher instanceof Array ? cipher : bufferToArray(cipher);
	return [...iv, ...salt, ...cipher].map(n => numberToHex(n)).join('');
}

export const parseHex = (string) => {
	const match = string.match(/[\da-f]{2}/gi);
	if (!match) {
		throw new Error('String is not made of hex values.');
	}

	return match.map(n => parseInt(n, 16));
}

export const toBase64 = (iv, salt, cipher) => {
	const chars = [...iv, ...salt, ...new Uint8Array(cipher)].map(n => String.fromCharCode(n));
	return btoa(chars.join(''));
}

export const parseBase64 = (string) => {
	const array = atob(string.slice(3)).split('').map(c => c.charCodeAt(0));
	return {
		iv: arrayToTyped(array.slice(0, ivLength)),
		salt: arrayToTyped(array.slice(ivLength, ivLength + saltLength)),
		cipher: arrayToTyped(array.slice(ivLength + saltLength))
	};
}
