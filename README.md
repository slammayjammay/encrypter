# Encrypter

Simple implementation of encryption using [SubtleCrypto](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto). Note the MDN warning:

> Even assuming you use the basic cryptographic functions correctly, secure key management and overall security system design are extremely hard to get right, and are generally the domain of specialist security experts.

I am not a security expert. This library is meant to be a fun gimmick.

## Install
```sh
$ npm install https://github.com/slammayjammay/encrypter
```

## Usage
Usable in Node and browser. Node example:

```js
import { webcrypto } from 'crypto';
import { Encrypter } from 'encrypter';

const SECRETS = `My social security number is 314159.`;
const PASSWORD = 'galloping gargoyles';

(async () => {
	console.log(`Secret text: "${SECRETS}".`);

	const encrypter = new Encrypter(webcrypto);
	const encrypted = await encrypter.encrypt(SECRETS, PASSWORD);
	console.log(`Encrypted text: "${encrypted}".`);

	const [error, decrypted] = await encrypter.decrypt(encrypted, PASSWORD);
	if (error) {
		console.log(`Error: "${error}".`);
	} else {
		console.log(`Decrypted text: "${decrypted}".`);
	}

	encrypter.destroy();
})();
```

Output:

```
Secret text: "My social security number is 314159.".
Encrypted text: "823022da78743aff19b3e8af8c8946906989d4581254261b1635eec13419057207ce656d95217ca509402aa2cc4a83bfdfcfd62e427e776ecaff0bdfbf40e793".
Decrypted text: "My social security number is 314159.".
```

### Browser

```js
const encrypter = new Encrypter(window.crypto);
```

### Node

```js
import { webcrypto } from 'crypto';
const encrypter = new Encrypter(webcrypto);
```
