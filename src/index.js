import ursa from 'ursa';
import crypto from 'crypto';
import generateCSPRN from 'csprng';

import guid from './utils/guid';

const IV_LENGTH = 16;

// const PEER_UNKNOWN = 0;
const PEER_HELO = 1;
const PEER_AUTH = 2;

const Private = new WeakMap();

export default class Steganos {
	constructor(encoding) {
		const privKey = ursa.generatePrivateKey();
		const pubKey = ursa.createPublicKey(privKey.toPublicPem());

		this.encoding = encoding || 'hex';

		Private.set(this, {
			peers: {},
			signature: guid(),
			privKey,
			pubKey
		});
	}

	sendHelo() {
		const { pubKey, signature } = Private.get(this);

		return {
			signature,
			type: 'HELO',
			payload: pubKey.toPublicPem(this.encoding)
		};
	}

	receiveHelo(pkg) {
		const { peers } = Private.get(this);

		const {
			signature,
			type,
			payload: theirPublicKey
		} = pkg;

		if (type !== 'HELO') {
			throw new TypeError(`Malformed HELO Package: Unknown type '${type}'.`);
		}

		peers[signature] = {
			stage: PEER_HELO,
			pubKey: ursa.createPublicKey(theirPublicKey, this.encoding),
			spk: null
		};
	}

	sendAuth(theirSignature) {
		// Grab `signature`'s public key from our `peers` (and store it in theirPublicKey)
		const {
			peers,
			signature: ourSignature
		} = Private.get(this);

		const { pubKey: theirPublicKey } = peers[theirSignature];

		// Generate Shared Private Key (SPK)
		const spk = generateCSPRN(); // CSPRNG => Pseudo-Random Number Generator : Crytographically Secure
		peers[theirSignature].spk = spk;
		peers[theirSignature].stage = PEER_AUTH;

		// Encrypt it using theirPublicKey
		const encryptedSpk = theirPublicKey.encrypt(spk, 'utf8', this.encoding);

		// return the encrypted version to send
		return {
			signature: ourSignature,
			type: 'AUTH',
			payload: encryptedSpk
		};
	}

	receiveAuth(pkg) {
		const {
			signature: theirSignature,
			type,
			payload
		} = pkg;

		if (type !== 'AUTH') {
			throw new TypeError(`Malformed AUTH Package: Unknown type '${type}'.`);
		}

		const { peers, privKey } = Private.get(this);
		const { spk } = peers[theirSignature];

		peers[theirSignature].stage = PEER_AUTH;

		const theirSpk = privKey.decrypt(payload, this.encoding, 'utf8');

		if (theirSpk !== spk) {
			throw new Error('Incorrect Shared Private Key');
		}
	}

	// ------------------------

	sendMessage(msg, theirSignature) {
		const { encoding } = this;

		// Look up theirPublicKey and the spk
		const { peers, signature: ourSignature } = Private.get(this);
		const { spk, pubKey: theirPublicKey } = peers[theirSignature];

		// Encrypt message with spk
		const iv = crypto.randomBytes(IV_LENGTH);
		const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(spk, 'utf8'), iv);
		const encryptedMsg = cipher.update(msg);

		const finalizedMsg = Buffer.concat([
			encryptedMsg,
			cipher.final()
		]);

		// Encrypt the IV with theirPublicKey
		const encryptedIv = theirPublicKey.encrypt(
			iv.toString(encoding), encoding, encoding
		);

		// Send TEXT message with the encrpyted versions in the payload, signed with our signature
		return {
			signature: ourSignature,
			type: 'TEXT',
			payload: `${encryptedIv}:${finalizedMsg.toString(encoding)}`
		};
	}

	receiveMessage(pkg) {
		// Grab our private key
		const { privKey, peers } = Private.get(this);


		// Look up the spk using theirSignature (from pkg)
		const {
			signature: theirSignature,
			type,
			payload
		} = pkg;

		const { spk } = peers[theirSignature];

		if (type !== 'TEXT') {
			throw TypeError(`Malformed TYPE Package: Unknown type '${type}'.`);
		}
		// Split payload into two parts: "encryptedIv:encryptedMsg"
		const [encryptedIv, ...encryptedMsg] = payload.split(':');

		// Decrypt the IV using our private key
		const decryptedIv = privKey.decrypt(encryptedIv, this.encoding);

		// Use the spk and decrypted IV to decrypt message
		const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(spk, 'utf8'), decryptedIv);

		const encryptedText = Buffer.from(encryptedMsg.join(':'), this.encoding);
		const decrypted = decipher.update(encryptedText);

		// return decrypted message

		return Buffer.concat([
			decrypted,
			decipher.final()
		]).toString();
	}
}
