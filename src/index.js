/* eslint-disable class-methods-use-this */
import ursa from 'ursa';
import generateCSPRN from 'csprng';
import Dispatcher from 'thenable-events';

// const PEER_UNKNOWN = 0;
const PEER_HELO = 1;
const PEER_AUTH = 2;

const guid = () => {
	function s4() {
		return Math.floor((1 + Math.random()) * 0x10000)
			.toString(16)
			.substring(1);
	}
	return `${s4() + s4()}-${s4()}-${s4()}-${s4()}-${s4()}${s4()}${s4()}`;
};

const Private = new WeakMap();

export default class Steganos {
	constructor() {
		const privKey = ursa.generatePrivateKey();
		const pubKey = ursa.createPublicKey(privKey.toPublicPem());

		Private.set(this, {
			peers: {},
			signature: guid(),
			privKey,
			pubKey,
			disp: new Dispatcher()
		});
	}

	sendHelo() {
		const { pubKey, signature } = Private.get(this);

		return {
			signature,
			type: 'HELO',
			payload: pubKey
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
			pubKey: ursa.createPublicKey(theirPublicKey),
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
		const encryptedSpk = theirPublicKey.encrypt(spk);

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

		const { peers, privKey, signature: ourSignature } = Private.get(this);
		const { spk, pubKey: theirPublicKey } = peers[theirSignature];

		peers[theirSignature].stage = PEER_AUTH;

		const theirSpk = privKey.decrypt(payload);

		if (theirSpk !== spk) {
			throw new Error('Incorrect Shared Private Key');
		}

		return {
			signature: ourSignature,
			type: 'READY',
			payload: theirPublicKey.encrypt('READY')
		};
	}

	// ------------------------

	sendMessage(msg, theirSignature) {
		// Look up theirPublicKey and the spk
		// Encrypt message with spk
		// Encrypt the spk with theirPublicKey
		// Send TEXT message with the encrpyted versions in the payload, signed with our signature
	}
	receiveMessage() {}
}
