/* eslint-disable no-console */
import Steganos from './index.js';

console.log('Creating new Steganos');
const stegInst = new Steganos();

console.log('Generating HELO package');
const heloPkg = stegInst.sendHelo();

const { signature } = heloPkg;
console.log(`Extracting signature for later use: ${signature}`);

console.log('Receiving HELO package');
stegInst.receiveHelo(heloPkg);

console.log('Generating AUTH package');
const authPkg = stegInst.sendAuth(signature);

console.log('Receiving AUTH package');
stegInst.receiveAuth(authPkg);

console.log('Generating TEXT package');
const msgPkg = stegInst.sendMessage('Hello World!', signature);
console.log({ message: msgPkg });

const decrypted = stegInst.receiveMessage(msgPkg);
console.log({ decrypted });
