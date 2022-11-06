import crypto from 'crypto';
import tls from 'tls';
import net from 'net';

import { ClientHello } from './ClientHello.mjs';
import { CipherSuite } from './CipherSuite.mjs';
import { Handshake, HandshakeType } from './Handshake.mjs';
import { ContentType, TLSPlaintext } from './TLSPlaintext.mjs';
import { SupportedVersionsExtension } from './extensions/SupportedVersions.mjs';
import { NamedGroup } from './extensions/NamedGroup.mjs';
import { PskKeyExchangeMode, PskKeyExchangeModesExtension } from './extensions/PskKeyExchangeModes.mjs';
import { KeyShareExtension } from './extensions/KeyShare.mjs';
import { SignatureAlgorithmsExtension, SignatureScheme } from './extensions/SignatureAlgorithms.mjs';
import { SupportedGroupsExtension } from './extensions/SupportedGroups.mjs';

const clientHello = Buffer.from([
  0x16,
  0x03, 0x01,                                       // TLS version (SSLv3.1)
  0x00, 0xf5,                                       // size
  0x01,                                             // handshake type
  0x00, 0x00, 0xf1,                                 // size
  0x03, 0x03,                                       // ProtocolVersion (SSLv3.3)
  0x55, 0xf6, 0x6e, 0x2a, 0xa8, 0x15, 0x27, 0xb5,   // random
  0xe8, 0x3a, 0xb7, 0xc8, 0x3e, 0x56, 0xa0, 0x23,   // random
  0x96, 0x8c, 0x38, 0xff, 0x11, 0xb7, 0xb9, 0xf3,   // random
  0x75, 0x7f, 0xa6, 0x05, 0x24, 0x5f, 0xdd, 0x48,   // random
  0x20,                                             // session ID length
    0x28, 0x15, 0x8d, 0x50, 0xfa, 0x62, 0xe8, 0xe1, // session ID
    0xac, 0x72, 0x67, 0x23, 0xca, 0xd3, 0x0f, 0x2b, // session ID
    0x3a, 0x59, 0x29, 0xad, 0x46, 0x2e, 0x6b, 0x67, // session ID
    0x83, 0x20, 0x6d, 0x5c, 0x5f, 0x16, 0x3b, 0xee, // session ID
  0x00, 0x08,                                       // length of cipher suites
    0x13, 0x02,                                     // TLS_AES_256_GCM_SHA384
    0x13, 0x03,                                     // TLS_CHACHA20_POLY1305_SHA256
    0x13, 0x01,                                     // TLS_AES_128_GCM_SHA256
    0x00, 0xff,                                     // psuedo-cipher-suite "renegotiation SCSV supported"
  0x01,                                             // compression methods length
    0x00,                                           // compression method (no compression)

  0x00, 0xa0,                                       // length of extensions

    0x00, 0x00,                                     // server name
      0x00, 0x15,
      0x00, 0x13,
        0x00,
        0x00, 0x10,
        0x67, 0x64, 0x6e, 0x2e, 0x6a, 0x72, 0x64, 0x6c,
        0x74, 0x64, 0x2e, 0x63, 0x6f, 0x2e, 0x75, 0x6b,

    0x00, 0x0b,
      0x00, 0x04,
        0x03,
          0x00, 0x01, 0x02,

    0x00, 0x0a, // *
      0x00, 0x16,
        0x00, 0x14,
          0x00, 0x1d,
          0x00, 0x17,
          0x00, 0x1e,
          0x00, 0x19,
          0x00, 0x18,
          0x01, 0x00,
          0x01, 0x01,
          0x01, 0x02,
          0x01, 0x03,
          0x01, 0x04,

    0x00, 0x23,
      0x00, 0x00,

    0x00, 0x16,
      0x00, 0x00,

    0x00, 0x17,
      0x00, 0x00,

    0x00, 0x0d, // *
      0x00, 0x1e,
        0x00, 0x1c,
          0x04, 0x03,
          0x05, 0x03,
          0x06, 0x03,
          0x08, 0x07,
          0x08, 0x08,
          0x08, 0x09,
          0x08, 0x0a,
          0x08, 0x0b,
          0x08, 0x04,
          0x08, 0x05,
          0x08, 0x06,
          0x04, 0x01,
          0x05, 0x01,
          0x06, 0x01,

    0x00, 0x2b,         // SupportedVersions
      0x00, 0x03,       // length of extension
        0x02,           // length of list
          0x03, 0x04,   // TLS 1.3

    0x00, 0x2d,         // PskKeyExchangeModes
      0x00, 0x02,       // length
        0x01,           // length
          0x01,         // mode - psk_dhe_ke

    0x00, 0x33,         // KeyShare
      0x00, 0x26,
        0x00, 0x24,
          0x00, 0x1d, // Group x25519
          0x00, 0x20, // Length of key exchange (32 bytes)
          0x75, 0x25, 0x96, 0x06, 0x84, 0x35, 0x9d, 0x2d, // key
          0xfd, 0x47, 0x29, 0x5d, 0xc0, 0xc2, 0xbe, 0x00, // key
          0x29, 0xf6, 0xc1, 0xc1, 0x3b, 0x9f, 0x48, 0xc5, // key
          0x29, 0x8f, 0xb5, 0x58, 0x71, 0x6b, 0xb4, 0x7b, // key
]);

const tlsPlaintext1 = TLSPlaintext.parse(clientHello);
console.log(tlsPlaintext1.log());

const bytes = tlsPlaintext1.serialize();

console.log(bytes.toString('hex') + '\n');

const tlsPlaintext2 = TLSPlaintext.parse(bytes);
console.log(tlsPlaintext2.log());

const tlsPlaintext3 = new TLSPlaintext(ContentType.Handshake);
tlsPlaintext3.Handshake = new Handshake(HandshakeType.ClientHello);
tlsPlaintext3.Handshake.ClientHello = new ClientHello([ CipherSuite.TLS_AES_128_GCM_SHA256 ]);
tlsPlaintext3.Handshake.ClientHello.Extensions = [
  new SupportedGroupsExtension([ NamedGroup.X25519 ]),
  new SignatureAlgorithmsExtension([ SignatureScheme.Ed25519 ]),
  new SupportedVersionsExtension([ 0x0304 ]),
  new PskKeyExchangeModesExtension([ PskKeyExchangeMode.pskDheKe ]),
  new KeyShareExtension(new Map([
    [ NamedGroup.X25519, crypto.randomBytes(32) ]
  ])),
];
console.log(tlsPlaintext3.log());
console.log(tlsPlaintext3.serialize().length);


const server = tls.createServer({
  requestCert: false,
}, (socket) => {
  // console.log('server connected',
  //             socket.authorized ? 'authorized' : 'unauthorized');
  // socket.write('welcome!\n');
  // socket.setEncoding('utf8');
  // socket.pipe(socket);
});
server.listen(8000, () => {
  console.log('server bound');
});

// console.log(tlsSocket.getProtocol());
const socket = net.connect({ port: 8000, host: 'localhost'}, () => {
  console.log('connected');
  socket.on('data', (data) => {
    const tlsMsg = TLSPlaintext.parse(data);
    console.log(tlsMsg.log());
  });
  socket.write(clientHello);


  // 15 03 03 00 02 02 28
});
