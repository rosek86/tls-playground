
import { TLSBase } from "./TLSBase.mjs";
import { ClientHello } from "./ClientHello.mjs";

export enum HandshakeType {
  ClientHello = 1,
  ServerHello = 2,
  NewSessionTicket = 4,
  EndOfEarlyData = 5,
  EncryptedExtensions = 8,
  Certificate = 11,
  CertificateRequest = 13,
  CertificateVerify = 15,
  Finished = 20,
  KeyUpdate = 24,
  MessageHash = 254,
}

export class Handshake extends TLSBase {
  private msgType = HandshakeType.ClientHello;

  private clientHello: ClientHello | null = null;

  public constructor(msgType?: HandshakeType) {
    super();
    this.msgType = msgType ?? this.msgType;
  }

  public get MsgType(): HandshakeType {
    return this.msgType;
  }

  public set MsgType(type: HandshakeType) {
    this.msgType = type
  }

  public get ClientHello(): ClientHello {
    if (!this.clientHello) { throw new Error(`Incorrect content type (no client hallo)`); }
    return this.clientHello;
  }

  public set ClientHello(clientHello: ClientHello) {
    this.clientHello = clientHello;
  }

  public override log(padding = 0): string {
    let log =
      this.pad(padding, `Handshake\n`) +
      this.pad(padding, `  HandshakeType: ${HandshakeType[this.msgType]} (${this.msgType})\n`);

    switch (this.msgType) {
      case HandshakeType.ClientHello:
        log += this.clientHello?.log(padding + 2);
        break;
    }

    return log;
  }

  public override serialize(): Buffer {
    const bytes = Buffer.alloc(1 + 3);

    let i = 0;
    i = bytes.writeUInt8(this.msgType, i);

    let fragment = Buffer.alloc(0);

    switch (this.msgType) {
      case HandshakeType.ClientHello:
        fragment = this.ClientHello.serialize();
        break;
    }

    i = bytes.writeUIntBE(fragment.length, i, 3);

    return Buffer.concat([ bytes, fragment ]);
  }

  public static parse(b: Buffer): Handshake {
    const h = new Handshake();

    let i = 0;
    h.msgType = b.readUInt8(i); i += 1;
    const length = b.readUIntBE(i, 3); i += 3;
    const fragment = b.slice(i, i + length); i += length;

    switch (h.msgType) {
      case HandshakeType.ClientHello:
        h.clientHello = ClientHello.parse(fragment);
        break;
    }

    return h;
  }
}
