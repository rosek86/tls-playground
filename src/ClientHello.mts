import crypto from 'crypto';

import { TLSBase } from "./TLSBase.mjs";
import { Extension, ExtensionType } from './extensions/Extension.mjs';
import { CipherSuite } from './CipherSuite.mjs';
import { ExtensionParser } from './extensions/ExtensionsParser.mjs';

export class ClientHello extends TLSBase {
  private legacyVersion = 0x0303;
  private random = crypto.randomBytes(32);
  private legacySessionId = Buffer.alloc(0);
  private cipherSuites: CipherSuite[] = [];
  private legacyCompressionMethods = [0];
  private extensions: Map<ExtensionType, Extension> = new Map();

  public constructor(cipherSuites?: CipherSuite[]) {
    super();
    this.cipherSuites = cipherSuites ?? this.cipherSuites;
  }

  public get LegacyVersion(): number {
    return this.legacyVersion;
  }

  public set LegacyVersion(version: number) {
    this.legacyVersion = version;
  }

  public formatLegacyVersion(): string {
    return this.formatVersion(this.legacyVersion);
  }

  public get Random(): Buffer {
    return this.random;
  }

  public set Random(random: Buffer) {
    this.random = random;
  }

  public generateRandom(): void {
    this.random = crypto.randomBytes(32);
  }

  public get LegacySessionId(): Buffer {
    return this.legacySessionId;
  }

  public set LegacySessionId(legacySessionId: Buffer) {
    this.legacySessionId = legacySessionId;
  }

  public get CipherSuites(): CipherSuite[] {
    return this.cipherSuites;
  }

  public set CipherSuites(cipherSuites: CipherSuite[]) {
    this.cipherSuites = cipherSuites;
  }

  public get LegacyCompressionMethods(): number[] {
    return this.legacyCompressionMethods;
  }

  public set LegacyCompressionMethods(legacyCompressionMethods: number[]) {
    this.legacyCompressionMethods = legacyCompressionMethods;
  }

  public get Extensions(): Extension[] {
    return [...this.extensions.values()];
  }

  public set Extensions(extensions: Extension[]) {
    this.extensions = new Map();
    for (const extension of extensions) {
      this.extensions.set(extension.Type, extension);
    }
  }

  public getExtension(type: ExtensionType): Extension | undefined {
    return this.extensions.get(type);
  }

  public override log(padding = 0): string {
    let log = '';

    log +=
      this.pad(padding, `ClientHello\n`) +
      this.pad(padding, `  LegacyVersion: ${this.formatLegacyVersion()}\n`) +
      this.pad(padding, `  Random: ${this.Random.toString('base64')}\n`) +
      this.pad(padding, `  LegacySessionId: ${this.LegacySessionId.toString('base64')}\n`);

    log += this.pad(padding, `  CipherSuites:\n`);
    for (const cipherSuite of this.CipherSuites) {
      log += this.pad(padding, `    ${CipherSuite[cipherSuite]}\n`);
    }

    log += this.pad(padding, `  LegacyCompressionMethods:\n`);
    for (const legacyCompressionMethod of this.LegacyCompressionMethods) {
      log += this.pad(padding, `    ${legacyCompressionMethod.toString(16)}\n`);
    }

    log += this.pad(padding, `  Extensions:\n`);
    for (const extension of this.Extensions) {
      log += extension.log(padding + 4);
    }

    return log;
  }

  public override serialize(): Buffer {
    const bytes = Buffer.alloc(
      2 + 32 + 1 + this.legacySessionId.length +
      2 + this.CipherSuites.length * 2 +
      1 + this.LegacyCompressionMethods.length +
      2
    );

    let i = 0;
    i  = bytes.writeUInt16BE(this.legacyVersion, i);

    i += this.Random.copy(bytes, i);

    i  = bytes.writeUInt8(this.LegacySessionId.length, i);
    i += this.LegacySessionId.copy(bytes, i);

    i  = bytes.writeUInt16BE(this.CipherSuites.length * 2, i);
    for (const cipherSuite of this.CipherSuites) {
      i = bytes.writeUInt16BE(cipherSuite, i);
    }

    i = bytes.writeUInt8(this.LegacyCompressionMethods.length, i);
    for (const legacyCompressionMethod of this.LegacyCompressionMethods) {
      i = bytes.writeUInt8(legacyCompressionMethod, i);
    }

    const fragment = Buffer.concat([
      ...this.Extensions.map((e) => e.serialize())
    ]);

    i = bytes.writeUInt16BE(fragment.length, i);

    return Buffer.concat([ bytes, fragment ]);
  }

  public static parse(b: Buffer): ClientHello {
    const hello = new ClientHello();

    let i = 0;

    hello.legacyVersion = b.readUInt16BE(i); i += 2;

    hello.random = b.slice(i, i + 32); i += 32;

    const legacySessionIdLength = b[i]; i += 1;
    hello.legacySessionId = b.slice(i, i + legacySessionIdLength);
    i += legacySessionIdLength;

    const cipherSuitesLength = b.readUInt16BE(i); i += 2;
    hello.cipherSuites = [];
    for (let j = 0; j < cipherSuitesLength; j += 2, i += 2) {
      hello.cipherSuites.push(b.readUInt16BE(i));
    }

    const legacyCompressionMethodsLength = b[i]; i += 1;
    hello.legacyCompressionMethods = [];
    for (let j = 0; j < legacyCompressionMethodsLength; j += 1, i += 1) {
      hello.legacyCompressionMethods.push(b[i]);
    }

    const extensionsLength = b.readUInt16BE(i); i += 2;
    hello.extensions = ExtensionParser.parseList(b.slice(i, i + extensionsLength));

    return hello;
  }
}
