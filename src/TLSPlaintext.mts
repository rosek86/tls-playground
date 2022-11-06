import { TLSBase } from "./TLSBase.mjs";
import { Alert } from "./Alert.mjs";
import { Handshake } from "./Handshake.mjs";

export enum ContentType {
  Invalid = 0,
  ChangeCipherSpec = 20,
  Alert = 21,
  Handshake = 22,
  ApplicationData = 23,
}

export class TLSPlaintext extends TLSBase {
  private contentType = ContentType.Handshake;
  private legacyRecordVersion = 0x0301;

  private handshake: Handshake | null = null;
  private alert: Alert | null = null;

  public constructor(contentType?: ContentType) {
    super();
    this.contentType = contentType ?? this.contentType;
  }

  public get ContentType(): ContentType {
    return this.contentType;
  }

  public set ContentType(contentType: number) {
    this.contentType = contentType;
  }

  public get LegacyRecordVersion(): number {
    return this.legacyRecordVersion;
  }

  public set LegacyRecordVersion(version: number) {
    this.legacyRecordVersion = version;
  }

  public formatLegacyRecordVersion(): string {
    return this.formatVersion(this.LegacyRecordVersion);
  }

  public get Handshake(): Handshake {
    if (!this.handshake) { throw new Error(`Incorrect content type (no handshake)`); }
    return this.handshake;
  }

  public set Handshake(handshake: Handshake) {
    this.handshake = handshake;
  }

  public get Alert(): Alert {
    if (!this.alert) { throw new Error(`Incorrect content type (no alert)`); }
    return this.alert;
  }

  public set Alert(alert: Alert) {
    this.alert = alert;
  }

  public override log(padding = 0): string {
    let log =
      this.pad(padding, `TLSPlaintext\n`) +
      this.pad(padding, `  ContentType: ${ContentType[this.contentType]} (${this.contentType})\n`) +
      this.pad(padding, `  LegacyRecordVersion: ${this.formatLegacyRecordVersion()}\n`);

    switch (this.contentType) {
      case ContentType.Handshake:
        log += this.Handshake.log(padding + 2);
        break;
      case ContentType.Alert:
        log += this.Alert.log(padding + 2);
    }

    return log;
  }

  public override serialize(): Buffer {
    const bytes = Buffer.alloc(1 + 2 + 2);

    let i = 0;
    i = bytes.writeUInt8(this.contentType, i);
    i = bytes.writeUInt16BE(this.legacyRecordVersion, i);

    let fragment = Buffer.alloc(0);

    switch (this.contentType) {
      case ContentType.Handshake: fragment = this.Handshake.serialize();  break;
      case ContentType.Alert:     fragment = this.Alert.serialize();      break;
      default:
        console.log(`unknown content type: ${this.contentType}`);
        break;
    }

    i = bytes.writeUInt16BE(fragment.length, i);

    return Buffer.concat([ bytes, fragment ]);
  }

  public static parse(b: Buffer): TLSPlaintext {
    const plainText = new TLSPlaintext();

    let i = 0;
    plainText.contentType = b.readUInt8(i); i += 1;
    plainText.legacyRecordVersion = b.readUInt16BE(i); i += 2;

    const length = b.readUInt16BE(i); i += 2;
    const fragment = b.slice(i, i + length); i += length;

    switch (plainText.contentType) {
      case ContentType.Handshake:
        plainText.handshake = Handshake.parse(fragment);
        break;
      case ContentType.Alert:
        plainText.alert = Alert.parse(fragment);
        break;
      default:
        console.log(`unknown content type: ${plainText.contentType}`);
        break;
    }

    return plainText;
  }
}
