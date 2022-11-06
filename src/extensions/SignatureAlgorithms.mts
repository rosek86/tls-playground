import { Extension, ExtensionType } from "./Extension.mjs";

export enum SignatureScheme {
  /* RSASSA-PKCS1-v1_5 algorithms */
  RsaPkcs1Sha256          = (0x0401),
  RsaPkcs1Sha384          = (0x0501),
  RsaPkcs1Sha512          = (0x0601),

  /* ECDSA algorithms */
  EcdsaSecp256r1Sha256    = (0x0403),
  EcdsaSecp384r1Sha384    = (0x0503),
  EcdsaSecp521r1Sha512    = (0x0603),

  /* RSASSA-PSS algorithms with public key OID rsaEncryption */
  RsaPssRsaeSha256        = (0x0804),
  RsaPssRsaeSha384        = (0x0805),
  RsaPssRsaeSha512        = (0x0806),

  /* EdDSA algorithms */
  Ed25519                 = (0x0807),
  Ed448                   = (0x0808),

  /* RSASSA-PSS algorithms with public key OID RSASSA-PSS */
  RsaPssPssSha256         = (0x0809),
  RsaPssPssSha384         = (0x080a),
  RsaPssPssSha512         = (0x080b),

  /* Legacy algorithms */
  RsaPkcs1Sha1            = (0x0201),
  EcdsaSha1               = (0x0203),

  /* Reserved Code Points */
  // private_use(0xFE00..0xFFFF),
};

export class SignatureAlgorithmsExtension extends Extension {
  private signatureAlgorithms: SignatureScheme[];

  public constructor(signatureAlgorithms?: SignatureScheme[]) {
    super();
    this.type = ExtensionType.SignatureAlgorithms;
    this.signatureAlgorithms = signatureAlgorithms ?? [];
  }

  public get SignatureAlgorithms(): SignatureScheme[] {
    return this.signatureAlgorithms;
  }

  public set SignatureAlgorithms(signatureAlgorithms: SignatureScheme[]) {
    this.signatureAlgorithms = signatureAlgorithms;
  }

  public override log(padding = 0): string {
    let log = super.log(padding);

    for (const algo of this.signatureAlgorithms) {
      log += this.pad(padding, `  ${SignatureScheme[algo]}\n`);
    }

    return log;
  }

  public override serialize(): Buffer {
    const fragment = Buffer.alloc(2 + 2 * this.signatureAlgorithms.length);

    let i = 0;
    i = fragment.writeUInt16BE(2 * this.signatureAlgorithms.length, i);

    for (const signatureAlgorithm of this.signatureAlgorithms) {
      i = fragment.writeUInt16BE(signatureAlgorithm, i);
    }

    return this.opaque(fragment);
  }

  public static override parse(type: ExtensionType, b: Buffer): Extension {
    const e = new SignatureAlgorithmsExtension();
    e.type = type;

    let i = 0;
    const length = b.readUInt16BE(i); i += 2;

    if (length !== (b.length - 2)) {
      throw new Error(`Invalid extension length: ${length} / ${b.length - 2}`);
    }

    while (i < b.length) {
      e.signatureAlgorithms.push(b.readUInt16BE(i)); i += 2;
    }

    return e;
  }
}
