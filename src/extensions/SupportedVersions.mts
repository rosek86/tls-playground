import { Extension, ExtensionType } from "./Extension.mjs";

export class SupportedVersionsExtension extends Extension {
  private versions: number[];

  public constructor(versions?: number[]) {
    super();
    this.type = ExtensionType.SupportedVersions;
    this.versions = versions ?? [];
  }

  public get Versions(): number[] {
    return this.versions;
  }

  public set Versions(versions: number[]) {
    this.versions = versions;
  }

  public getVersionsSSLNotation(): string[] {
    return this.versions.map((v) => this.toSSLVersion(v));
  }

  public getVersionsTLSNotation(): string[] {
    return this.versions
      .map((v) => this.toTLSVersion(v))
      .filter((v?: string): v is string => !!v);
  }

  public override log(padding = 0): string {
    let log = super.log(padding);

    for (const version of this.versions) {
      log += this.pad(padding, `  ${this.formatVersion(version)}\n`);
    }

    return log;
  }

  public override serialize(): Buffer {
    const fragment = Buffer.alloc(1 + 2 * this.versions.length);

    let i = 0;
    i = fragment.writeUInt8(2 * this.versions.length, i);

    for (const version of this.versions) {
      i = fragment.writeUInt16BE(version, i);
    }

    return this.opaque(fragment);
  }

  public static override parse(type: ExtensionType, b: Buffer): Extension {
    const e = new SupportedVersionsExtension();
    e.type = type;

    let i = 0;
    const length = b.readUInt8(i); i += 1;

    if (length !== (b.length - 1)) {
      throw new Error(`Invalid extension length: ${length} / ${b.length - 1}`);
    }

    e.versions = [];

    while (i < b.length) {
      e.versions.push(b.readUInt16BE(i)); i += 2;
    }

    return e;
  }
}
