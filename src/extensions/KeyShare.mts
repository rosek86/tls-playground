import { ExtensionType, Extension } from "./Extension.mjs";
import { NamedGroup } from "./NamedGroup.mjs";


export class KeyShareExtension extends Extension {
  private clientShares: Map<NamedGroup, Buffer>;

  public constructor(clientShares?: Map<NamedGroup, Buffer>) {
    super();
    this.type = ExtensionType.KeyShare;
    this.clientShares = clientShares ?? new Map();
  }

  public get ClientShares(): Map<NamedGroup, Buffer> {
    return this.clientShares;
  }

  public set ClientShares(clientShares: Map<NamedGroup, Buffer>) {
    this.clientShares = clientShares;
  }

  public getClientShare(type: NamedGroup): Buffer | undefined{
    return this.clientShares.get(type);
  }

  public override log(padding = 0): string {
    let log = super.log(padding);

    for (const type of this.clientShares.keys()) {
      log += this.pad(padding, `  ${NamedGroup[type]}: ${this.getClientShare(type)?.toString('base64')}\n`);
    }

    return log;
  }

  public override serialize(): Buffer {
    let length = 2;
    for (const [ _, keyExchange ] of this.clientShares) {
      length += 2 + 2 + keyExchange.length;
    }

    const fragment = Buffer.alloc(length);

    let i = 0;
    i = fragment.writeUInt16BE(length - 2, i);

    for (const [ type, keyExchange ] of this.clientShares) {
      i  = fragment.writeUInt16BE(type, i);
      i  = fragment.writeUInt16BE(keyExchange.length, i);
      i += keyExchange.copy(fragment, i);
    }

    return this.opaque(fragment);
  }

  public static override parse(type: ExtensionType, b: Buffer): Extension {
    const e = new KeyShareExtension();
    e.type = type;

    let i = 0;
    const length = b.readUInt16BE(i); i += 2;

    if (length !== (b.length - 2)) {
      throw new Error(`Invalid extension length: ${length} / ${b.length - 2}`);
    }

    while (i < b.length) {
      const group = b.readUInt16BE(i) as NamedGroup; i += 2;
      const length = b.readUInt16BE(i); i += 2;
      const keyExchange = b.slice(i, i + length); i += length;

      if (length !== keyExchange.length) {
        throw new Error(`Invalid key length: ${length} / ${keyExchange.length}`);
      }

      e.clientShares.set(group, keyExchange);
    }

    return e;
  }
}
