import { Extension, ExtensionType } from "./Extension.mjs";

export enum ServerNameType {
  HostName = 0,
}

export class ServerNameExtension extends Extension {
  private names: Map<ServerNameType, string>;

  public constructor(names?: Map<ServerNameType, string>) {
    super();
    this.type = ExtensionType.ServerName;
    this.names = names ?? new Map();
  }

  public get Names(): Map<ServerNameType, string> {
    return this.names;
  }

  public set Names(names: Map<ServerNameType, string>) {
    this.names = names;
  }

  public getName(type: ServerNameType): string | undefined{
    return this.names.get(type);
  }

  public override log(padding = 0): string {
    let log = super.log(padding);

    for (const type of this.names.keys()) {
      log += this.pad(padding, `  ${ServerNameType[type]}: ${this.getName(type)}\n`);
    }

    return log;
  }

  public override serialize(): Buffer {
    let length = 2;
    for (const [ _, name ] of this.names) {
      length += 1 + 2 + name.length;
    }

    const fragment = Buffer.alloc(length);

    let i = 0;
    i = fragment.writeUInt16BE(length - 2, i);

    for (const [ type, name ] of this.names) {
      i  = fragment.writeUInt8(type, i);
      i  = fragment.writeUInt16BE(name.length, i);
      i += Buffer.from(name).copy(fragment, i);
    }

    return this.opaque(fragment);
  }

  public static override parse(type: ExtensionType, b: Buffer): Extension {
    const e = new ServerNameExtension();
    e.type = type;

    let i = 0;
    const length = b.readUInt16BE(i); i += 2;

    if (length !== (b.length - 2)) {
      throw new Error(`Invalid extension length: ${length} / ${b.length - 2}`);
    }

    while (i < b.length) {
      const type    = b.readUInt8(i);     i += 1;
      const length  = b.readUInt16BE(i);  i += 2;

      if (type === ServerNameType.HostName) {
        const slice = b.slice(i, i + length);

        if (slice.length !== length) {
          throw new Error(`Invalid host name length: ${length} / ${slice.length}`);
        }
        if (e.names.get(type) !== undefined) {
          throw new Error(`Host name duplicated`);
        }

        e.names.set(type, slice.toString('ascii'));
      }

      i += length;
    }

    return e;
  }
}
