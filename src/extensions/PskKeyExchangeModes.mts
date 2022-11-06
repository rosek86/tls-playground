import { ExtensionType, Extension } from "./Extension.mjs";

export enum PskKeyExchangeMode {
  pskKe     = 0, // PSK-only key establishment
  pskDheKe  = 1, // PSK with (EC)DHE key establishment
}

export class PskKeyExchangeModesExtension extends Extension {
  private modes: PskKeyExchangeMode[];

  public constructor(modes?: PskKeyExchangeMode[]) {
    super();
    this.type = ExtensionType.PskKeyExchangeModes;
    this.modes = modes ?? [];
  }

  public get Modes(): PskKeyExchangeMode[] {
    return this.modes;
  }

  public set Modes(modes: PskKeyExchangeMode[]) {
    this.modes = modes;
  }

  public override log(padding = 0): string {
    let log = super.log(padding);

    for (const type of this.modes) {
      log += this.pad(padding, `  ${PskKeyExchangeMode[type]}\n`);
    }

    return log;
  }

  public override serialize(): Buffer {
    const fragment = Buffer.alloc(1 + this.modes.length);

    let i = 0;
    i = fragment.writeUInt8(this.modes.length, i);

    for (const mode of this.modes) {
      i = fragment.writeUInt8(mode, i);
    }

    return this.opaque(fragment);
  }

  public static override parse(type: ExtensionType, b: Buffer): Extension {
    const e = new PskKeyExchangeModesExtension();
    e.type = type;

    let i = 0;
    const length = b.readUInt8(i); i += 1;

    if (length !== (b.length - 1)) {
      throw new Error(`Invalid extension length: ${length} / ${b.length - 1}`);
    }

    while (i < b.length) {
      e.modes.push(b.readUInt8(i)); i += 1;
    }

    return e;
  }
}
