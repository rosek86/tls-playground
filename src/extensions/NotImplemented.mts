import { Extension, ExtensionType } from "./Extension.mjs";

export class NotImplementedExtension extends Extension {
  public override serialize(): Buffer {
    return this.opaque(Buffer.alloc(0));
  }

  public static override parse(type: ExtensionType, _: Buffer): Extension {
    const e = new NotImplementedExtension();
    e.type = type;
    return e;
  }
}
