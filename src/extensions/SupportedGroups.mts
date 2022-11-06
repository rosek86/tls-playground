import { Extension, ExtensionType } from "./Extension.mjs";
import { NamedGroup } from "./NamedGroup.mjs";

export class SupportedGroupsExtension extends Extension {
  private supportedGroups: NamedGroup[];

  public constructor(supportedGroups?: NamedGroup[]) {
    super();
    this.type = ExtensionType.SupportedGroups;
    this.supportedGroups = supportedGroups ?? [];
  }

  public get SupportedGroups(): NamedGroup[] {
    return this.supportedGroups;
  }

  public set SupportedGroups(supportedGroups: NamedGroup[]) {
    this.supportedGroups = supportedGroups;
  }

  public override log(padding = 0): string {
    let log = super.log(padding);

    for (const group of this.supportedGroups) {
      log += this.pad(padding, `  ${NamedGroup[group]}\n`);
    }

    return log;
  }

  public override serialize(): Buffer {
    const fragment = Buffer.alloc(2 + 2 * this.supportedGroups.length);

    let i = 0;
    i = fragment.writeUInt16BE(2 * this.supportedGroups.length, i);

    for (const supportedGroup of this.supportedGroups) {
      i = fragment.writeUInt16BE(supportedGroup, i);
    }

    return this.opaque(fragment);
  }

  public static override parse(type: ExtensionType, b: Buffer): Extension {
    const e = new SupportedGroupsExtension();
    e.type = type;

    let i = 0;
    const length = b.readUInt16BE(i); i += 2;

    if (length !== (b.length - 2)) {
      throw new Error(`Invalid extension length: ${length} / ${b.length - 2}`);
    }

    while (i < b.length) {
      e.supportedGroups.push(b.readUInt16BE(i)); i += 2;
    }

    return e;
  }
}
