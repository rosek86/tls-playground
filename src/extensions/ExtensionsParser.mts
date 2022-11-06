import { Extension, ExtensionType } from "./Extension.mjs";
import { ServerNameExtension } from "./ServerName.mjs";
import { SupportedVersionsExtension } from "./SupportedVersions.mjs";
import { PskKeyExchangeModesExtension } from "./PskKeyExchangeModes.mjs";
import { KeyShareExtension } from "./KeyShare.mjs";
import { SignatureAlgorithmsExtension } from "./SignatureAlgorithms.mjs";
import { SupportedGroupsExtension } from "./SupportedGroups.mjs";
import { NotImplementedExtension } from "./NotImplemented.mjs";

export abstract class ExtensionParser {
  public static parseList(b: Buffer): Map<ExtensionType, Extension> {
    let i = 0;
    const extensions: Map<ExtensionType, Extension> = new Map();
    while (i < b.length) {
      const type = b.readUInt16BE(i) as ExtensionType; i += 2;
      const length = b.readUInt16BE(i); i += 2;
      const fragment = b.slice(i, i + length); i += length;

      if (length !== fragment.length) {
        throw new Error('Cannot parse extension - invalid length');
      }
  
      extensions.set(type, this.parse(type, fragment));
    }
    return extensions;
  }

  public static parse(type: ExtensionType, b: Buffer): Extension {
    switch (type) {
      case ExtensionType.ServerName:          return ServerNameExtension          .parse(type, b);
      case ExtensionType.SupportedVersions:   return SupportedVersionsExtension   .parse(type, b);
      case ExtensionType.SupportedGroups:     return SupportedGroupsExtension     .parse(type, b);
      case ExtensionType.SignatureAlgorithms: return SignatureAlgorithmsExtension .parse(type, b);
      case ExtensionType.PskKeyExchangeModes: return PskKeyExchangeModesExtension .parse(type, b);
      case ExtensionType.KeyShare:            return KeyShareExtension            .parse(type, b);
    }

    return NotImplementedExtension.parse(type, b);
  }
}
