import { TLSBase } from "./TLSBase.mjs";

export enum AlertLevel {
  Warning = 1,
  Fatal = 2,
}

export enum AlertDescription {
  close_notify = 0,
  unexpected_message = 10,
  bad_record_mac = 20,
  record_overflow = 22,
  handshake_failure = 40,
  bad_certificate = 42,
  unsupported_certificate = 43,
  certificate_revoked = 44,
  certificate_expired = 45,
  certificate_unknown = 46,
  illegal_parameter = 47,
  unknown_ca = 48,
  access_denied = 49,
  decode_error = 50,
  decrypt_error = 51,
  protocol_version = 70,
  insufficient_security = 71,
  internal_error = 80,
  inappropriate_fallback = 86,
  user_canceled = 90,
  missing_extension = 109,
  unsupported_extension = 110,
  unrecognized_name = 112,
  bad_certificate_status_response = 113,
  unknown_psk_identity = 115,
  certificate_required = 116,
  no_application_protocol = 120,
}

export class Alert extends TLSBase {
  private level = AlertLevel.Warning;
  private description = AlertDescription.close_notify;

  public constructor(level?: AlertLevel, description?: AlertDescription) {
    super();
    this.level = level ?? this.level;
    this.description = description ?? this.description;
  }

  public override log(padding = 0): string {
    return this.pad(padding, `Alert:\n`) +
      this.pad(padding, `  Level: ${AlertLevel[this.level]} (${this.level})\n`) +
      this.pad(padding, `  Description: ${AlertDescription[this.description]} (${this.description})\n`);
  }

  public override serialize(): Buffer {
    const bytes = Buffer.alloc(2);
    bytes[0] = this.level;
    bytes[1] = this.description;
    return bytes;
  }

  public static parse(b: Buffer): Alert {
    const alert = new Alert();
    alert.level = b[0];
    alert.description = b[1];
    return alert;
  }
}
