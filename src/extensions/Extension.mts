import { TLSBase } from "../TLSBase.mjs";

export enum ExtensionType {
  ServerName = 0,                              /* RFC 6066 */
  MaxFragmentLength = 1,                       /* RFC 6066 */
  ClientCertificateUrl = 2,                    /* RFC 6066 */
  TrustedCaKeys = 3,                           /* RFC 6066 */
  TruncatedHmac = 4,                           /* RFC 6066 */
  StatusRequest = 5,                           /* RFC 6066 */
  UserMapping = 6,                             /* RFC 4681 */
  ClientAuthz = 7,                             /* RFC 5878 */
  ServerAuthz = 8,                             /* RFC 5878 */
  CertType = 9,                                /* RFC 6091 */
  SupportedGroups = 10,                        /* RFC 8422, 7919 */
  EcPointFormats = 11,                         /* RFC 8422 */
  Srp = 12,                                    /* RFC5054 */
  SignatureAlgorithms = 13,                    /* RFC 8446 */
  UseSrtp = 14,                                /* RFC 5764 */
  Heartbeat = 15,                              /* RFC 6520 */
  ApplicationLayerProtocolNegotiation = 16,    /* RFC 7301 */
  StatusRequestV2 = 17,                        /* RFC 6961 */
  SignedCertificateTimestamp = 18,             /* RFC 6962 */
  ClientCertificateType = 19,                  /* RFC 7250 */
  ServerCertificateType = 20,                  /* RFC 7250 */
  Padding = 21,                                /* RFC 7685 */
  EncryptThenMac = 22,                         /* RFC 7366 */
  ExtendedMasterSecret = 23,                   /* RFC 7627 */
  TokenBinding = 24,                           /* RFC 8472 */
  CachedInfo = 25,                             /* RFC 7924 */
  TlsLts = 26,                                 /* draft-gutmann-tls-lts */
  CompressCertificate = 27,                    /* RFC 8879 */
  RecordSizeLimit = 28,                        /* RFC 8449 */
  PwdProtect = 29,                             /* RFC 8492 */
  PwdClear = 30,                               /* RFC 8492 */
  PasswordSalt = 31,                           /* RFC 8492 */
  TicketPinning = 32,                          /* RFC 8672 */
  TlsCertWithExternPsk = 33,                   /* RFC 8773 */
  DelegatedCredentials = 34,                   /* RFC ietf-tls-subcerts-15 */
  SessionTicket = 35,                          /* RFC 5077, 8447 */
  Tlmps = 36,                                  /* ETSI TS 103 523-2 */
  TlmpsDelegate = 38,                          /* ETSI TS 103 523-2 */
  TlmpsProxying = 37,                          /* ETSI TS 103 523-2 */
  SupportedEktCiphers = 39,                    /* RFC 8870 */
  Reserved1 = 40,
  PreSharedKey = 41,                           /* RFC 8446 */
  EarlyData = 42,                              /* RFC 8446 */
  SupportedVersions = 43,                      /* RFC 8446 */
  Cookie = 44,                                 /* RFC 8446 */
  PskKeyExchangeModes = 45,                    /* RFC 8446 */
  Reserved2 = 46,
  CertificateAuthorities = 47,                 /* RFC 8446 */
  OidFilters = 48,                             /* RFC 8446 */
  PostHandshakeAuth = 49,                      /* RFC 8446 */
  SignatureAlgorithmsCert = 50,                /* RFC 8446 */
  KeyShare = 51,                               /* RFC 8446 */
  TransparencyInfo = 52,                       /* RFC 9162, */
  ConnectionIdDeprecated = 53,                 /* RFC 9146, */
  ConnectionId = 54,                           /* RFC 9146, */
  ExternalIdHash = 55,                         /* RFC 8844, */
  ExternalSessionId = 56,                      /* RFC 8844, */
  QuicTransportParameters = 57,                /* RFC 9001, */
  TicketRequest = 58,                          /* RFC 9149, */
  DnssecChain = 59,                            /* RFC 9102, 6860 */
}

export abstract class Extension extends TLSBase {
  protected type = ExtensionType.ServerName;

  public get Type(): ExtensionType {
    return this.type;
  }

  public set Type(type: ExtensionType) {
    this.type = type;
  }

  public override log(padding = 0): string {
    return this.pad(padding,
      `${ExtensionType[this.type].padEnd(40, ' ')} ` +
      `(${this.type.toString().padEnd(2, ' ')} = 0x${this.type.toString(16).padStart(2, '0')})\n`);
  }

  public abstract override serialize(): Buffer;

  protected opaque(fragment: Buffer): Buffer {
    const bytes = Buffer.alloc(2 + 2);

    let i = 0;
    i = bytes.writeUInt16BE(this.Type, i);
    i = bytes.writeUInt16BE(fragment.length, i);

    return Buffer.concat([ bytes, fragment ]);
  }

  public static parse(_type: ExtensionType, _b: Buffer): Extension {
    throw new Error('Implemented in sub classes');
  }
}
