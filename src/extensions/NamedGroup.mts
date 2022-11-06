export enum NamedGroup {
  // unallocated_RESERVED(0x0000),

  /* Elliptic Curve Groups (ECDHE) */
  // obsolete_RESERVED(0x0001..0x0016),
  Secp256r1 = (0x0017),
  Secp384r1 = (0x0018),
  Secp521r1 = (0x0019),
  // obsolete_RESERVED(0x001A..0x001C),
  X25519    = (0x001d),
  X448      = (0x001e),

  /* Finite Field Groups (DHE) */
  Ffdhe2048 = (0x0100),
  Ffdhe3072 = (0x0101),
  Ffdhe4096 = (0x0102),
  Ffdhe6144 = (0x0103),
  Ffdhe8192 = (0x0104),

  /* Reserved Code Points */
  // ffdhe_private_use(0x01FC..0x01FF),
  // ecdhe_private_use(0xFE00..0xFEFF),
  // obsolete_RESERVED(0xFF01..0xFF02),
}
