export abstract class TLSBase {
  public abstract log(padding: number): string;
  public abstract serialize(): Buffer;

  protected pad(padding = 0, s: string): string {
    return ``.padStart(padding, ` `) + s;
  }

  protected toSSLVersion(version: number) {
    return `${(version >> 8) & 0xFF}.${(version >> 0) & 0xFF}`;
  }

  protected toTLSVersion(version: number): string | undefined {
    const V: {[id: number]: string} = { 0x0304: '1.3', 0x0303: '1.2', 0x0302: '1.1', 0x0301: '1.0' };
    return V[version];
  }

  protected formatVersion(version: number): string {
    return `TLSv${this.toTLSVersion(version)} (SSLv${this.toSSLVersion(version)})`;
  }
}
