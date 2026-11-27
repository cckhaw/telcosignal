// Test PKI generated at runtime with the openssl CLI. Nothing here is committed; keys live in a temp dir.
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const sh = (args: string[], cwd: string) => execFileSync("openssl", args, { cwd, stdio: ["ignore", "pipe", "pipe"] });
export interface Pem { cert: string; key: string }
export class TestPki {
  readonly dir = mkdtempSync(join(tmpdir(), "ts-pki-"));
  readonly caCert: string;
  readonly rogueCaCert: string;
  constructor() {
    this.caCert = this.ca("ca");
    this.rogueCaCert = this.ca("rogue");
  }
  private ca(name: string): string {
    sh(["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", `${name}.key`, "-out", `${name}.crt`, "-days", "2", "-subj", `/CN=test-${name}-ca`], this.dir);
    return readFileSync(join(this.dir, `${name}.crt`), "utf8");
  }
  issue(name: string, o: { server?: boolean; ca?: "ca" | "rogue" } = {}): Pem {
    const ca = o.ca ?? "ca";
    const eku = o.server ? "serverAuth" : "clientAuth";
    sh(["req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", `${name}.key`, "-out", `${name}.csr`, "-subj", `/CN=${name}`], this.dir);
    writeFileSync(join(this.dir, `${name}.ext`), `basicConstraints=CA:FALSE\nextendedKeyUsage=${eku}\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n`);
    sh(["x509", "-req", "-in", `${name}.csr`, "-CA", `${ca}.crt`, "-CAkey", `${ca}.key`, "-CAcreateserial", "-out", `${name}.crt`, "-days", "2", "-extfile", `${name}.ext`], this.dir);
    return { cert: readFileSync(join(this.dir, `${name}.crt`), "utf8"), key: readFileSync(join(this.dir, `${name}.key`), "utf8") };
  }
}
