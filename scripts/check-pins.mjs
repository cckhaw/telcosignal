import { readFileSync } from "node:fs";
const pkg = JSON.parse(readFileSync("package.json", "utf8"));
const bad = [];
for (const sec of ["dependencies", "devDependencies", "optionalDependencies"]) {
  for (const [n, v] of Object.entries(pkg[sec] ?? {})) if (!/^\d+\.\d+\.\d+$/.test(v)) bad.push(`${sec}.${n}=${v}`);
}
if (bad.length) { console.error("Non-exact pins:\n" + bad.join("\n")); process.exit(1); }
console.log("all dependency pins exact");
