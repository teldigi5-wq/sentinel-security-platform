/** Offline, deterministic provenance guard for the committed npm v3 lock. */
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const packagePath = process.argv[2] ? resolve(process.argv[2]) : resolve(root, "package.json");
const lockPath = process.argv[3] ? resolve(process.argv[3]) : resolve(root, "package-lock.json");

function verify(manifest, lock) {
  if (lock.lockfileVersion !== 3 || lock.requires !== true || !lock.packages || typeof lock.packages !== "object") {
    throw new Error("Missing or unsupported npm v3 lockfile");
  }
  const top = lock.packages[""];
  if (!top || top.name !== manifest.name || top.version !== manifest.version || lock.name !== manifest.name || lock.version !== manifest.version) {
    throw new Error("Root package identity is inconsistent");
  }
  for (const field of ["dependencies", "devDependencies", "optionalDependencies"]) {
    const expected = manifest[field] ?? {};
    const locked = top[field] ?? {};
    if (JSON.stringify(Object.entries(expected).sort()) !== JSON.stringify(Object.entries(locked).sort())) {
      throw new Error(`Lockfile root ${field} differs from package.json`);
    }
  }
  const declared = { ...manifest.dependencies, ...manifest.devDependencies, ...manifest.optionalDependencies };
  for (const name of Object.keys(declared)) {
    if (!lock.packages[`node_modules/${name}`]) throw new Error(`Direct dependency is missing: ${name}`);
  }
  let resolved = 0;
  for (const [name, pkg] of Object.entries(lock.packages)) {
    if (name === "") continue;
    if (!name.startsWith("node_modules/") || !pkg || typeof pkg !== "object" || pkg.link) {
      throw new Error(`Unexpected lock entry or symbolic link: ${name}`);
    }
    // Reject resolved git/http/tarball/file dependencies or credentials in the registry URL.
    if (typeof pkg.resolved !== "string") throw new Error(`Missing resolution for ${name}`);
    let url;
    try { url = new URL(pkg.resolved); } catch { throw new Error(`Invalid package URL: ${name}`); }
    if (url.protocol !== "https:" || url.hostname !== "registry.npmjs.org" || url.username || url.password || url.port || url.search || url.hash) {
      throw new Error(`Unapproved package source: ${name}`);
    }
    if (typeof pkg.integrity !== "string" || !/^sha(?:256|384|512)-[A-Za-z0-9+/]+={0,2}$/.test(pkg.integrity)) {
      throw new Error(`Missing or invalid integrity hash: ${name}`);
    }
    if (typeof pkg.version !== "string") throw new Error(`Missing resolved version: ${name}`);
    resolved += 1;
  }
  if (resolved === 0) throw new Error("Empty dependency tree");
  return resolved;
}

try {
  const manifest = JSON.parse(readFileSync(packagePath, "utf8"));
  const lock = JSON.parse(readFileSync(lockPath, "utf8"));
  const count = verify(manifest, lock);
  console.log(`Verified ${count} integrity-pinned npm packages from registry.npmjs.org.`);
} catch (error) {
  console.error(`Frontend lock verification failed: ${error.message}`);
  process.exitCode = 1;
}
