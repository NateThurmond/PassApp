// RFC 5054 2048-bit group (hex). g = 2
const N_HEX =
  "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050" +
  "A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50" +
  "E8083969EDB767B0CF6096C3D6A9F0BFF5CB6F406B7EDEE386BFB5A899FA5AE9" +
  "F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A691" +
  "63FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670" +
  "C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF";
const g = 2n;
const N = BigInt("0x" + N_HEX.replace(/\s+/g, ""));

async function sha256(bytes) {
  const buf = await crypto.subtle.digest("SHA-256", bytes);
  return new Uint8Array(buf);
}

function utf8(str) {
  return new TextEncoder().encode(str);
}
function hexToBytes(hex) {
  if (hex.startsWith("0x")) hex = hex.slice(2);
  if (hex.length % 2) hex = "0" + hex;
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}
function hexToBigInt(hex) {
  if (hex.startsWith("0x")) hex = hex.slice(2);
  return BigInt("0x" + hex);
}
function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
}
function concatBytes(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0); out.set(b, a.length);
  return out;
}
function modPow(base, exp, mod) {
  let result = 1n;
  let b = BigInt(base) % mod;
  let e = BigInt(exp);
  while (e > 0n) {
    if (e & 1n) result = (result * b) % mod;
    b = (b * b) % mod;
    e >>= 1n;
  }
  return result;
}

/**
 * Compute SRP verifier v = g^x mod N, where x = H(s || H(I ":" P))
 * @param {string} username
 * @param {string} password
 * @param {Uint8Array|string} saltBytes   // pass Uint8Array, or hex string
 * @returns {{saltHex:string, verifierHex:string}}
 */
async function computeSrpVerifier(username, password, saltBytes) {
  const s = saltBytes instanceof Uint8Array ? saltBytes : hexToBytes(String(saltBytes));
  // Inner hash: H(I ":" P)
  const inner = await sha256(utf8(`${username}:${password}`));
  // xH = H( s || inner )
  const xH = await sha256(concatBytes(s, inner));
  // Convert x to BigInt
  const x = BigInt("0x" + bytesToHex(xH));
  // v = g^x mod N
  const v = modPow(g, x, N);
  // Output hex (no 0x prefix)
  return {
    saltHex: bytesToHex(s),
    verifierHex: v.toString(16)
  };
}

// random 32-byte private value (for login)
function randomPrivateA(bytes=32){
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  return BigInt("0x" + bytesToHex(arr));
}

// pad A to N size (hex) for consistent encoding
function padHexToN(hex) { return hex.padStart(N_HEX.length, "0"); }

// Generate client ephemeral
function genClientEphemeral(){
  let a, A;
  do {
    a = randomPrivateA(32); // private ephemeral (client-side only)
    A = modPow(g, a, N); // public ephemeral (passed to server)
  } while (A === 0n); // extremely unlikely, but required by SRP

  return {
    a, // BigInt (for browser storage and later use)
    Ahex: padHexToN(A.toString(16)) // send to server for proof
  };
}

async function sha256Bytes(...parts) {
  const msg = new Uint8Array(parts.reduce((len, p) => len + p.length, 0));
  let offset = 0;
  for (const p of parts) { msg.set(p, offset); offset += p.length; }
  const buf = await crypto.subtle.digest("SHA-256", msg);
  return new Uint8Array(buf);
}

function bigIntToBytes(bi) {
  let hex = bi.toString(16);
  if (hex.length % 2) hex = "0" + hex;
  return Uint8Array.from(hex.match(/.{2}/g).map(byte => parseInt(byte, 16)));
}

async function computeM1(username, saltBytes, A_big, B_big, K_bytes, N, g) {
  const HN = await sha256Bytes(bigIntToBytes(N));
  const Hg = await sha256Bytes(bigIntToBytes(g));
  const Hxor = new Uint8Array(HN.length);
  for (let i = 0; i < HN.length; i++) Hxor[i] = HN[i] ^ Hg[i];

  const HI = await sha256Bytes(new TextEncoder().encode(username));

  const m1_bytes = await sha256Bytes(
    Hxor,
    HI,
    saltBytes,
    bigIntToBytes(A_big),
    bigIntToBytes(B_big),
    K_bytes
  );

  return Array.from(m1_bytes).map(b => b.toString(16).padStart(2, "0")).join("");
}