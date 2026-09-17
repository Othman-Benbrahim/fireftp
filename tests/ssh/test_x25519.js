// Verifie X25519 (kex_curve25519.js) : vecteurs RFC 7748 + comparaison avec OpenSSL.
const vm = require('vm'), fs = require('fs'), path = require('path'), crypto = require('crypto');
const base = path.join(__dirname, '../../src/content/js/connection/paramikojs') + '/';
const ctx = { navigator: { userAgent: 'x', platform: 'Linux x86_64' }, window: {}, Components: {}, inherit(d, b) { for (var p in b) if (!d[p]) d[p] = b[p]; } };
vm.createContext(ctx);
for (const f of ['kryptos/kryptos.js', 'common.js', 'python_shim.js', 'BigInteger.js', 'util.js', 'ssh_exception.js', 'kex_curve25519.js'])
  vm.runInContext(fs.readFileSync(base + f, 'utf8'), ctx, { filename: f });
const X = vm.runInContext('paramikojs.KexCurve25519.x25519', ctx);
const s = h => Buffer.from(h, 'hex').toString('latin1'), h = b => Buffer.from(b, 'latin1').toString('hex');
let ok = true;
const check = (label, got, exp) => { const r = got === exp; ok = ok && r; console.log((r ? 'OK   ' : 'FAIL ') + label + (r ? '' : `\n  attendu ${exp}\n  obtenu  ${got}`)); };

// RFC 7748 section 5.2
check('RFC 7748 vecteur 1', h(X(s('a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4'), s('e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c'))),
      'c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552');
check('RFC 7748 vecteur 2', h(X(s('4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d'), s('e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493'))),
      '95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957');
// RFC 7748 section 6.1 (Diffie-Hellman Alice/Bob)
const a = s('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a');
const b = s('5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb');
const B9 = s('09' + '00'.repeat(31));
check('RFC 7748 clé publique Alice', h(X(a, B9)), '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a');
check('RFC 7748 secret partagé', h(X(a, X(b, B9))), '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742');

// Comparaison aleatoire avec OpenSSL
for (let i = 0; i < 5; i++) {
  const me = crypto.generateKeyPairSync('x25519'), peer = crypto.generateKeyPairSync('x25519');
  const mePriv = Buffer.from(me.privateKey.export({ format: 'jwk' }).d, 'base64url').toString('latin1');
  const peerPub = Buffer.from(peer.publicKey.export({ format: 'jwk' }).x, 'base64url').toString('latin1');
  const expect = crypto.diffieHellman({ privateKey: me.privateKey, publicKey: peer.publicKey }).toString('hex');
  check(`secret partagé = OpenSSL (${i + 1})`, h(X(mePriv, peerPub)), expect);
}
const t = Date.now(); X(a, B9); console.log(`durée d'une opération X25519 : ${Date.now() - t} ms`);
process.exit(ok ? 0 : 1);
