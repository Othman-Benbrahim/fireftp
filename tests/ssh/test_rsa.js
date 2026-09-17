const vm = require('vm'), fs = require('fs'), crypto = require('crypto');
const base = require('path').join(__dirname, '../../src/content/js/connection/paramikojs') + '/';
const ctx = {
  console,
  Components: { classes: { "@mozilla.org/security/hash;1": { createInstance() {
    let h; return { initWithString(t){ h = crypto.createHash(t); }, update(a){ h.update(Buffer.from(a)); },
      finish(){ return h.digest().toString('latin1'); } }; } } },
    interfaces: { nsICryptoHash: {} } },
  inherit(d, b) { for (var p in b) if (!d[p]) d[p] = b[p]; },
};
ctx.window = ctx; ctx.navigator = { userAgent: 'Mozilla/5.0 (X11; Linux x86_64) Goanna PaleMoon/34', platform: 'Linux x86_64' }; vm.createContext(ctx);
const files = ['kryptos/kryptos.js','kryptos/Hash/baseHash.js','kryptos/Hash/SHA.js','kryptos/Hash/SHA256.js',
 'kryptos/Hash/SHA512.js','kryptos/PublicKey/RSA.js','kryptos/Cipher/AES.js','kryptos/Cipher/DES3.js','common.js','python_shim.js','BigInteger.js','util.js',
 'ssh_exception.js','message.js','pkey.js','rsakey.js'];
for (const f of files) vm.runInContext(fs.readFileSync(base + f, 'utf8'), ctx, { filename: f });
vm.runInContext('this.P = paramikojs; this.BI = BigInteger;', ctx);

const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwk = privateKey.export({ format: 'jwk' });
const b2bi = (s) => new ctx.BI(Buffer.from(s, 'base64url').toString('hex'), 16);
const n = b2bi(jwk.n), e = b2bi(jwk.e), d = b2bi(jwk.d);
const key = new ctx.P.RSAKey(null, null, null, null, [e, n], null);
key.d = d;
const data = 'donnees de session SSH ' + Date.now();

let ok = true;
const check = (label, cond) => { console.log((cond ? 'OK   ' : 'FAIL ') + label); ok = ok && cond; };
for (const [alg, h] of [['ssh-rsa','sha1'],['rsa-sha2-256','sha256'],['rsa-sha2-512','sha512']]) {
  // 1) signature produite par OpenSSL -> vérifiée par paramikojs (clé hôte serveur)
  const sig = crypto.sign(h, Buffer.from(data, 'latin1'), privateKey).toString('latin1');
  const m = new ctx.P.Message(); m.add_string(alg); m.add_string(sig);
  check(`verify ${alg} (signature OpenSSL)`, key.verify_ssh_sig(data, new ctx.P.Message(m.toString()), alg));
  // mauvais algorithme attendu -> refus
  check(`refus si alg négocié différent (${alg})`, !key.verify_ssh_sig(data, new ctx.P.Message(m.toString()), alg == 'ssh-rsa' ? 'rsa-sha2-256' : 'ssh-rsa'));
  // 2) signature produite par paramikojs (auth client) -> vérifiée par OpenSSL ; simule le Worker
  ctx.gRsaKeyWorkerJs = 'x';
  ctx.Worker = function() { const self = this; this.postMessage = (msg) => {
    const rsa = new ctx.P.RSAKey(null,null,null,null,[e,n],null);
    const inflated = ctx.P.util.inflate_long(msg.pkcs1imified, true);
    const s = inflated.modPow(new ctx.BI(msg.d,10), new ctx.BI(msg.n,10));
    self.onmessage({ data: s.toString() }); }; };
  key.sign_ssh_data(null, data, (sm) => {
    const r = new ctx.P.Message(sm.toString());
    const name = r.get_string(), s = Buffer.from(r.get_string(), 'latin1');
    check(`sign ${alg} : nom=${name}, longueur=${s.length}`, name === alg && s.length === 256);
    check(`sign ${alg} vérifiée par OpenSSL`, crypto.verify(h, Buffer.from(data,'latin1'), publicKey, s));
  }, alg);
}
process.exit(ok ? 0 : 1);
