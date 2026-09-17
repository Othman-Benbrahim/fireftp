// Banc de test : exécute paramikojs (comme FireFTP) contre un vrai OpenSSH.
// usage : node harness.js [password|key]
// variables : SSH_HOST (127.0.0.1), SSH_PORT (22), SSH_USER, SSH_PASS, SSH_KEY (cle RSA PEM),
//             EXPECT (nom d'un fichier attendu dans le dossier d'accueil, optionnel)
const vm = require('vm'), fs = require('fs'), crypto = require('crypto'), net = require('net');
const path = require('path');
const mode = process.argv[2] || 'password';
const base = path.join(__dirname, '../../src/content/js/connection/paramikojs') + '/';
const HOST = process.env.SSH_HOST || '127.0.0.1', PORT = parseInt(process.env.SSH_PORT || '22', 10);
const USER = process.env.SSH_USER, PASS = process.env.SSH_PASS, KEYFILE = process.env.SSH_KEY, EXPECT = process.env.EXPECT;
if (!USER || (mode === 'password' && !PASS) || (mode === 'key' && !KEYFILE)) {
  console.error('Definir SSH_USER et SSH_PASS (mode password) ou SSH_KEY (mode key).'); process.exit(2);
}
const order = ['kryptos/kryptos.js','kryptos/Cipher/AES.js','kryptos/Cipher/Blowfish.js','kryptos/Cipher/DES3.js',
 'kryptos/Cipher/ARC4.js','kryptos/Hash/baseHash.js','kryptos/Hash/SHA.js','kryptos/Hash/SHA256.js','kryptos/Hash/SHA512.js',
 'kryptos/Hash/MD5.js','kryptos/Hash/HMAC.js','kryptos/PublicKey/RSA.js','kryptos/PublicKey/DSA.js',
 'kryptos/Random/_UserFriendlyRNG.js','kryptos/Random/Fortuna/SHAd256.js','kryptos/Random/Fortuna/FortunaAccumulator.js',
 'kryptos/Random/Fortuna/FortunaGenerator.js','kryptos/Random/OSRNG/browser.js','common.js','python_shim.js','BigInteger.js',
 'agent.js','auth_handler.js','ber.js','channel.js','client.js','compress.js','dsskey.js','file.js','hostkeys.js',
 'kex_gex.js','kex_group1.js','kex_group14.js','message.js','packet.js','pkey.js','rsakey.js','sftp_attr.js',
 'sftp_client.js','sftp_file.js','sftp.js','ssh_exception.js','transport.js','unknown_key.js','util.js','win_pageant.js'];
const logs = [];
const ctx = {
  console, setTimeout, clearTimeout, crypto: { getRandomValues: (a) => crypto.randomFillSync(a) },
  navigator: { userAgent: 'Mozilla/5.0 (X11; Linux x86_64) Goanna/6 PaleMoon/34', platform: 'Linux x86_64' },
  Components: { classes: {
      "@mozilla.org/security/hash;1": { createInstance() { let h; return {
        initWithString(t){ h = crypto.createHash(t); }, update(a){ h.update(Buffer.from(a)); },
        finish(){ return h.digest().toString('latin1'); } }; } },
      "@mozilla.org/security/hmac;1": { createInstance() { let h; const alg = {2:'md5',3:'sha1',4:'sha256',6:'sha512'}; return {
        MD5: 2, SHA1: 3, SHA256: 4, SHA512: 6,
        init(a, key){ h = crypto.createHmac(alg[a], Buffer.from(key.k, 'latin1')); },
        update(d){ h.update(Buffer.from(d)); }, finish(){ return h.digest().toString('latin1'); } }; } },
      "@mozilla.org/security/keyobjectfactory;1": { getService() { return { keyFromString: (t, k) => ({ k }) }; } },
      "@mozilla.org/intl/utf8converterservice;1": { getService() { return { convertStringToUTF8: s => Buffer.from(s,'utf8').toString('latin1') }; } },
      "@mozilla.org/intl/scriptableunicodeconverter": { getService() { return { ConvertFromUnicode: s => s, Finish: () => '' }; } },
    }, interfaces: new Proxy({}, { get: (t, n) => n === 'nsIKeyObject' ? { HMAC: 257 } : ({}) }) },
  debug: (m) => logs.push('debug: ' + m),
  gStrbundle: { getString: s => s, getFormattedString: s => s },
  localFile: { init: () => ({ exists: () => false }) },
  inherit(d, b) { for (var p in b) if (!d[p]) d[p] = b[p]; },
  gRsaKeyWorkerJs: 'worker',
};
ctx.window = ctx; ctx.self = ctx;
vm.createContext(ctx);
for (const f of order) vm.runInContext(fs.readFileSync(base + f, 'utf8'), ctx, { filename: f });
// Worker de signature RSA : même calcul que sign_ssh_data_worker.js, en synchrone
ctx.Worker = function () { const w = this; this.postMessage = (d) => setTimeout(() => {
  const r = vm.runInContext(`(function(d){ var rsa = new kryptos.publicKey.RSA().construct(new BigInteger(d.n,10), new BigInteger(d.e,10), new BigInteger(d.d,10));
    return rsa.sign(paramikojs.util.inflate_long(d.pkcs1imified, true), '')[0].toString(); })`, ctx)(d);
  w.onmessage({ data: r }); }, 0); };
vm.runInContext(`logging.log = function(level, msg) { __log('[' + level + '] ' + msg); };`, Object.assign(ctx, { __log: m => logs.push(m) }));

const observer = { version: '-FireFTP-test', onDebug: m => logs.push('onDebug: ' + m), onError: m => logs.push('onError: ' + m),
  onSftpCache: (b, k, cb) => cb(true) };
const sock = net.connect(PORT, HOST);
let transport, done = false;
const finish = (ok, why) => { if (done) return; done = true; console.log((ok ? 'SUCCÈS' : 'ÉCHEC') + ' [' + mode + '] ' + why);
  console.log(logs.filter(l => /onDebug|onError|Disconnect|Incompatible|sig|kex|key|Auth|auth|rsa/i.test(l)).slice(-12).map(l => '   ' + l.slice(0, 200)).join('\n'));
  sock.destroy(); process.exit(ok ? 0 : 1); };
sock.on('close', () => finish(false, 'connexion fermée par le serveur'));
sock.on('error', (e) => finish(false, 'erreur réseau : ' + e.message));
sock.on('connect', () => {
  const client = vm.runInContext('new paramikojs.SSHClient()', ctx);
  client.set_missing_host_key_policy(vm.runInContext('new paramikojs.AutoAddPolicy()', ctx));
  let pkey = null;
  if (mode === 'key') {
    const jwk = crypto.createPrivateKey(fs.readFileSync(KEYFILE)).export({ format: 'jwk' });
    const bi = s => vm.runInContext(`new BigInteger('${Buffer.from(s,'base64url').toString('hex')}', 16)`, ctx);
    pkey = vm.runInContext('(function(e,n,d){ var k = new paramikojs.RSAKey(null,null,null,null,[e,n],null); k.d = d; return k; })', ctx)(bi(jwk.e), bi(jwk.n), bi(jwk.d));
  }
  const write = out => sock.write(Buffer.from(out, 'latin1'));
  const auth_success = () => client.open_sftp(sftp => sftp.listdir('.', list => {
    const names = [].concat(list).map(a => a.filename || a).join(', ');
    finish(EXPECT ? names.split(', ').indexOf(EXPECT) != -1 : true, `SFTP listdir: ${names}  | clé hôte négociée: ${transport.host_key_type}`);
  }));
  transport = client.connect(observer, write, auth_success, HOST, PORT, USER,
                             mode === 'password' ? PASS : null, pkey, null, null, false, false);
  sock.on('data', buf => { try { transport.fullBuffer += buf.toString('latin1'); transport.run(); }
                          catch (ex) { finish(false, 'exception: ' + (ex.message || ex)); } });
});
setTimeout(() => finish(false, 'délai dépassé'), 60000);
