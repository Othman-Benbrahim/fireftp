/*
  Echange de cles curve25519-sha256 (RFC 8731), avec X25519 (RFC 7748).

  Necessaire pour OpenSSH >= 10.0, dont la configuration serveur par defaut
  n'offre plus aucun echange Diffie-Hellman classique (diffie-hellman-group*).

  Note : l'arithmetique repose sur BigInteger.js et n'est pas a temps constant.
  La cle privee est ephemere (une par connexion), ce qui limite fortement
  l'interet d'une attaque temporelle cote client.
*/

paramikojs.KexCurve25519 = function(transport) {
  this.transport = transport;
  this.hash_algo = kryptos.hash.SHA256;
  this.priv = null;   // 32 octets (chaine binaire), scalaire X25519
  this.Q_C = null;    // 32 octets, cle publique ephemere du client
}

paramikojs.KexCurve25519._MSG_KEX_ECDH_INIT = 30;
paramikojs.KexCurve25519._MSG_KEX_ECDH_REPLY = 31;

paramikojs.KexCurve25519.P = new BigInteger("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed", 16);
paramikojs.KexCurve25519.A24 = new BigInteger("121665", 10);

// --- X25519 (RFC 7748, section 5) ------------------------------------------------

// chaine binaire little-endian -> BigInteger
paramikojs.KexCurve25519._decodeLE = function(s) {
  var hex = '';
  for (var i = s.length - 1; i >= 0; --i) {
    var c = s.charCodeAt(i).toString(16);
    hex += (c.length == 1 ? '0' : '') + c;
  }
  return new BigInteger(hex, 16);
};

// BigInteger -> 32 octets little-endian
paramikojs.KexCurve25519._encodeLE = function(n) {
  var hex = n.toString(16);
  while (hex.length < 64) {
    hex = '0' + hex;
  }
  var out = '';
  for (var i = 62; i >= 0; i -= 2) {
    out += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
  }
  return out;
};

// k, u : chaines de 32 octets ; renvoie X25519(k, u) sur 32 octets
paramikojs.KexCurve25519.x25519 = function(k, u) {
  var C = paramikojs.KexCurve25519;
  var p = C.P;
  if (k.length != 32 || u.length != 32) {
    throw new paramikojs.ssh_exception.SSHException('X25519: longueur invalide');
  }

  // decodeScalar25519
  k = String.fromCharCode(k.charCodeAt(0) & 248) + k.substring(1, 31) +
      String.fromCharCode((k.charCodeAt(31) & 127) | 64);
  var scalar = C._decodeLE(k);

  // decodeUCoordinate : bit de poids fort ignore
  u = u.substring(0, 31) + String.fromCharCode(u.charCodeAt(31) & 127);
  var x1 = C._decodeLE(u).mod(p);

  var x2 = BigInteger.ONE, z2 = BigInteger.ZERO;
  var x3 = x1,             z3 = BigInteger.ONE;
  var swap = 0, tmp;

  for (var t = 254; t >= 0; --t) {
    var kt = scalar.testBit(t) ? 1 : 0;
    swap ^= kt;
    if (swap) {
      tmp = x2; x2 = x3; x3 = tmp;
      tmp = z2; z2 = z3; z3 = tmp;
    }
    swap = kt;

    var A  = x2.add(z2).mod(p);
    var AA = A.multiply(A).mod(p);
    var B  = x2.subtract(z2).mod(p);
    var BB = B.multiply(B).mod(p);
    var E  = AA.subtract(BB).mod(p);
    var Cc = x3.add(z3).mod(p);
    var D  = x3.subtract(z3).mod(p);
    var DA = D.multiply(A).mod(p);
    var CB = Cc.multiply(B).mod(p);
    var s1 = DA.add(CB).mod(p);
    var s2 = DA.subtract(CB).mod(p);
    x3 = s1.multiply(s1).mod(p);
    z3 = x1.multiply(s2.multiply(s2)).mod(p);
    x2 = AA.multiply(BB).mod(p);
    z2 = E.multiply(AA.add(C.A24.multiply(E))).mod(p);
  }
  if (swap) {
    tmp = x2; x2 = x3; x3 = tmp;
    tmp = z2; z2 = z3; z3 = tmp;
  }

  var result = x2.multiply(z2.modPow(p.subtract(new BigInteger("2", 10)), p)).mod(p);
  return C._encodeLE(result);
};

paramikojs.KexCurve25519.BASE_POINT = String.fromCharCode(9) + new Array(32).join('\x00');

// --- protocole SSH ------------------------------------------------------------------

paramikojs.KexCurve25519.prototype = {
  name : 'curve25519-sha256',

  start_kex : function() {
    if (this.transport.server_mode) {
      throw new paramikojs.ssh_exception.SSHException('curve25519-sha256 : mode serveur non pris en charge');
    }
    this.priv = this.transport.rng.read(32);
    this.Q_C = paramikojs.KexCurve25519.x25519(this.priv, paramikojs.KexCurve25519.BASE_POINT);

    var m = new paramikojs.Message();
    m.add_byte(String.fromCharCode(paramikojs.KexCurve25519._MSG_KEX_ECDH_INIT));
    m.add_string(this.Q_C);
    this.transport._send_message(m);
    this.transport._expect_packet(paramikojs.KexCurve25519._MSG_KEX_ECDH_REPLY);
  },

  parse_next : function(ptype, m) {
    if (!this.transport.server_mode && ptype == paramikojs.KexCurve25519._MSG_KEX_ECDH_REPLY) {
      return this._parse_kex_ecdh_reply(m);
    }
    throw new paramikojs.ssh_exception.SSHException('KexCurve25519 asked to handle packet type ' + ptype);
  },

  _parse_kex_ecdh_reply : function(m) {
    var host_key = m.get_string();
    var Q_S = m.get_string();
    var sig = m.get_string();

    if (Q_S.length != 32) {
      throw new paramikojs.ssh_exception.SSHException('curve25519 : cle publique serveur invalide');
    }

    var X = paramikojs.KexCurve25519.x25519(this.priv, Q_S);
    this.priv = null;
    if (X == new Array(33).join('\x00')) {
      throw new paramikojs.ssh_exception.SSHException('curve25519 : secret partage nul');
    }

    // RFC 8731 : les 32 octets de X sont lus comme un entier non signe big-endian
    var K = paramikojs.util.inflate_long(X, true);

    // H = HASH(V_C || V_S || I_C || I_S || K_S || Q_C || Q_S || K)
    var hm = new paramikojs.Message();
    hm.add(this.transport.local_version, this.transport.remote_version,
           this.transport.local_kex_init, this.transport.remote_kex_init);
    hm.add_string(host_key);
    hm.add_string(this.Q_C);
    hm.add_string(Q_S);
    hm.add_mpint(K);
    this.transport._set_K_H(K, new this.hash_algo(hm.toString()).digest());
    this.transport._verify_key(host_key, sig);
    this.transport._activate_outbound();
  }
};
