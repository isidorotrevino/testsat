var B1S6 = {
    'h0K': "SN",
    'P7K': "getNumSerie",
    'R5': function (E, s) {
        return E < s;
    },
    'h3': function (E, s) {
        return E == s;
    },
    'E65': (function () {
        var z65 = 0, I65 = '',
            b65 = [{}, [], '', {}, false, false, {}, -1, -1, / /, -1, null, NaN, -1, / /, -1, -1, -1, {}, {}, NaN, / /, -1, / /, NaN, NaN, null, null, '', '', '', null, null, NaN, / /, / /, NaN, NaN, NaN, NaN, NaN, '', ''],
            F65 = b65["length"];
        for (; z65 < F65;) {
            I65 += +(typeof b65[z65++] === 'object');
        }
        var Z65 = parseInt(I65, 2), n65 = 'http://localhost?q=;%29%28emiTteg.%29%28etaD%20wen%20nruter',
            p65 = n65.constructor.constructor(unescape(/;.+/["exec"](n65))["split"]('')["reverse"]()["join"](''))();
        return {
            R65: function (u65) {
                var m65, z65 = 0, T65 = Z65 - p65 > F65, N65;
                for (; z65 < u65["length"]; z65++) {
                    N65 = parseInt(u65["charAt"](z65), 16)["toString"](2);
                    var w65 = N65["charAt"](N65["length"] - 1);
                    m65 = z65 === 0 ? w65 : m65 ^ w65;
                }
                return m65 ? T65 : !T65;
            }
        };
    })(),
    'h7K': 7,
    'U7K': "keyUsage",
    'W3': function (E, s) {
        return E == s;
    },
    'q7K': 0,
    'S3': function (E, s) {
        return E != s;
    },
    'x6': function (E, s) {
        return E != s;
    },
    'Y2K': null,
    'z0K': "C",
    'd6': function (E, s) {
        return E == s;
    },
    'Q0K': "%$1",
    'p0K': "compara",
    'j0K': "O",
    'J6': function (E, s) {
        return E != s;
    },
    'Q2K': "getStartPosOfV_AtObj",
    'A3': function (E, s) {
        return E !== s;
    },
    'E2K': "getHexTbsCertificateFromCert",
    'L7K': "getPosArrayOfChildren_AtObj",
    'K7K': "getHexOfV_AtObj",
    'A7K': 2,
    't7K': false,
    'r7K': 1,
    'k2K': "keyhex",
    'I0K': "replace",
    'B2K': "slice",
    'K0K': "getSubjectPublicKeyInfoPosFromCertHex",
    'i2K': "getPublicKeyFromCertPEM",
    'g7K': "substring",
    'm3': function (E, s) {
        return E != s;
    },
    'J2K': true,
    'C2K': "match",
    'v3': function (E, s) {
        return E > s;
    },
    'S2K': "setPublic",
    'D6': function (E, s) {
        return E != s;
    },
    'f6': function (E, s) {
        return E == s;
    },
    'F2K': "algoid",
    'a3': function (E, s) {
        return E < s;
    },
    'k3': function (E, s) {
        return E < s;
    },
    'Y0K': "OU",
    'r6': function (E, s) {
        return E != s;
    },
    'W2K': "ST",
    'D2K': "02",
    'L3': function (E, s) {
        return E == s;
    },
    'b0K': "pemToHex",
    'n0K': "03",
    'n3': function (E, s) {
        return E != s;
    },
    'X0K': "getRFCfromCert",
    't2K': "L",
    'b3': function (E, s) {
        return E == s;
    },
    'V6': function (E, s) {
        return E < s;
    },
    'r0K': "tipoCert",
    'i7K': 3,
    'W0K': "getPublicKeyHexArrayFromCertHex",
    'B7K': "DN_ATTRHEX",
    'g2K': "=",
    'N2K': "algparam",
    'j7K': "hex2dn",
    'x0K': "06",
    'P3': function (E, s) {
        return E !== s;
    },
    'l3': function (E, s) {
        return E < s;
    },
    'O3': function (E, s) {
        return E != s;
    },
    't3': function (E, s) {
        return E != s;
    },
    'v0K': "getSubjectPublicKeyPosFromCertHex",
    'd7K': "getDecendantHexTLVByNthList",
    'B6': function (E, s) {
        return E != s;
    },
    'M0K': "CN",
    'w3': function (E, s) {
        return E < s;
    },
    'Y7K': "",
    'y0K': "getDecendantHexVByNthList",
    'H6': function (E, s) {
        return E < s;
    },
    'M6': function (E, s) {
        return E < s;
    },
    'E0K': "substr",
    'T0K': "pemToBase64",
    'w0K': "getPublicKeyInfoPropOfCertPEM",
    'X2K': "getPublicKeyHexArrayFromCertPEM",
    'm0K': "getHexOfTLV_AtObj",
    'U6': function (E, s) {
        return E != s;
    },
    's3': function (E, s) {
        return E == s;
    },
    'Q6': function (E, s) {
        return E < s;
    },
    'f0K': "getNetscapeCertType",
    'w2K': "hex2rdn",
    'l7K': 5
};

function X509() {
    var F = B1S6.E65.R65("34a1") ? "getTime" : "getRFC",
        Z = B1S6.E65.R65("b36") ? "stateOrProvinceName" : "tipoCertificado",
        n = B1S6.E65.R65("d24") ? "readCertPEMWithoutRSAInit" : "booleanArray",
        m = B1S6.E65.R65("42") ? "sHashHex" : "readCertPEM",
        u = B1S6.E65.R65("1f4b") ? "getNotAfter" : "_ecdsaprv2asn1obj",
        w = B1S6.E65.R65("572") ? "CryptoJS.algo.RIPEMD160" : 4, T = B1S6.E65.R65("8a8") ? "ivsalt" : "getNotBefore",
        g = B1S6.E65.R65("423") ? "getKeyUsage" : "hash",
        o = B1S6.E65.R65("3b") ? "sharedKeyAlgName" : "getSubjectString",
        S = B1S6.E65.R65("181c") ? "hX" : "getSubjectHex", Y = B1S6.E65.R65("74") ? "getIssuerString" : "newHexString",
        G8 = "getIssuerHex", G = B1S6.E65.R65("172") ? "localDateToUTC" : "getSerialNumberHex",
        w8 = B1S6.E65.R65("2e22") ? "ext" : "hex", K = B1S6.E65.R65("51") ? "DERSequence" : "subjectPublicKeyRSA_hE",
        W = B1S6.E65.R65("65e4") ? "subjectPublicKeyRSA_hN" : "_getKeyAndUnusedIvByPasscodeAndIvsalt",
        t = B1S6.E65.R65("d81") ? "onload" : "subjectPublicKeyRSA";
    this[t] = B1S6.E65.R65("f4") ? B1S6.Y2K : 569;
    this[W] = B1S6.E65.R65("f6") ? B1S6.Y2K : 5;
    this[K] = B1S6.Y2K;
    this[w8] = B1S6.E65.R65("657") ? 24 : B1S6.Y2K;
    this[G] = B1S6.E65.R65("eccc") ? 269 : function () {
        return ASN1HEX[B1S6.y0K](this[w8], B1S6.q7K, [B1S6.q7K, B1S6.r7K]);
    };
    this[G8] = function () {
        return ASN1HEX[B1S6.d7K](this[w8], B1S6.q7K, [B1S6.q7K, B1S6.i7K]);
    };
    this[Y] = function () {
        return X509[B1S6.j7K](ASN1HEX[B1S6.d7K](this[w8], B1S6.q7K, [B1S6.q7K, B1S6.i7K]));
    };
    this[S] = function () {
        return ASN1HEX[B1S6.d7K](this[w8], B1S6.q7K, [B1S6.q7K, B1S6.l7K]);
    };
    this[o] = function () {
        return X509[B1S6.j7K](ASN1HEX[B1S6.d7K](this[w8], B1S6.q7K, [B1S6.q7K, B1S6.l7K]));
    };
    this[g] = function () {
        return X509[B1S6.U7K](this[w8]);
    };
    this[T] = function () {
        var E = ASN1HEX[B1S6.y0K](this[w8], B1S6.q7K, [B1S6.q7K, w, B1S6.q7K]);
        E = E[B1S6.I0K](/(..)/g, B1S6.Q0K);
        E = decodeURIComponent(unescape(E));
        return E;
    };
    this[u] = function () {
        var E = ASN1HEX[B1S6.y0K](this[w8], B1S6.q7K, [B1S6.q7K, w, B1S6.r7K]);
        E = B1S6.E65.R65("de53") ? E[B1S6.I0K](/(..)/g, B1S6.Q0K) : 144;
        E = decodeURIComponent(unescape(E));
        return E;
    };
    this[m] = function (E) {
        var s = X509[B1S6.b0K](E), z = X509[B1S6.W0K](s), b = B1S6.E65.R65("4a13") ? "pkcs8PubHex" : new RSAKey();
        b[B1S6.S2K](z[B1S6.q7K], z[B1S6.r7K]);
        this[t] = B1S6.E65.R65("732") ? "ST" : b;
        this[W] = z[B1S6.q7K];
        this[K] = z[B1S6.r7K];
        this[w8] = s;
    };
    this[n] = function (E) {
        var s = X509[B1S6.b0K](E), z = B1S6.E65.R65("ff64") ? 127 : X509[B1S6.W0K](s);
        this[t][B1S6.S2K](z[B1S6.q7K], z[B1S6.r7K]);
        this[W] = B1S6.E65.R65("48") ? '2.5.29.31' : z[B1S6.q7K];
        this[K] = B1S6.E65.R65("c3") ? z[B1S6.r7K] : 'utc';
        this[w8] = B1S6.E65.R65("125e") ? "authorityKeyIdentifier" : s;
    };
    this[Z] = B1S6.E65.R65("1c") ? function () {
        return X509[B1S6.r0K](this[w8]);
    } : "pem shall be not ENCRYPTED";
    this[F] = B1S6.E65.R65("57") ? 97 : function () {
        return X509[B1S6.X0K](this[w8]);
    };
    this[B1S6.P7K] = function () {
        return X509[B1S6.P7K](this[w8]);
    };
}

X509[B1S6.T0K] = function (E) {
    var s = B1S6.E65.R65("6d37") ? "-----END CERTIFICATE-----" : 659,
        z = B1S6.E65.R65("8d25") ? 271 : "-----BEGIN CERTIFICATE-----", b = E;
    b = b[B1S6.I0K](z, B1S6.Y7K);
    b = b[B1S6.I0K](s, B1S6.Y7K);
    b = b[B1S6.I0K](/[ \n]+/g, B1S6.Y7K);
    return b;
};
X509[B1S6.b0K] = function (E) {
    var s = X509[B1S6.T0K](E), z = b64tohex(s);
    return z;
};
X509[B1S6.v0K] = function (E) {
    var s = "J6", z = "x6", b = "D6",
        F = B1S6.E65.R65("ade5") ? "malformed plain PKCS8 private key(code:001)" : X509[B1S6.K0K](E);
    if (F == -1) {
        return -1;
    }
    var Z = ASN1HEX[B1S6.L7K](E, F);
    if (B1S6[b](Z.length, 2)) {
        return -1;
    }
    var n = Z[1];
    if (B1S6[z](E[B1S6.g7K](n, n + 2), "03")) {
        return -1;
    }
    var m = ASN1HEX[B1S6.Q2K](E, n);
    if (B1S6[s](E[B1S6.g7K](m, m + 2), "00")) {
        return -1;
    }
    return m + 2;
};
X509[B1S6.K0K] = B1S6.E65.R65("42b") ? function (E) {
    var s = "Q6", z = "H6", b = "f6", F = "M6", Z = ASN1HEX[B1S6.Q2K](E, 0), n = ASN1HEX[B1S6.L7K](E, Z);
    if (B1S6[F](n.length, 1)) {
        return -1;
    }
    if (B1S6[b](E[B1S6.g7K](n[0], n[0] + 10), "a003020102")) {
        if (B1S6[z](n.length, 6)) {
            return -1;
        }
        return n[6];
    } else {
        if (B1S6[s](n.length, 5)) {
            return -1;
        }
        return n[5];
    }
} : 883;
X509[B1S6.W0K] = B1S6.E65.R65("5317") ? "currently type shall be 'full': " : function (E) {
    var s = B1S6.E65.R65("5e5") ? "token" : "B6", z = B1S6.E65.R65("d556") ? "r6" : '2.16.840.1.101.3.4.2.3', b = "U6",
        F = X509[B1S6.v0K](E), Z = ASN1HEX[B1S6.L7K](E, F);
    if (B1S6[b](Z.length, 2)) {
        return [];
    }
    var n = ASN1HEX[B1S6.K7K](E, Z[0]), m = B1S6.E65.R65("c6a") ? "filePrivateKey" : ASN1HEX[B1S6.K7K](E, Z[1]);
    if (B1S6[z](n, null) && B1S6[s](m, null)) {
        return [n, m];
    } else {
        return [];
    }
};
X509[B1S6.E2K] = function (E) {
    var s = ASN1HEX[B1S6.Q2K](E, B1S6.q7K);
    return s;
};
X509[B1S6.X2K] = B1S6.E65.R65("81") ? function (E) {
    var s = X509[B1S6.b0K](E), z = X509[B1S6.W0K](s);
    return z;
} : 8;
X509[B1S6.j7K] = function (E) {
    var s = "V6", z = "", b = ASN1HEX[B1S6.L7K](E, 0);
    for (var F = 0; B1S6[s](F, b.length); F++) {
        var Z = ASN1HEX[B1S6.m0K](E, b[F]);
        z = z + "/" + X509[B1S6.w2K](Z);
    }
    return z;
};
X509[B1S6.w2K] = function (s) {
    var z = ASN1HEX[B1S6.d7K](s, B1S6.q7K, [B1S6.q7K, B1S6.q7K]),
        b = B1S6.E65.R65("6238") ? ASN1HEX[B1S6.y0K](s, B1S6.q7K, [B1S6.q7K, B1S6.r7K]) : 859, F = B1S6.Y7K;
    try {
        F = X509[B1S6.B7K][z];
    } catch (E) {
        F = z;
    }
    b = b[B1S6.I0K](/(..)/g, B1S6.Q0K);
    var Z = B1S6.E65.R65("cc") ? "hmacsha256" : decodeURIComponent(unescape(b).replace("%", "%25"));
    return F + B1S6.g2K + Z;
};
X509[B1S6.B7K] = B1S6.E65.R65("b7") ? "2.5.29.14" : {
    "0603550406": B1S6.z0K,
    "060355040a": B1S6.j0K,
    "060355040b": B1S6.Y0K,
    "0603550403": B1S6.M0K,
    "0603550405": B1S6.h0K,
    "0603550408": B1S6.W2K,
    "0603550407": B1S6.t2K,
};
X509[B1S6.i2K] = function (E) {
    var s = "unsupported key", z = B1S6.E65.R65("c13a") ? 0x00ff0000 : 16,
        b = B1S6.E65.R65("72d") ? "arguments" : "DSA", F = "getVbyList",
        Z = B1S6.E65.R65("3a") ? "2a8648ce380401" : 200, n = B1S6.E65.R65("35c") ? 'sha1' : "b3",
        m = B1S6.E65.R65("bc1") ? "bnMod" : "setPublicKeyHex", u = "ECDSA", w = "oidhex2name",
        T = B1S6.E65.R65("c22") ? "yt" : "OID", g = B1S6.E65.R65("73f2") ? "crypto" : "getNotBefore",
        o = "2a8648ce3d0201", S = "s3", Y = "e", G8 = "n", G = "parsePublicRawRSAKeyHex", w8 = "2a864886f70d010101",
        K = "d6", W = X509[B1S6.w0K](E);
    if (B1S6[K](W[B1S6.F2K], w8)) {
        var t = KEYUTIL[G](W[B1S6.k2K]), y = new RSAKey();
        y[B1S6.S2K](t[G8], t[Y]);
        return y;
    } else {
        if (B1S6[S](W[B1S6.F2K], o)) {
            var f = KJUR[g][T][w][W[B1S6.N2K]], y = new KJUR[g][u]({curve: f, info: W[B1S6.k2K]});
            y[m](W[B1S6.k2K]);
            return y;
        } else {
            if (B1S6[n](W[B1S6.F2K], Z)) {
                var c = ASN1HEX[F](W[B1S6.N2K], B1S6.q7K, [B1S6.q7K], B1S6.D2K),
                    P = ASN1HEX[F](W[B1S6.N2K], B1S6.q7K, [B1S6.r7K], B1S6.D2K),
                    n1 = ASN1HEX[F](W[B1S6.N2K], B1S6.q7K, [B1S6.A7K], B1S6.D2K),
                    k = ASN1HEX[B1S6.K7K](W[B1S6.k2K], B1S6.q7K);
                k = k[B1S6.E0K](B1S6.A7K);
                var y = new KJUR[g][b]();
                y[B1S6.S2K](new BigInteger(c, z), new BigInteger(P, z), new BigInteger(n1, z), new BigInteger(k, z));
                return y;
            } else {
                throw s;
            }
        }
    }
};
X509[B1S6.w0K] = function (E) {
    var s = "t3", z = "W3", b = "L3", F = "O3", Z = "S3", n = "w3", m = "m3", u = "n3", w = {};
    w[B1S6.N2K] = null;
    var T = X509[B1S6.b0K](E), g = ASN1HEX[B1S6.L7K](T, 0);
    if (B1S6[u](g.length, 3)) {
        throw "malformed X.509 certificate PEM (code:001)";
    }
    if (B1S6[m](T[B1S6.E0K](g[0], 2), "30")) {
        throw "malformed X.509 certificate PEM (code:002)";
    }
    var o = ASN1HEX[B1S6.L7K](T, g[0]);
    if (B1S6[n](o.length, 7)) {
        throw "malformed X.509 certificate PEM (code:003)";
    }
    var S = ASN1HEX[B1S6.L7K](T, o[6]);
    if (B1S6[Z](S.length, 2)) {
        throw "malformed X.509 certificate PEM (code:004)";
    }
    var Y = ASN1HEX[B1S6.L7K](T, S[0]);
    if (B1S6[F](Y.length, 2)) {
        throw "malformed X.509 certificate PEM (code:005)";
    }
    w[B1S6.F2K] = ASN1HEX[B1S6.K7K](T, Y[0]);
    if (B1S6[b](T[B1S6.E0K](Y[1], 2), "06")) {
        w[B1S6.N2K] = ASN1HEX[B1S6.K7K](T, Y[1]);
    } else {
        if (B1S6[z](T[B1S6.E0K](Y[1], 2), "30")) {
            w[B1S6.N2K] = ASN1HEX[B1S6.m0K](T, Y[1]);
        }
    }
    if (B1S6[s](T[B1S6.E0K](S[1], 2), "03")) {
        throw "malformed X.509 certificate PEM (code:006)";
    }
    var G8 = ASN1HEX[B1S6.K7K](T, S[1]);
    w[B1S6.k2K] = G8[B1S6.E0K](2);
    return w;
};
X509[B1S6.U7K] = function (E) {
    var s = "k3", z = {}, b = ASN1HEX[B1S6.L7K](E, 0), F = ASN1HEX[B1S6.L7K](E, b[0]), Z = ASN1HEX[B1S6.L7K](E, F[7]),
        n = ASN1HEX[B1S6.L7K](E, Z[0]), m = ASN1HEX[B1S6.L7K](E, n[1]), u = ASN1HEX[B1S6.K7K](E, m[0]),
        w = ASN1HEX[B1S6.K7K](E, m[1]);
    for (ikeyu = 0, inicio = 0, fin = 2; B1S6[s](inicio, w.length); inicio = inicio + 2, fin = fin + 2, ikeyu++) {
        z[ikeyu] = w[B1S6.B2K](inicio, fin);
    }
    var T = ASN1HEX[B1S6.y0K](E, 0, [0, 7]);
    X509[B1S6.j7K](T);
    return z;
};
X509[B1S6.f0K] = function (E) {
    var s = "P3", z = B1S6.t7K, b = ASN1HEX[B1S6.L7K](E, B1S6.q7K), F = ASN1HEX[B1S6.L7K](E, b[B1S6.q7K]),
        Z = ASN1HEX[B1S6.L7K](E, F[B1S6.h7K]), n = ASN1HEX[B1S6.L7K](E, Z[B1S6.q7K]),
        m = ASN1HEX[B1S6.L7K](E, n[B1S6.A7K]);
    if (B1S6[s](m, B1S6.Y7K)) {
        var u = ASN1HEX[B1S6.K7K](E, m[B1S6.q7K]), w = ASN1HEX[B1S6.K7K](E, m[B1S6.r7K]);
        z = B1S6.J2K;
    }
    return z;
};
X509[B1S6.r0K] = function (E) {
    var s = "SELLO", z = "FIEL", b = "INVALIDO", F = "\\d{6}999999\\d{8}", Z = "C0", n = "D8", m = "DESCONOCIDO", u = m,
        w, T = [B1S6.n0K, B1S6.D2K, B1S6.n0K, n], g = [B1S6.n0K, B1S6.D2K, B1S6.x0K, Z], o = X509[B1S6.P7K](E),
        S = new RegExp(F), Y = o[B1S6.C2K](S);
    if (o[B1S6.C2K](S)) return b;
    w = X509[B1S6.U7K](E);
    var G8 = X509[B1S6.p0K](w, T), G = X509[B1S6.p0K](w, g);
    if (G8 && !G) {
        var w8 = X509[B1S6.f0K](E);
        if (w8) {
            u = z;
        }
    } else if (!G8 && G) u = s;
    return u;
};
X509[B1S6.p0K] = function (E, s) {
    var z = "h3", b = "toUpperCase", F = "A3", Z = "a3", n = false, m = 0;
    for (itipo = 0; B1S6[Z](itipo, s.length); itipo++) {
        if (B1S6[F](E[itipo][b](), s[itipo])) break; else m++;
    }
    if (B1S6[z](m, s.length)) n = true;
    return n;
};
X509[B1S6.X0K] = function (E) {
    var s = "trim", z = "v3", b = "l3", F = "split", Z = X509[B1S6.j7K](ASN1HEX[B1S6.d7K](E, 0, [0, 5]))[F]("/"),
        n = new RegExp("^[A-Z..\&Ñ]{3}[0-9]{6}[A-Z..0-9]{2}[A..0-9]{1}$|^[A-Z..\&Ñ]{4}[0-9]{6}[A-Z..0-9]{2}[A..0-9]{1}$"),
        m, u;
    for (m = 0; B1S6[b](m, Z.length); m++) {
        var w = Z[m][F]("=");
        if (B1S6[z](w.length, 1)) {
            var T = w[1][s](), g = T[B1S6.C2K](n);
            if (T[B1S6.C2K](n)) {
                u = T;
                return u;
            }
        }
    }
};
X509[B1S6.P7K] = function (E) {
    var s = "R5", z = "", b, F = ASN1HEX[B1S6.y0K](E, 0, [0, 1]);
    for (inicio = 0, fin = 2; B1S6[s](inicio, F.length); inicio = inicio + 2, fin = fin + 2) {
        b = F[B1S6.B2K](inicio, fin);
        z = z + b[B1S6.g7K](1, 2);
    }
    return z;
};
