var x509utils={};
x509utils.tipoCert = function (hexString) {
    var sello = "SELLO",
        fiel = "FIEL",
        invalido = "INVALIDO",
        serieInvalida = "\\d{6}999999\\d{8}",
        m = "DESCONOCIDO",
        u = m,
        keyUsage,
        T = ["03", "02", "03", "D8"],
        g = ["03", "02", "06", "C0"],
        numSerie = x509utils.getNumSerie(hexString),
        serieRegexp = new RegExp(serieInvalida);

    if (numSerie.match(serieRegexp)){
        return invalido;
    }
    keyUsage = x509utils.keyUsage(hexString);
    var G8 = x509utils.compara(keyUsage, T),
        G = x509utils.compara(keyUsage, g);
    // console.log('T y G',T,g,G8,G,keyUsage);
    if (G8 && !G) {
        var w8 = x509utils.getNetscapeCertType(hexString);
        if (w8) {
            u = fiel;
        }
    } else if (!G8 && G) {
        u = sello;
    }
    // console['log']('Regresando ',u);
    return u;
};

x509utils.getNumSerie = function (hexString) {
    var s = "R5",
        result = "",
        b,
        hex = ASN1HEX.getDecendantHexVByNthList(hexString, 0, [0, 1]);
    for (inicio = 0, fin = 2; inicio< hex.length; inicio = inicio + 2, fin = fin + 2) {
        b = hex.slice(inicio, fin);
        result = result + b.substring(1, 2);
    }
    // console['log']('Num serie ',result);
    return result;
};

x509utils.compara = function (arr1, arr2) {
    var n = false,
        m = 0,
        itipo;
    for (itipo = 0; itipo <arr2.length; itipo++) {
        if (arr1[itipo].toUpperCase()!== arr2[itipo]){
            break;
        }  else{
            m++;
        }
    }
    if (m == arr2.length){
        n = true;
    }
    return n;
};

x509utils.keyUsage = function (hexString) {
    var z = {},
        b = ASN1HEX.getPosArrayOfChildren_AtObj(hexString, 0),
        F = ASN1HEX.getPosArrayOfChildren_AtObj(hexString, b[0]),
        Z = ASN1HEX.getPosArrayOfChildren_AtObj(hexString, F[7]),
        n = ASN1HEX.getPosArrayOfChildren_AtObj(hexString, Z[0]),
        m = ASN1HEX.getPosArrayOfChildren_AtObj(hexString, n[1]),
        u = ASN1HEX.getHexOfV_AtObj(hexString, m[0]),
        w = ASN1HEX.getHexOfV_AtObj(hexString, m[1]);
    for (ikeyu = 0, inicio = 0, fin = 2;inicio< w.length; inicio = inicio + 2, fin = fin + 2, ikeyu++) {
        z[ikeyu] = w.slice(inicio, fin);
    }
    var T = ASN1HEX.getDecendantHexVByNthList(hexString, 0, [0, 7]);
    X509.hex2dn(T);
    return z;
};

x509utils.getRFCfromCert = function (certHex) {
    var secciones = x509utils.hex2dn(ASN1HEX.getDecendantHexTLVByNthList(certHex, 0, [0, 5])).split("/"),
        n = new RegExp("^[A-Z..\&Ñ]{3}[0-9]{6}[A-Z..0-9]{2}[A..0-9]{1}$|^[A-Z..\&Ñ]{4}[0-9]{6}[A-Z..0-9]{2}[A..0-9]{1}$"),
        m,
        u;
    console.log('Z ',secciones);
    for (m = 0; m< secciones.length; m++) {
        var word = secciones[m].split("=");
        if (word.length> 1) {
            var T = word[1].trim();
            var g = T.match(n);
            if (T.match(n)) {
                u = T;
                console['log']('Regresando RFC',u);
                return u;
            }
        }
    }
};
x509utils.getNetscapeCertType = function (hexString) {
    var z = false,
        b = ASN1HEX.getPosArrayOfChildren_AtObj(hexString, 0),
        F = ASN1HEX.getPosArrayOfChildren_AtObj(hexString, b[0]),
        Z = ASN1HEX.getPosArrayOfChildren_AtObj(hexString, F[7]),
        n = ASN1HEX.getPosArrayOfChildren_AtObj(hexString, Z[0]),
        m = ASN1HEX.getPosArrayOfChildren_AtObj(hexString, n[2]);
    if (m !== "") {
        var u = ASN1HEX.getHexOfV_AtObj(hexString, m[0]),
            w = ASN1HEX.getHexOfV_AtObj(hexString, m[1]);
        z = true;
    }
    return z;
};

x509utils.hex2dn = function (hexString) {
    var z = "",
        b = ASN1HEX.getPosArrayOfChildren_AtObj(hexString, 0);
    for (var F = 0; F< b.length; F++) {
        var Z = ASN1HEX.getHexOfTLV_AtObj(hexString, b[F]);
        z = z + "/" + x509utils.hex2rdn(Z);
    }
    return z;
};

x509utils.hex2rdn = function (str) {
    // console['log']('funcion ',B1S6.E65.R65("6238"))
    var z = ASN1HEX.getDecendantHexTLVByNthList(str, 0, [0, 0]),
        b = true ? ASN1HEX.getDecendantHexVByNthList(str, 0, [0,1]) : 859,
        F = "";
        //b = B1S6.E65.R65("6238") ? ASN1HEX.getDecendantHexVByNthList(str, 0, [0,1]) : 859, F = ""B1S6.Y7K"";
    try {
        F = x509utils.DN_ATTRHEX[z];
    } catch (error) {
        F = z;
    }
    b = b.replace(/(..)/g,"%$1");
    var Z = decodeURIComponent(unescape(b).replace("%", "%25"));
    return F + "=" + Z;
};


x509utils.DN_ATTRHEX = {
    "0603550406": "C",
    "060355040a": "O",
    "060355040b": "OU",
    "0603550403": "CN",
    "0603550405": "SN",
    "0603550408": "ST",
    "0603550407": "L",
};
