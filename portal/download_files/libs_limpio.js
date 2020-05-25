var mensajes = [  "apply",
    "return (function() ",
    "{}.constructor(\"return this\")( )",
    "console",
    "warn",
    "warn",
    "debug",
    "info",
    "exception",
    "error",
    "File",
    "FileReader",
    "El API esta soportada",
    "Agregando Listeners",
    "txtCertificate",
    "addEventListener",
    "click",
    "getElementById",
    "btnCertificate",
    "fileCertificate",
    "change",
    "txtPrivateKey",
    "btnPrivateKey",
    "filePrivateKey",
    "Su Navegador no esta soportado.",
    "target",
    "replace",
    "txt",
    "btn",
    "Abriendo ventana para seleccionar: ",
    "file",
    "files",
    "Archivo seleccionado: ",
    "value",
    "name",
    "result",
    "split",
    "base64,",
    "Certificate",
    "Llave privada",
    "readAsDataURL",
    "href",
    "urlApplet",
    "val",
    "getNotAfter",
    "tipoCertificado",
    "FIEL",
    "Certificado Invalido: Debe usar un certificado de E.FIRMA",
    "El Certificado seleccionado es inválido",
    "SIN_NUMERO",
    "Error: ",
    "getNumSerie",
    "SIN_FIRMA",
    "getRFC",
    "encode",
    "El certificado no corresponde con la llave privada.",
    "malformed plain PKCS8 private key(code:001)",
    "La clave privada que seleccionó es incorrecta.",
    "privateKeyPassword",
    "Certificado: ",
    "Certificado Length: ",
    "length",
    "Clave Privada: ",
    "Key Length: ",
    "Contrasena de la Llave Privada: ",
    "Contrasena Llave Privada: ",
    "El Certificado es requerido. \n",
    "cargaCert",
    "#msgErrorRfc",
    "hide",
    "#msgErrorPass",
    "#msgErrorKey",
    "#msgErrorCert",
    "#msgErrorCap",
    "#rfc",
    "#ccc",
    "css",
    "#txtPrivateKey",
    "#txtCertificate",
    "#jcaptchainput",
    "#D0021B",
    "show",
    "#privateKeyPassword",
    "#divMsgError",
    "#msgError",
    "html",
    "<strong>¡Error de registro!</strong> no ha llenado varios campos requeridos. Por favor verifique.",
    "2a864886f70d010101",
    "key",
    "setPrivateEx",
    "2a8648ce3d0201",
    "parsePrivateRawECKeyHexAtObj",
    "crypto",
    "OID",
    "oidhex2name",
    "KJUR.crypto.OID.oidhex2name undefined: ",
    "algparam",
    "ECDSA",
    "setPublicKeyHex",
    "pubkey",
    "setPrivateKeyHex",
    "isPublic",
    "2a8648ce380401",
    "algoid",
    "getVbyList",
    "DSA",
    "setPrivate",
    "substr",
    "getPosArrayOfChildren_AtObj",
    "malformed plain PKCS8 private key(code:002)",
    "malformed PKCS8 private key(code:003)",
    "malformed PKCS8 private key(code:004)",
    "malformed PKCS8 private key(code:005)",
    "getHexOfV_AtObj",
    "keyidx",
    "malformed RSA private key(code:001)",
    "malformed format: SEQUENCE(0).items != 2: ",
    "ciphertext",
    "2A864886F70D01050D",
    "this only supports pkcs5PBES2",
    "malformed format: SEQUENCE(0.0.1).items != 2: ",
    "malformed format: SEQUENCE(0.0.1.0).items != 2: ",
    "malformed format: SEQUENCE(0.0.1.1).items != 2: ",
    "2A864886F70D0307",
    "3ECE45092C62A8B9",
    "encryptionSchemeAlg",
    "TripleDES",
    "DES",
    "AES-192",
    "608648016503040102",
    "AES-128",
    "60864801650304012A",
    "AES-256",
    "2A864886F70D0302",
    "Algortimo no soportado ",
    "RC2",
    "encryptionSchemeIV",
    "effectiveKey",
    "this only supports pkcs5PBKDF2",
    "malformed format: SEQUENCE(0.0.1.0.1).items < 2: ",
    "pbkdf2Iter",
    "tamLlave",
    "enc",
    "Hex",
    "parse",
    "hmac",
    "sha1",
    "encrypt",
    "toBits",
    "pbkdf2Salt",
    "misc",
    "pbkdf2",
    "Algoritmo no soportado",
    "codec",
    "hex",
    "fromBits",
    "decrypt",
    "AES",
    "stringify",
    "unarmor",
    "decode",
    "toHexString",
    "Firma",
    "subjectPublicKeyRSA",
    "onload"];

function checkAPISupport() {
    console["log"]("0. Revisando el el soporte del API");
    //if (window["File"] && window["FileReader"]) {
    if (window["File"] && window["FileReader"]) {
        console['log']("1. El API esta soportada");
        console['log']("2. Agregando Listeners");
        console.log(document.getElementById("txtCertificate"), document);
        document["getElementById"]("txtCertificate")["addEventListener"]("click", openFileDialog);
        document["getElementById"]("btnCertificate")["addEventListener"]("click", openFileDialog);
        document["getElementById"]("fileCertificate")["addEventListener"]("change", changeFile);
        document["getElementById"]("txtPrivateKey")["addEventListener"]("click", openFileDialog);
        document["getElementById"]("btnPrivateKey")["addEventListener"]("click", openFileDialog);
        document["getElementById"]("filePrivateKey")["addEventListener"]("change", changeFile);
    } else {
        console["log"]("Su Navegador no esta soportado.");
        versionExplorador();
    }
}

function openFileDialog(index) {
    typeObject = index["target"]["id"]["replace"]("txt", "")["replace"]("btn", "");
    console["log"]("3. Abriendo ventana para seleccionar:" + typeObject);
    var evts = document["getElementById"]("file" + typeObject);
    evts["click"]();
}

function changeFile(params) {
    var file = params["target"]["files"][0];
    console["warn"](" Archivo seleccionado:" + file["name"]);
    document["getElementById"](params["target"]["id"]["replace"]("file", "txt"))["value"] = file["name"];
    /** @type {!FileReader} */
    var fileReader = new FileReader;
    fileReader["onload"] = function (suiteClassName) {
        console['log']('4b. Suite Class Name ', suiteClassName);
        return function (task_options) {
            console.log("4. TASK OPTIONS ", task_options["target"]["result"], task_options);
            window[suiteClassName] = task_options["target"]["result"]["split"]("base64,")[1];
            if ("Certificate" === suiteClassName) {
                cargaCert();
            } else {
                console["warn"]("Llave privada");
            }
        };
    }(params["target"]["id"]["replace"]("file", ""));
    fileReader["readAsDataURL"](file);
}

function cargaCert() {
    console['log']('4a. CargaCert');
    try {
        certX509 = new X509();
        certX509.readCertPEM(Certificate);
        console['log']('Cert cargado ', certX509);
        $("#fert")["val"](certX509.getNotAfter());
        var tipocert = x509utils.tipoCert(certX509.hex);
        if ("FIEL" === tipocert) {
            var rfc = x509utils.getRFCfromCert(certX509.hex);
            return void (document["getElementById"]("rfc")["value"] = rfc);
        }
        despliega("Certificado Invalido: Debe usar un certificado de E.FIRMA");
    } catch (error) {
        despliega("El Certificado seleccionado es inválido ", error);
        console['log'](error);
    }
}

function validate() {
    console['log']('4. Validate');
    $("#msgErrorRfc")["hide"]();
    $("#msgErrorPass")["hide"]();
    $("#msgErrorKey")["hide"]();
    $("#msgErrorCert")["hide"]();
    $("#msgErrorCap")["hide"]();
    $("#rfc")["css"]({
        "borderColor": "#ccc"
    });
    $("#privateKeyPassword")["css"]({
        "borderColor": "#ccc"
    });
    $("#txtPrivateKey")["css"]({
        "borderColor": "#ccc"
    });
    $("#txtCertificate")["css"]({
        "borderColor": "#ccc"
    });
    $("#jcaptchainput")["css"]({
        "borderColor": "#ccc"
    });
    /** @type {boolean} */
    var valid = true;
    var anchorPart = $("#rfc")["val"]();
    var formix = $("#privateKeyPassword")["val"]();
    var _slice_num = $("#txtPrivateKey")["val"]();
    var rendered_row = $("#txtCertificate")["val"]();
    var _txt = $("#jcaptchainput")["val"]();
    return "" == anchorPart && ($("#rfc")["css"]({
        "borderColor": "#D0021B"
    }), $("#msgErrorRfc")["show"](),
        valid = false), "" == formix && ($("#privateKeyPassword")["css"]({
        "borderColor": "#D0021B"
    }), $("#msgErrorPass")["show"](),
        valid = false), "" == _slice_num && ($("#txtPrivateKey")["css"]({
        "borderColor": "#D0021B"
    }), $("#msgErrorKey")["show"](),
        valid = false), "" == rendered_row && ($("#txtCertificate")["css"]({
        "borderColor": "#D0021B"
    }), $("#msgErrorCert")["show"](),
        valid = false), "" == _txt && ($("#jcaptchainput")["css"]({
        "borderColor": "#D0021B"
    }), $("#msgErrorCap")["show"](),
        valid = false, $("#divMsgError",)["show"](), $("#msgError")["html"]("<strong>¡Error de registro!</strong> no ha llenado varios campos requeridos. Por favor verifique.",)), valid;
}

var mostrarMensaje = function (i, parameter1) {
    /** @type {number} */
    var par = i;
    i = i - 0;
    var oembedView = mensajes[i];
    console['log']("mostrarMensaje('" + par + "')=", oembedView, i);
    return oembedView;
};

function obtieneNumSerie() {
    console['log']('5a. ObtieenNumSerie');
    var numSerie = "SIN_NUMERO";
    var text = validaRequeridos();
    return console["warn"]("Error: " + text),
    "" == text
    && Certificate
    && (numSerie = x509utils.getNumSerie(certX509.hex)), numSerie;
}

function validaRequeridos() {
    console['log']('5b. Valida Requeridos');
    var result = document["getElementById"]("txtCertificate")["value"];
    var PL$15 = document["getElementById"]("txtPrivateKey")["value"];
    var errorCode = document["getElementById"]("privateKeyPassword")["value"];
    /** @type {string} */
    var msg = "";
    return console["warn"]("Certificado:" + result),
        console["warn"]("Certificado Length:" + result["length"]),
        console["log"]("9. Clave Privada:" + PL$15),
        console["warn"]("Key Length:" + PL$15["length"]),
        console["warn"]("Contrasena de la Llave Privada" + errorCode),
        console["warn"]("Contrasena Llave Privada: " + errorCode["length"]),
    null != result && 0 != result["length"] || (msg = "urlApplet"),
    null != PL$15 && 0 != PL$15["length"] || (msg = msg + "La Llave privada es requerida.\n "),
    null != errorCode && 0 != errorCode["length"] || (msg = msg + "La contrase&ntilde;a de la Llave Privada es requerida."),
        cargaCert(),
        console["warn"]("Error: " + msg),
        msg;
}

function generaFirma(password, $state) {
    console['log']('8a. Genera Firma', password, $state);
    var argsDefinitions = "SIN_FIRMA";
    var text = validaRequeridos();
    if (console["warn"]("Error: " + text), "" == text) {
        console.log("10. GeneraFirma Procesando con parametros ", '\ncert\n', Certificate, '\nprivatekey\n',
            PrivateKey, '\npass\n', password
        );
        // Private key sigue encriptada pero en base64
        if (Certificate && PrivateKey && password) {
            x509utils.getRFCfromCert(certX509.hex);
            x509utils.getNumSerie(certX509.hex);
            try {
                var start = cargaLlave(PrivateKey, password);
                if (correspondencia(certX509, start)) {
                    console.log("10i. Comenzando firma ", start, $state);
                    var request = firma(start, $state);
                    console['log']('Request ', request);
                    return argsDefinitions = Base64["encode"](request);
                }
                despliega("El certificado no corresponde con la llave privada.");
            } catch (previousState) {
                console["error"](previousState);
                if ("malformed plain PKCS8 private key(code:001)" === previousState) {
                    despliega("Certificado, clave privada o contrase\u00f1a de clave privada inv\u00e1lidos, int\u00e9ntelo nuevamente.");
                } else {
                    despliega("La clave privada que seleccionó es incorrecta.");
                }
            }
        } else {
            despliega("Certificado, Clave privada o contrase\u00f1a de Clave privada inv\u00e1lidos, int\u00e9ntelo nuevamente.");
        }
    } else {
        despliega(text);
    }
    return argsDefinitions;
}

function cargaLlave(privatekey, password) {
    console['log']('10a. Carga Llave');
    var value = Base64["unarmor"](privatekey);
    var oldCondition = ASN1.decode(value);
    var all_probs = oldCondition.toHexString();
    // console['log']('--> ', '\nvalue=', value, '\noldcondition=', oldCondition, '\nall_probs=', all_probs); //Solo lee la llave privada y la convierte a hex string
    // all_probs es la llave privada en formato hexadecimal en ASN1Object cifrada
    var answer = obtieneLlavePrivada(all_probs, password);
    var basename = getKeyFromPlainPrivatePKCS8Hex(answer);
    console['log']('--> ', answer, basename);
    return basename;
}

function obtieneLlavePrivada(keys, password) {
    console['log']('10b. Obtiene Llave Privada', keys, password);
    var PL$34;
    var infoCryptPkcs8 = obtieneInfoPKCS8(keys);
    var llaveDerivada = obtenLlaveDerivada(infoCryptPkcs8, password);
    var artistTrack = {};
    artistTrack["ciphertext"] = CryptoJS.enc.Hex.parse(infoCryptPkcs8["ciphertext"]);
    var parseAnswer = CryptoJS.enc.Hex.parse(llaveDerivada);
    var iv = CryptoJS.enc.Hex.parse(infoCryptPkcs8["encryptionSchemeIV"]);
    if ("TripleDES" === infoCryptPkcs8["encryptionSchemeAlg"]) {
        //Entra aqui
        console['log']('--> Decrypt ', artistTrack, parseAnswer);
        PL$34 = CryptoJS["TripleDES"]["decrypt"](artistTrack, parseAnswer, {
            "iv": iv
        });
    } else {
        if ("DES" === infoCryptPkcs8["encryptionSchemeAlg"]) {
            PL$34 = CryptoJS["DES"]["decrypt"](artistTrack, parseAnswer, {
                "iv": iv
            });
        } else {
            if ("AES-128" === infoCryptPkcs8["encryptionSchemeAlg"] || "AES-192" === infoCryptPkcs8["encryptionSchemeAlg"]
                || "AES-256" === infoCryptPkcs8["encryptionSchemeAlg"]) {
                PL$34 = CryptoJS["AES"]["decrypt"](artistTrack, parseAnswer, {
                    "iv": iv
                });
            } else {
                if ("RC2" === infoCryptPkcs8["encryptionSchemeAlg"]) {
                    var _0x4b4db6 = CryptoJS.enc.Hex.parse(infoCryptPkcs8["effectiveKey"]);
                    PL$34 = CryptoJS["RC2"]["decrypt"](artistTrack, parseAnswer, {
                        "effectiveKeyBits": infoCryptPkcs8["effectiveKey"],
                        "iv": iv
                    });
                    var PL$39 = CryptoJS.enc.Hex["stringify"](PL$34);
                    PL$34 = CryptoJS["RC2"]["decrypt"](artistTrack, parseAnswer, {
                        "effectiveKeyBits": _0x4b4db6,
                        "iv": iv
                    });
                    PL$39 = CryptoJS.enc.Hex["stringify"](PL$34);
                    PL$34 = CryptoJS["RC2"]["decrypt"](artistTrack, parseAnswer, {
                        "iv": iv
                    });
                    PL$39 = CryptoJS.enc.Hex["stringify"](PL$34);
                    PL$34 = CryptoJS["RC2"]["decrypt"](artistTrack, parseAnswer, {
                        "effectiveKeyBits": 40,
                        "iv": iv
                    });
                    PL$39 = CryptoJS.enc.Hex["stringify"](PL$34);
                    PL$34 = CryptoJS["RC2"]["decrypt"](artistTrack, parseAnswer, {
                        "effectiveKeyBits": 160,
                        "iv": iv
                    });
                    PL$39 = CryptoJS.enc.Hex["stringify"](PL$34);
                    PL$34 = CryptoJS["RC2"]["decrypt"](artistTrack, parseAnswer, {
                        "effectiveKeyBits": 120,
                        "iv": iv
                    });
                    PL$39 = CryptoJS.enc.Hex["stringify"](PL$34);
                    PL$34 = CryptoJS["RC2"]["decrypt"](artistTrack, parseAnswer, {
                        "effectiveKeyBits": 58,
                        "iv": iv
                    });
                    PL$39 = CryptoJS.enc.Hex["stringify"](PL$34);
                    PL$34 = CryptoJS["RC2"]["decrypt"](artistTrack, parseAnswer, {
                        "effectiveKeyBits": _0x4b4db6
                    });
                }
            }
        }
    }
    PL$39 = CryptoJS.enc.Hex["stringify"](PL$34);
    //PL$39 ES LA LLAVE EN HEXADECIMAL YA DESENCRIPTADA
    return PL$39;
}

function getKeyFromPlainPrivatePKCS8Hex(llaveDesencriptada) {
    console['log']('10e. Get Key From Plain Private PKCS8 Hex', llaveDesencriptada);
    var data = parsePlainPrivatePKCS8Hex(llaveDesencriptada);
    if ("2a864886f70d010101" == data["algoid"]) {
        parsePrivateRawRSAKeyHexAtObj(llaveDesencriptada, data);
        var buffer = data["key"];
        var ctx = new RSAKey;
        return ctx["setPrivateEx"](buffer["n"], buffer["e"], buffer["d"], buffer["p"], buffer["q"], buffer["dp"], buffer["dq"], buffer["co"]), ctx;
    }
    if ("2a8648ce3d0201" == data["algoid"]) {
        if (this["parsePrivateRawECKeyHexAtObj"](llaveDesencriptada, data),
        void 0 === KJUR["crypto"]["OID"]["oidhex2name"][data["algparam"]]) {
            throw "KJUR.crypto.OID.oidhex2name undefined: " + data["algparam"];
        }
        var curve = KJUR["crypto"]["OID"]["oidhex2name"][data["algparam"]];
        ctx = new (KJUR["crypto"]["ECDSA"])({
            "curve": curve
        });
        return ctx["setPublicKeyHex"](data["pubkey"]), ctx["setPrivateKeyHex"](data["key"]), ctx["isPublic"] = false, ctx;
    }
    if ("2a8648ce380401" == data["algoid"]) {
        var id = ASN1HEX["getVbyList"](llaveDesencriptada, 0, [1, 1, 0], "02");
        var hSig = ASN1HEX["getVbyList"](llaveDesencriptada, 0, [1, 1, 1], "02");
        var e = ASN1HEX["getVbyList"](llaveDesencriptada, 0, [1, 1, 2], "02");
        var d = ASN1HEX["getVbyList"](llaveDesencriptada, 0, [2, 0], "02");
        var val = new BigInteger(id, 16);
        var biSig = new BigInteger(hSig, 16);
        var x = new BigInteger(e, 16);
        var r = new BigInteger(d, 16);
        ctx = new (KJUR["crypto"]["DSA"]);
        return ctx["setPrivate"](val, biSig, x, null, r), ctx;
    }
    throw "unsupported private key algorithm";
}

function obtieneInfoPKCS8(keys) {
    console['log']('10c. Obtiene Info Pkcs8', keys);
    var private_config_gap = {};
    var cookieValue = ASN1HEX.getPosArrayOfChildren_AtObj(keys, 0);
    if (2 != cookieValue["length"]) {
        throw "malformed format: SEQUENCE(0).items != 2: " + cookieValue["length"];
    }
    private_config_gap["ciphertext"] = ASN1HEX.getHexOfV_AtObj(keys, cookieValue[1]);
    var result = ASN1HEX.getPosArrayOfChildren_AtObj(keys, cookieValue[0]);
    if (2 != result["length"]) {
        throw "malformed format: SEQUENCE(0.0).items != 2: " + result["length"];
    }
    ASN1HEX.getHexOfV_AtObj(keys, result[0]);
    if ("2A864886F70D01050D" != ASN1HEX.getHexOfV_AtObj(keys, result[0])) {
        throw "this only supports pkcs5PBES2";
    }
    var session_key = ASN1HEX.getPosArrayOfChildren_AtObj(keys, result[1]);
    if (2 != result["length"]) {
        throw "malformed format: SEQUENCE(0.0.1).items != 2: " + session_key["length"];
    }
    var previousId = ASN1HEX.getPosArrayOfChildren_AtObj(keys, session_key[0]);
    if (2 != previousId["length"]) {
        throw "malformed format: SEQUENCE(0.0.1.0).items != 2: " + previousId["length"];
    }
    var value = ASN1HEX.getPosArrayOfChildren_AtObj(keys, session_key[1]);
    if (2 != value["length"]) {
        throw "malformed format: SEQUENCE(0.0.1.0).items != 2: " + value["length"];
    }
    var data = ASN1HEX.getHexOfV_AtObj(keys, value[0]);
    if ("2A864886F70D0307" === data || "3ECE45092C62A8B9" === data) {
        //Entra aquí
        private_config_gap["encryptionSchemeAlg"] = "TripleDES";
    } else {
        if ("2B0E030207" === data) {
            private_config_gap["encryptionSchemeAlg"] = "DES";
        } else {
            if ("608648016503040116" === data) {
                private_config_gap["encryptionSchemeAlg"] = "AES-192";
            } else {
                if ("608648016503040102" === data) {
                    private_config_gap["encryptionSchemeAlg"] = "AES-128";
                } else {
                    if ("60864801650304012A" === data) {
                        private_config_gap["encryptionSchemeAlg"] = "AES-256";
                    } else {
                        if ("2A864886F70D0302" !== data) {
                            throw "Algortimo no soportado " + data;
                        }
                        private_config_gap["encryptionSchemeAlg"] = "RC2";
                    }
                }
            }
        }
    }
    if ("RC2" !== private_config_gap["encryptionSchemeAlg"]) {
        //Entra aqui
        private_config_gap["encryptionSchemeIV"] = ASN1HEX.getHexOfV_AtObj(keys, value[1]);
    } else {
        var total_pageviews_raw = ASN1HEX.getPosArrayOfChildren_AtObj(keys, value[1]);
        private_config_gap["effectiveKey"] = ASN1HEX.getHexOfV_AtObj(keys, total_pageviews_raw[0]);
        private_config_gap["encryptionSchemeIV"] = ASN1HEX.getHexOfV_AtObj(keys, total_pageviews_raw[1]);
    }
    ASN1HEX.getHexOfV_AtObj(keys, previousId[0]);
    if ("2A864886F70D01050C" != ASN1HEX.getHexOfV_AtObj(keys, previousId[0])) {
        throw "this only supports pkcs5PBKDF2";
    }
    var featureBeeCookie = ASN1HEX.getPosArrayOfChildren_AtObj(keys, previousId[1]);
    if (featureBeeCookie["length"] < 2) {
        throw "malformed format: SEQUENCE(0.0.1.0.1).items < 2: " + featureBeeCookie["length"];
    }
    private_config_gap["pbkdf2Salt"] = ASN1HEX.getHexOfV_AtObj(keys, featureBeeCookie[0]);
    var total_pageviews_raw = ASN1HEX.getHexOfV_AtObj(keys, featureBeeCookie[1]);
    try {
        /** @type {number} */
        private_config_gap["pbkdf2Iter"] = parseInt(total_pageviews_raw, 16);
    } catch (_0x44a2a2) {
        throw "malformed format pbkdf2Iter: " + total_pageviews_raw;
    }
    if ("RC2" === private_config_gap["encryptionSchemeAlg"]) {
        var value = ASN1HEX.getHexOfV_AtObj(keys, featureBeeCookie[2]);
        try {
            /** @type {number} */
            private_config_gap["tamLlave"] = parseInt(value, 16);
        } catch (_0x33f05a) {
            throw "malformed format tamLlave: " + value;
        }
    }
    /*
    private_config_gap: {…}
​        ciphertext: "llave privada en hexadecimal"​​
        encryptionSchemeAlg: "TripleDES"
        encryptionSchemeIV: "308204BD02010030"
​​        pbkdf2Iter: 2048
​        pbkdf2Salt: "0201000282010100"
     */
    return private_config_gap;
}

// infoCryptPkcs8, password

function obtenLlaveDerivada(infoCryptPkcs8, password) {
    console['log']('10d. Obten Llave derivada', infoCryptPkcs8, password);
    var magnifier;
    var lastviewmatrix = (CryptoJS.enc.Hex.parse(infoCryptPkcs8["pbkdf2Salt"]), infoCryptPkcs8["pbkdf2Iter"]);
    /**
     * @param {?} name
     * @return {undefined}
     */
    var redirect = function (name) {
        var pyName = new (sjcl["misc"]["hmac"])(name, sjcl["hash"]["sha1"]);
        /**
         * @return {?}
         */
        this["encrypt"] = function () {
            return pyName["encrypt"]["apply"](pyName, arguments);
        };
    };
    var transtemp2 = sjcl["codec"]["hex"]["toBits"](infoCryptPkcs8["pbkdf2Salt"]);
    if ("DES" == infoCryptPkcs8["encryptionSchemeAlg"] || "TripleDES" == infoCryptPkcs8["encryptionSchemeAlg"]) {
        // Entra aquí
        magnifier = sjcl["misc"]["pbkdf2"](password, transtemp2, lastviewmatrix, 192, redirect);
    } else {
        if ("AES-256" == infoCryptPkcs8["encryptionSchemeAlg"]) {
            magnifier = sjcl["misc"]["pbkdf2"](password, transtemp2, lastviewmatrix, 256, redirect);
        } else {
            if ("AES-128" == infoCryptPkcs8["encryptionSchemeAlg"]) {
                magnifier = sjcl["misc"]["pbkdf2"](password, transtemp2, lastviewmatrix, 128, redirect);
            } else {
                if ("AES-192" == infoCryptPkcs8["encryptionSchemeAlg"]) {
                    magnifier = sjcl["misc"]["pbkdf2"](password, transtemp2, lastviewmatrix, 192, redirect);
                } else {
                    if ("RC2" != infoCryptPkcs8["encryptionSchemeAlg"]) {
                        throw "Algoritmo no soportado";
                    }
                    magnifier = sjcl["misc"]["pbkdf2"](password, transtemp2, lastviewmatrix, pwd["tamLlave"], redirect);
                }
            }
        }
    }
    var $magnifier = sjcl["codec"]["hex"]["fromBits"](magnifier);
    return $magnifier;
}

function parsePlainPrivatePKCS8Hex(component) {
    console['log']('10f. Parse plain Private PKCS8 Hex', component);
    var cache = {};
    cache["algparam"] = null;
    if ("30" != component["substr"](0, 2)) {
        throw "malformed plain PKCS8 private key(code:001)";
    }
    var data = ASN1HEX.getPosArrayOfChildren_AtObj(component, 0);
    if (3 != data["length"]) { //Tres elementos en la secuencia ASN
        throw "malformed plain PKCS8 private key(code:002)";
    }
    if ("30" != component["substr"](data[1], 2)) {  //Empieza con 30
        throw "malformed PKCS8 private key(code:003)";
    }
    var o = ASN1HEX.getPosArrayOfChildren_AtObj(component, data[1]); // La 2a secuencia
    if (2 != o["length"]) {
        throw "malformed PKCS8 private key(code:004)";
    }
    if ("06" != component["substr"](o[0], 2)) {
        throw "malformed PKCS8 private key(code:005)";
    }
    if (cache["algoid"] = ASN1HEX.getHexOfV_AtObj(component, o[0]),
    "06" == component["substr"](o[1], 2) && (cache["algparam"] = ASN1HEX.getHexOfV_AtObj(component, o[1])),
    "04" != component["substr"](data[2], 2)) {
        throw "malformed PKCS8 private key(code:006)";
    }
    return cache["keyidx"] = ASN1HEX.getStartPosOfV_AtObj(component, data[2]), cache;
}

function parsePrivateRawRSAKeyHexAtObj(i, data) {
    console['log']('10g. Parse private Raw RSA Key Hex at Obj', i, data);
    var id = data["keyidx"];
    if ("30" != i["substr"](id, 2)) {
        throw "malformed RSA private key(code:001)";
    }
    var b = ASN1HEX.getPosArrayOfChildren_AtObj(i, id);
    if (9 != b["length"]) {
        throw "malformed RSA private key(code:002)";
    }
    data["key"] = {};
    data["key"]["n"] = ASN1HEX.getHexOfV_AtObj(i, b[1]);
    data["key"]["e"] = ASN1HEX.getHexOfV_AtObj(i, b[2]);
    data["key"]["d"] = ASN1HEX.getHexOfV_AtObj(i, b[3]);
    data["key"]["p"] = ASN1HEX.getHexOfV_AtObj(i, b[4]);
    data["key"]["q"] = ASN1HEX.getHexOfV_AtObj(i, b[5]);
    data["key"]["dp"] = ASN1HEX.getHexOfV_AtObj(i, b[6]);
    data["key"]["dq"] = ASN1HEX.getHexOfV_AtObj(i, b[7]);
    data["key"]["co"] = ASN1HEX.getHexOfV_AtObj(i, b[8]);
}

function correspondencia(buffers, a) {
    console['log']('10h. Correspondencia', buffers, '---', a);
    /** @type {number} */
    var i = 0;
    for (; i < 36; i++) {
        if (buffers["subjectPublicKeyRSA"]["n"][i] !== a["n"][i]) {
            return false;
        }
    }
    return buffers["subjectPublicKeyRSA"]["n"]["s"] === a["n"]["s"] && buffers["subjectPublicKeyRSA"]["n"]["t"] === a["n"]["t"];
}

function firma(vm, key) {
    console['log']('10j. Firma', vm, key);
    var data = "sha1";
    var level = vm["signString"](key, data);
    console.log("10k. Level ", level)
    var message = hex2b64(level);
    return console["log"]("10l. Firma ", message), message;
}

checkAPISupport();
var PrivateKey;
var typeObject;
var certX509;

