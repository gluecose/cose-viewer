import * as CBOR from "cbor-redux";
import * as Base64 from "js-base64";

const COSE_Sign1_TAG = 18;

function typedArrayToBuffer(array) {
    return array.buffer.slice(array.byteOffset, array.byteLength + array.byteOffset)
}

function decodeCOSESign1(buf) {
    let msg;
    try {
        msg = CBOR.decode(buf, null, { dictionary: "map" });
    } catch (e) {
        console.log(e);
        throw new Error("Not a COSE_Sign1 message: CBOR decode error");
    }
    let tag = null;
    if (msg.tag) {
        if (msg.tag != COSE_Sign1_TAG) {
            throw new Error("Not a COSE_Sign1 message: invalid tag");
        }
        tag = msg.tag;
        msg = msg.value;
    }
    if (!Array.isArray(msg) || msg.length != 4) {
        throw new Error("Not a COSE_Sign1 message: not an array of length 4");
    }
    const phdr = msg[0];
    const uhdr = msg[1];
    const payload = msg[2];
    const signature = msg[3];

    if (!ArrayBuffer.isView(phdr)) {
        throw new Error("Not a COSE_Sign1 message: protected header not wrapped in bstr");
    }
    const phdrBuf = typedArrayToBuffer(phdr);
    const phdrMap = CBOR.decode(phdrBuf, null, { dictionary: "map" });
    if (!(phdrMap instanceof Map)) {
        throw new Error("Not a COSE_Sign1 message: protected header not a map");
    }
    if (!(uhdr instanceof Map)) {
        throw new Error("Not a COSE_Sign1 message: unprotected header not a map");
    }
    if (!ArrayBuffer.isView(payload)) {
        throw new Error("Not a COSE_Sign1 message: payload not a bstr");
    }
    if (!ArrayBuffer.isView(signature)) {
        throw new Error("Not a COSE_Sign1 message: signature not a bstr");
    }
    return {
        size: buf.byteLength,
        tag: tag,
        phdr: phdrMap,
        uhdr: uhdr,
        payload: payload,
        signature: signature
    }
}

const CoseAlgs = new Map([
    [-7,  "ES256"],
    [-35, "ES384"],
    [-36, "ES512"],
    [-37, "PS256"],
    [-38, "PS384"],
    [-39, "PS512"],
    [-16, "SHA-256"],
    [-43, "SHA-384"],
    [-44, "SHA-512"],
]);

function toHexString(byteArray) {
    return Array.prototype.map.call(byteArray, function(byte) {
        return ('0' + (byte & 0xFF).toString(16)).slice(-2);
    }).join('');
}

function toBase64(byteArray) {
    return Base64.fromUint8Array(byteArray);
}

function prettyAlg(val) {
    if (CoseAlgs.has(val)) {
        return `${val} (${CoseAlgs.get(val)})`;
    } else {
        return prettyUnknown(val);
    }
}

function prettyCrit(val) {
    return "[" + val.map(prettyUnknown).join(", ") + "]";
}

function prettyContentType(val) {
    return prettyUnknown(val);
}

function prettyKid(val) {
    // TODO check if tstr within bstr
    return prettyUnknown(val);
}

function prettyBstrHex(val) {
    return `<${val.byteLength} bytes: ${toHexString(val)}>`;
}

function prettyBstrBase64(val) {
    return `<${val.byteLength} bytes: ${toBase64(val)}>`;
}

function prettyCounterSignature(val) {
    return prettyUnknown(val);
}

function prettyCoseX509(val) {
    if (Array.isArray(val)) {
        return "[" + val.map(prettyBstrBase64).join(", ") + "]";
    } else {
        return prettyBstrBase64(val);
    }
}

function prettyCoseCertHash(val) {
    const [hashAlg, hashValue ] = val;
    return `[${prettyAlg(hashAlg)}, ${prettyBstrHex(hashValue)}]`;
}

function prettyString(val) {
    return `"${val}"`;
}

function prettyUnknown(val) {
    let prettyValue
    if (Array.isArray(val)) {
        prettyValue = "[" + val.map(prettyUnknown).join(", ") + "]";
    } else if (ArrayBuffer.isView(val)) {
        prettyValue = prettyBstrHex(val);
    } else if (val instanceof Object.getPrototypeOf(Uint8Array)) {
        prettyValue = prettyBstrBase64(val);
    } else if (typeof val === "string") {
        prettyValue = `"${val}"`;
    } else if (typeof val === "number") {
        prettyValue = val.toString();
    } else if (val instanceof Map) {
        prettyValue = "[";
        for (const [key, value] of val) {
            prettyValue += `  (${prettyUnknown(key)}): ${prettyUnknown(value)},`;
        }
        prettyValue += "]";
    } else if (val.tag) {
        prettyValue = `Tag(${val.tag}) ${prettyUnknown(val.value)}`;
    } else {
        prettyValue = `<no pretty value: ${typeof val}>`;
    }
    return prettyValue
}

const HeaderMapping = new Map([
    [1, ["alg", prettyAlg ]],
    [2, ["crit", prettyCrit ]],
    [3, ["content type", prettyContentType ]],
    [4, ["kid", prettyKid ]],
    [5, ["IV", prettyBstrHex ]],
    [6, ["Partial IV", prettyBstrHex ]],
    [7, ["counter signature", prettyCounterSignature ]],
    [9, ["CounterSignature0", prettyBstrHex ]],
    [10, ["kid context", prettyBstrHex ]],
    [15, ["CWT claims", prettyUnknown ]],
    [32, ["x5bag", prettyCoseX509 ]],
    [33, ["x5chain", prettyCoseX509 ]],
    [34, ["x5t", prettyCoseCertHash ]],
    [35, ["x5u", prettyString ]],
]);

function displayCOSESign1(cose) {
    function prettyHeader(header) {
        let str = "";
        for (const [key, value] of header) {
            if (HeaderMapping.has(key)) {
                const [name, prettyFn] = HeaderMapping.get(key);
                str += `${key} (${name}): ${prettyFn(value)}\n`;
            } else {
                str += `${prettyUnknown(key)}: ${prettyUnknown(value)}\n`;
            }
        }
        return str;
    }
    const prettyPhdr = prettyHeader(cose.phdr);
    const prettyUhdr = prettyHeader(cose.uhdr);
    
    let prettyPayload = prettyBstrHex(cose.payload);

    // Attempt to decode payload as text
    try {
        const str = new TextDecoder("utf-8", {fatal: true}).decode(cose.payload);
        prettyPayload += '\n\nText:\n' + str;
    } catch (e) {
    }

    const prettySignature = prettyBstrHex(cose.signature);

    const out =
        `Type: COSE_Sign1 (tagged: ${!!cose.tag})\n` +
        `Size: ${cose.size} bytes\n\n` +
        `Protected Header\n================\n\n${prettyPhdr}\n\n` +
        `Unprotected Header\n==================\n\n${prettyUhdr}\n\n` + 
        `Payload\n=======\n\n${prettyPayload}\n\n` + 
        `Signature\n=========\n\n${prettySignature}`;
    
    document.getElementById("output").innerHTML = out;
}

function loadFromBuffer(buf) {
    try {
        const cose = decodeCOSESign1(buf);
        console.log(cose);
        displayCOSESign1(cose);
    } catch (e) {
        console.log(e);
        document.getElementById("output").innerHTML = e.toString();
    }
}

async function onLoadFileButtonClicked() {
    const file = document.getElementById("file").files[0];
    const buf = await file.arrayBuffer();
    loadFromBuffer(buf);
}

function hexToArrayBuffer(hex) {
    const arr = new Uint8Array(hex.match(/[\da-f]{2}/gi).map(h => parseInt(h, 16)));
    return typedArrayToBuffer(arr);
}

async function onLoadHexButtonClicked() {
    const hex = window.prompt("Paste hexdump here");
    const buf = hexToArrayBuffer(hex);
    loadFromBuffer(buf);
}

window.addEventListener("DOMContentLoaded", () => {
    document.getElementById("load-file").addEventListener("click", onLoadFileButtonClicked);
    document.getElementById("load-hex").addEventListener("click", onLoadHexButtonClicked);
});
