/**
 * A recursive, multi-threaded open redirect URL scanner and fuzzer.
 */

"use strict";

globalThis.console ? globalThis.console.clear = () => {} : "";

let callbackURLOpenRedirectTimestamps = "http://0.0.0.0:4242";
let callbackURLRequestTimestamps = "http://0.0.0.0:4243";
let delayCloseTabs = 5000;
let delayRangeRequests = [4000, 20000];
let scanOutOfScopeOrigins = false;
let scanRecursively = true;
let scope = [
  "*://stackoverflow.com",
];
let sessionID = "f028ut3jf4";
let threads = 2;
let timeoutCallback = 32000;

const redirectURLs = [
  "https://runescape.com",
  "https://runescape.com/",
  "https://runescape.com/splash",
  "https://runescape.com/splash?nothing"
];

const alphabeticalChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
const anchor = location.anchor;
const consoleCSS = "background-color:rgb(80,255,0);text-shadow:0 1px 1px rgba(0,0,0,.3);color:black";
const regexpSelectorURLWithURIParameterHTML = /["'](?:http[s]?(?:[:]|%3a)(?:(?:[/]|%2f){2})?)?(?:(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{1,63})|[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})?(?:[^'"()=&?\[\]\{\}<>]+)?[?][^"']+[=](?:http|[/]|%2f)[^"'()\[\]\{\}]*['"]/ig;
const regexpSelectorURLWithURIParameterPlain = /(?:http[s]?(?:[:]|%3a)(?:(?:[/]|%2f){2})?)?(?:(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{1,63})|[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})?(?:[^'"()=&?\[\]\{\}<>]+)?[?][^"']+[=](?:http|[/]|%2f)[^"'()\[\]\{\}]*/ig;
const regexpSelectorEscapableURICharacters = /[A-Za-z0-9_.!~*'()-]/ig;

let allInjectedURLs = [];
let arrayPermutations = [];
let chunkedPendingURLs = [];
let discoveredURLs = [];
let parsedCallbackURLOpenRedirectTimestamps = ["","","","","",""];
let parsedCallbackURLRequestTimestamps = ["","","","","",""];
let paused = false;
let pendingURLs = [];
let scanCount = 0;
let scanning = false;
let shuttingDown = false;

/**
 * Imported JSON.prune() script.
 */
(() => {
  var DEFAULT_MAX_DEPTH = 6;
  var DEFAULT_ARRAY_MAX_LENGTH = 50;
  var seen;
  var iterator;
  var forEachEnumerableOwnProperty = function(obj, callback) {
    for (var k in obj) {
      if (Object.prototype.hasOwnProperty.call(obj, k)) callback(k);
    }
  };
  var forEachEnumerableProperty = function(obj, callback) {
    for (var k in obj) callback(k);
  };
  var forEachProperty = function(obj, callback, excluded) {
    if (obj==null) return;
    excluded = excluded || {};
    Object.getOwnPropertyNames(obj).forEach(function(k){
      if (!excluded[k]) {
        callback(k);
        excluded[k] = true;
      }
    });
    forEachProperty(Object.getPrototypeOf(obj), callback, excluded);
  };
  Date.prototype.toPrunedJSON = Date.prototype.toJSON;
  String.prototype.toPrunedJSON = String.prototype.toJSON;
  var escapable = /[\\\"\x00-\x1f\x7f-\x9f\u00ad\u0600-\u0604\u070f\u17b4\u17b5\u200c-\u200f\u2028-\u202f\u2060-\u206f\ufeff\ufff0-\uffff]/g;
  var meta = {
    '\b': '\\b',
    '\t': '\\t',
    '\n': '\\n',
    '\f': '\\f',
    '\r': '\\r',
    '"' : '\\"',
    '\\': '\\\\'
  };
  function quote(string) {
    escapable.lastIndex = 0;
    return escapable.test(string) ? '"' + string.replace(escapable, function (a) {
      var c = meta[a];
      return
        typeof c === 'string'
          ? c
          : '\\u' + ('0000' + a.charCodeAt(0).toString(16)).slice(-4);
    }) + '"' : '"' + string + '"';
  }
  function str(key, holder, depthDecr, arrayMaxLength) {
    if (key.match(/webkitStorageInfo/)) key = replace(/webkitStorageInfo/g, "navigator.webkitTemporaryStorage");
    var i, k, v, length, partial, value = holder[key];
    if (value && typeof value === 'object' && typeof value.toPrunedJSON === 'function') {
      value = value.toPrunedJSON(key);
    }
    switch (typeof value) {
      case 'string':
        return quote(value);
      case 'number':
        return isFinite(value) ? String(value) : 'null';
      case 'boolean':
      case 'null':
        return String(value);
      case 'object':
        if (!value) {
          return 'null';
        }
        if (depthDecr<=0 || seen.indexOf(value)!==-1) {
          return '"-pruned-"';
        }
        seen.push(value);
        partial = [];
        if (Object.prototype.toString.apply(value) === '[object Array]') {
          length = Math.min(value.length, arrayMaxLength);
          for (i = 0; i < length; i += 1) {
            partial[i] = str(i, value, depthDecr-1, arrayMaxLength) || 'null';
          }
          return  '[' + partial.join(',') + ']';
        }
        iterator(value, function(k) {
          try {
            v = str(k, value, depthDecr-1, arrayMaxLength);
            if (v) partial.push(quote(k) + ':' + v);
          } catch(e) {}               
        });
        return '{' + partial.join(',') + '}';
    }
  }
  JSON.prune = function (value, depthDecr, arrayMaxLength) {
    if (typeof depthDecr == "object") {
      var options = depthDecr;
      depthDecr = options.depthDecr;
      arrayMaxLength = options.arrayMaxLength;
      iterator = options.iterator || forEachEnumerableOwnProperty;
      if (options.allProperties) {
        iterator = forEachProperty;
      } else if (options.inheritedProperties) {
        iterator = forEachEnumerableProperty;
      }
    } else {
      iterator = forEachEnumerableOwnProperty;
    }
    seen = [];
    depthDecr = depthDecr || DEFAULT_MAX_DEPTH;
    arrayMaxLength = arrayMaxLength || DEFAULT_ARRAY_MAX_LENGTH;
    return str('', {'': value}, depthDecr, arrayMaxLength);
  };
  JSON.prune.log = function() {
    console.log.apply(console, Array.prototype.slice.call(arguments).map(function(v){
      return JSON.parse(JSON.prune(v))
    }));
  }
  JSON.prune.forEachProperty = forEachProperty;
})();

/**
 * Returns an integer value between a minimum and maximum range of milliseconds.
 */
const getIntFromRange = (min, max) => {
  return parseInt(min + (Math.random() * (max - min)));
}

/**
 * Appends all possible permutations of a given array to arrayPermutations.
 */
const getArrayPermutations = (prefix, arr) => {
  for (let a = 0; a < arr.length; a++) {
    arrayPermutations.push(prefix.concat(arr[a]));
    getArrayPermutations(prefix.concat(arr[a]), arr.slice(a + 1));
  }
}

/**
 *  Returns a string exactly like globalThis.encodeURIComponent does, with lowercase hex
 *  encoding.
 */
const encodeURIComponentLowerCase = str => {
  let encoded = "";
  let encodedBuffer = new Array(str.length);
  for (let a = 0; a < str.length; a++) {
    if (!str.charAt(a).match(regexpSelectorEscapableURICharacters)) {
      encodedBuffer[a] = "%" + str.charCodeAt(a).toString(16).toLowerCase();
    } else {
      encodedBuffer[a] = str.charAt(a);
    }
  } 
  return encodedBuffer.join("");
}

/**
 * Returns a lowercase hex encoded string (type 1) using a given string.
 * (example input: "https://myredirectsite.com/")
 * (example output: "https%3a%2f%2fmyredirectsite%2ecom%2f")
 */
const hexEncodeOneLowerCase = str => {
  let encoded = "";
  for (let a = 0; a < str.length; a++) {
    if (alphabeticalChars.indexOf(str.charAt(a) === -1)) {
      encoded = encoded + "%" + str.charCodeAt(a).toString(16).toLowerCase();
    } else {
      encoded = encoded + str.charAt(a);
    }
  } 
  return encoded;
}

/**
 * Returns an uppercase hex encoded string (type 1) using a given string.
 * (example input: "https://myredirectsite.com/")
 * (example output: "https%3A%2F%2Fmyredirectsite%2Ecom%2f")
 */
const hexEncodeOneUpperCase = str => {
  let encoded = "";
  for (let a = 0; a < str.length; a++) {
    if (alphabeticalChars.indexOf(str.charAt(a) === -1)) {
      encoded = encoded + "%" + str.charCodeAt(a).toString(16).toUpperCase();
    } else {
      encoded = encoded + str.charAt(a);
    }
  }
  return encoded;
}

/**
 * Returns a lowercase hex encoded string (type 2) using a given string.
 * (example input: "https://myredirectsite.com/")
 * (example output: "%68%74%74%70%73%3a%2f%2f%6d%79%72%65%64%69%72%65%63%74%73%69%74%65%2e%63%6f%6d%2f")
 */
const hexEncodeTwoLowerCase = str => {
  let encoded = "";
  for (let a = 0; a < str.length; a++) {
    encoded = encoded + "%" + str.charCodeAt(a).toString(16).toLowerCase();
  }
  return encoded;
}

/**
 * Returns an uppercase hex encoded string (type 2) using a given string.
 * (example input: "https://myredirectsite.com/")
 * (example output: "%68%74%74%70%73%3A%2F%2F%6D%79%72%65%64%69%72%65%63%74%73%69%74%65%2E%63%6F%6D%2F")
 */
const hexEncodeTwoUpperCase = str => {
  let encoded = "";
  for (let a = 0; a < str.length; a++) {
    encoded = encoded + "%" + str.charCodeAt(a).toString(16).toUpperCase();
  }
  return encoded;
}

/*
 * Returns a lowercase hex encoded string (type 3) using a given string.
 * (example input: "https://myredirectsite.com/")
 * (example output: "https\\u003a\\u002f\\u002fmyredirectsite\\u002ecom\\u002f")
 */
const hexEncodeThreeLowerCase = str => {
  let encoded = "";
  for (let a = 0; a < str.length; a++) {
    if (alphabeticalChars.indexOf(str.charAt(a)) === -1) {

    } else { 
      encoded = encoded + str.charAt(a);
    } 
  }
  return encoded;
}

/**
 * Returns an uppercase hex encoded string (type 3) using a given string.
 * (example input: "https://myredirectsite.com/")
 * (example output: "https\\u003A\\u002F\\u002Fmyredirectsite\\u002Ecom\\u002f")
 */
const hexEncodeThreeUpperCase = str => {
  let encoded = "";
  for (let a = 0; a < str.length; a++) {
    if (alphabeticalChars.indexOf(str.charAt(a)) === -1) {
      encoded = encoded + "\\u00" + str.charCodeAt(a).toString(16).toUpperCase();
    } else {
      encoded = encoded + str.charAt(a);
    }
  }
  return encoded;
}

/**
 * Returns a lowercase hex encoded string (type 4) using a given string.
 * (example input: "https://myredirectsite.com/")
 * (example output: "\\u0068\\u0074\\u0074\\u0070\\u0073\\u003a\\u002f\\u002f\\u006d\\u0079\\u0072\\u0065\\u0064\\u0069\\u0072\\u0065\\u0063\\u0074\\u0073\\u0069\\u0074\\u0065\\u002e\\u0063\\u006f\\u006d\\u002f")
 */
const hexEncodeFourLowerCase = str => {
  let encoded = "";
  for (let a = 0; a < str.length; a++) {
    encoded = encoded + "\\u00" + str.charCodeAt(a).toString(16).toLowerCase();
  }
  return encoded;
}

/**
 * Returns an uppercase hex encoded string (type 4) using a given string.
 * (example input: "https://myredirectsite.com/")
 * (example output: "\\u0068\\u0074\\u0074\\u0070\\u0073\\u003A\\u002F\\u002F\\u006D\\u0079\\u0072\\u0065\\u0064\\u0069\\u0072\\u0065\\u0063\\u0074\\u0073\\u0069\\u0074\\u0065\\u002E\\u0063\\u006F\\u006D\\u002F")
 */
const hexEncodeFourUpperCase = str => {
  let encoded = "";
  for (let a = 0; a < str.length; a++) {
    encoded = encoded + "\\u00" + str.charCodeAt(a).toString(16).toUpperCase();
  }
  return encoded;
}

/**
 * Returns a lowercase hex encoded string (type 5) using a given string.
 * (example input: "https://myredirectsite.com/")
 * (example output: "https\\x3a\\x2f\\x2fmyredirectsite\\x2ecom\\x2f")
 */
const hexEncodeFiveLowerCase = str => {
  let encoded = "";
  for (let a = 0; a < str.length; a++) {
    if (alphabeticalChars.indexOf(str.charAt(a)) === -1) {
      encoded = encoded + "\\x" + str.charCodeAt(a).toString(16).toLowerCase();
    } else {
      encoded = encoded + str.charAt(a);
    }
  } 
  return encoded;
}

/**
 * Returns an uppercase hex encoded string (type 5) using a given string.
 * (example input: "https://myredirectsite.com/")
 * (example output: "https\\x3A\\x2F\\x2Fmyredirectsite\\x2Ecom\\x2f")
 */
const hexEncodeFiveUpperCase = str => {
  let encoded = "";
  for (let a = 0; a < str.length; a++) {
    if (alphabeticalChars.indexOf(str.charAt(a)) === -1) {
      encoded = encoded + "\\x" + str.charCodeAt(a).toString(16).toUpperCase();
    } else {
      encoded = encoded + str.charAt(a);
    } 
  }
  return encoded;
}

/**
 * Returns a lowercase hex encoded string (type 6) using a given string.
 * (example input: "https://myredirectsite.com/")
 * (example output: "\\x68\\x74\\x74\\x70\\x73\\x3a\\x2f\\x2f\\x6d\\x79\\x72\\x65\\x64\\x69\\x72\\x65\\x63\\x74\\x73\\x69\\x74\\x65\\x2e\\x63\\x6f\\x6d\\x2f")
 */
const hexEncodeSixLowerCase = str => {
  let encoded = "";
  for (let a = 0; a < str.length; a++) {
    encoded = encoded + "\\x" + str.charCodeAt(a).toString(16).toLowerCase();
  }
  return encoded;
}

/**
 * Returns an uppercase hex encoded string (type 6) using a given string.
 * (example input: "https://myredirectsite.com/")
 * (example output: "\\x68\\x74\\x74\\x70\\x73\\x3A\\x2F\\x2F\\x6D\\x79\\x72\\x65\\x64\\x69\\x72\\x65\\x63\\x74\\x73\\x69\\x74\\x65\\x2E\\x63\\x6F\\x6D\\x2F")
 */
const hexEncodeSixUpperCase = str => {
  let encoded = "";
  for (let a = 0; a < str.length; a++) {
    encoded = encoded + "\\x" + str.charCodeAt(a).toString(16).toUpperCase();
  }
  return encoded;
}

/**
 * Decodes all HTML entities in a given string.
 */
const unescapeHTML = str => {
  let unescapedStr = str
    .replace(/&#32;/ig,  " ")
    .replace(/&#33;/ig,  "!")
    .replace(/&#34;/ig,  "\"")
    .replace(/&#35;/ig,  "#")
    .replace(/&#36;/ig,  "\$")
    .replace(/&#37;/ig,  "%")
    .replace(/&amp;/ig,  "&")
    .replace(/&#39;/ig,  "'")
    .replace(/&#40;/ig,  "(")
    .replace(/&#41;/ig,  ")")
    .replace(/&#42;/ig,  "*")
    .replace(/&#43;/ig,  "+")
    .replace(/&#44;/ig,  ",")
    .replace(/&#45;/ig,  "-")
    .replace(/&#46;/ig,  ".")
    .replace(/&#47;/ig,  "/")
    .replace(/&#48;/ig,  "0")
    .replace(/&#49;/ig,  "1")
    .replace(/&#50;/ig,  "2")
    .replace(/&#51;/ig,  "3")
    .replace(/&#52;/ig,  "4")
    .replace(/&#53;/ig,  "5")
    .replace(/&#54;/ig,  "6")
    .replace(/&#55;/ig,  "7")
    .replace(/&#56;/ig,  "8")
    .replace(/&#57;/ig,  "9")
    .replace(/&#58;/ig,  ":")
    .replace(/&#59;/ig,  ";")
    .replace(/&lt;/ig,   "<")
    .replace(/&#61;/ig,  "=")
    .replace(/&gt;/ig,   ">")
    .replace(/&#63;/ig,  "?")
    .replace(/&#64;/ig,  "@")
    .replace(/&#65;/ig,  "A")
    .replace(/&#66;/ig,  "B")
    .replace(/&#67;/ig,  "C")
    .replace(/&#68;/ig,  "D")
    .replace(/&#69;/ig,  "E")
    .replace(/&#70;/ig,  "F")
    .replace(/&#71;/ig,  "G")
    .replace(/&#72;/ig,  "H")
    .replace(/&#73;/ig,  "I")
    .replace(/&#74;/ig,  "J")
    .replace(/&#75;/ig,  "K")
    .replace(/&#76;/ig,  "L")
    .replace(/&#77;/ig,  "M")
    .replace(/&#78;/ig,  "N")
    .replace(/&#79;/ig,  "O")
    .replace(/&#80;/ig,  "P")
    .replace(/&#81;/ig,  "Q")
    .replace(/&#82;/ig,  "R")
    .replace(/&#83;/ig,  "S")
    .replace(/&#84;/ig,  "T")
    .replace(/&#85;/ig,  "U")
    .replace(/&#86;/ig,  "V")
    .replace(/&#87;/ig,  "W")
    .replace(/&#88;/ig,  "X")
    .replace(/&#89;/ig,  "Y")
    .replace(/&#90;/ig,  "Z")
    .replace(/&#91;/ig,  "[")
    .replace(/&#92;/ig,  "\\")
    .replace(/&#93;/ig,  "]")
    .replace(/&#94;/ig,  "^")
    .replace(/&#95;/ig,  "_")
    .replace(/&#96;/ig,  "`")
    .replace(/&#97;/ig,  "a")
    .replace(/&#98;/ig,  "b")
    .replace(/&#99;/ig,  "c")
    .replace(/&#100;/ig, "d")
    .replace(/&#101;/ig, "e")
    .replace(/&#102;/ig, "f")
    .replace(/&#103;/ig, "g")
    .replace(/&#104;/ig, "h")
    .replace(/&#105;/ig, "i")
    .replace(/&#106;/ig, "j")
    .replace(/&#107;/ig, "k")
    .replace(/&#108;/ig, "l")
    .replace(/&#109;/ig, "m")
    .replace(/&#110;/ig, "n")
    .replace(/&#111;/ig, "o")
    .replace(/&#112;/ig, "p")
    .replace(/&#113;/ig, "q")
    .replace(/&#114;/ig, "r")
    .replace(/&#115;/ig, "s")
    .replace(/&#116;/ig, "t")
    .replace(/&#117;/ig, "u")
    .replace(/&#118;/ig, "v")
    .replace(/&#119;/ig, "w")
    .replace(/&#120;/ig, "x")
    .replace(/&#121;/ig, "y")
    .replace(/&#122;/ig, "z")
    .replace(/&#123;/ig, "{")
    .replace(/&#124;/ig, "|")
    .replace(/&#125;/ig, "}")
    .replace(/&#126;/ig, "~");
  return unescapedStr;
}

/**
 * Returns an array containing the protocol, host, port, path, search and anchor of a
 * given URL if found.
 * (example input: "/path/to/file?v=4.4.2#hash")
 * (example output: [
 *   "",
 *   "",
 *   "",
 *   "/path/to/file",
 *   "?v=4.4.2",
 *   "#hash"
 * ])
 */
const parseURL = url => {
  const strippedURL = stripAllTrailingWhitespaces(url);
  const retval = ["","","","","",""];
  // protocol
  if (strippedURL.match(/^((?:[a-z0-9.+-]+:)?\/\/).*$/i)) {
    retval[0] = strippedURL.replace(/^((?:[a-z0-9.+-]+:)?\/\/).*$/i, "$1");
  }
  // host
  if (strippedURL.match(/^(?:(?:(?:[a-z0-9.+-]+:)?\/\/)((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{1,63})|[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})(?:[:][1-9][0-9]{0,4})?)(?:[/][^/].*$|[/]$|[?#].*$|$)/i)) {
    retval[1] = strippedURL.replace(/^(?:(?:(?:[a-z0-9.+-]+:)?\/\/)((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{1,63})|[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})(?:[:][1-9][0-9]{0,4})?)(?:[/][^/].*$|[/]$|[?#].*$|$)/i, "$1");
  }
  // port
  if (strippedURL.match(/^(?:(?:(?:[a-z0-9.+-]+:)?\/\/)?(?:(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{1,63})|[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}))([:][1-9][0-9]{0,4}).*/i)) {
    retval[2] = strippedURL.replace(/^(?:(?:(?:[a-z0-9.+-]+:)?\/\/)?(?:(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{1,63})|[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}))([:][1-9][0-9]{0,4}).*$/i, "$1");
  }
  // path
  if (strippedURL.match(/^(?:(?:[a-z0-9.+-]+:)?\/\/(?:(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{1,63})|[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})(?:[:][1-9][0-9]{0,4})?)?([/][^?]*)(?:[#][^/]*?)?/i)) {
    retval[3] = strippedURL.replace(/^(?:(?:[a-z0-9.+-]+:)?\/\/)?[^/?#]*([/][^?]*)(?:[#][^/]*?)?/i, "$1");
  }
  // search
  if (strippedURL.match(/^.*?([?][^#]*).*$/i)) {
    retval[4] = strippedURL.replace(/^.*?([?][^#]*).*$/i, "$1");
  }
  // anchor
  if (strippedURL.match(/^[^#]*([#][^/]*$)/i)) {
    retval[5] = strippedURL.replace(/^[^#]*([#][^/]*$)/i, "$1");
  }
  return retval;
}

/**
 * Returns an array of 140 URLs that could lead to the same address as a given URL.
 */
const getURLVariants = url => {
  const parsedURL = parseURL(url);
  const urls = new Array(140);
  urls[0] = (
    "https://" +
    parsedURL[1] +
    parsedURL[2] +
    parsedURL[3] +
    parsedURL[4] +
    parsedURL[5]);
  urls[1] = (
    "http://" +
    parsedURL[1] +
    parsedURL[2] +
    parsedURL[3] +
    parsedURL[4] +
    parsedURL[5]);
  urls[2] = (
    "//" +
    parsedURL[1] +
    parsedURL[2] +
    parsedURL[3] +
    parsedURL[4] +
    parsedURL[5]);
  urls[3] = (
    parsedURL[1] +
    parsedURL[2] +
    parsedURL[3] +
    parsedURL[4] +
    parsedURL[5]);
  urls[4] = (
    encodeURIComponent("https://") +
    encodeURIComponent(parsedURL[1]) +
    encodeURIComponent(parsedURL[2]) +
    encodeURIComponent(parsedURL[3]) +
    encodeURIComponent(parsedURL[4]) +
    encodeURIComponent(parsedURL[5]));
  urls[5] = (
    encodeURIComponent("http://") +
    encodeURIComponent(parsedURL[1]) +
    encodeURIComponent(parsedURL[2]) +
    encodeURIComponent(parsedURL[3]) +
    encodeURIComponent(parsedURL[4]) +
    encodeURIComponent(parsedURL[5]));
  urls[6] = (
    encodeURIComponent("//") +
    encodeURIComponent(parsedURL[1]) +
    encodeURIComponent(parsedURL[2]) +
    encodeURIComponent(parsedURL[3]) +
    encodeURIComponent(parsedURL[4]) +
    encodeURIComponent(parsedURL[5]));
  urls[7] = (
    encodeURIComponent(parsedURL[1]) +
    encodeURIComponent(parsedURL[2]) +
    encodeURIComponent(parsedURL[3]) +
    encodeURIComponent(parsedURL[4]) +
    encodeURIComponent(parsedURL[5]));
  urls[8] = (
    encodeURIComponent(encodeURIComponent("https://")) +
    encodeURIComponent(encodeURIComponent(parsedURL[1])) +
    encodeURIComponent(encodeURIComponent(parsedURL[2])) +
    encodeURIComponent(encodeURIComponent(parsedURL[3])) +
    encodeURIComponent(encodeURIComponent(parsedURL[4])) +
    encodeURIComponent(encodeURIComponent(parsedURL[5])));
  urls[9] = (
    encodeURIComponent(encodeURIComponent("http://")) +
    encodeURIComponent(encodeURIComponent(parsedURL[1])) +
    encodeURIComponent(encodeURIComponent(parsedURL[2])) +
    encodeURIComponent(encodeURIComponent(parsedURL[3])) +
    encodeURIComponent(encodeURIComponent(parsedURL[4])) +
    encodeURIComponent(encodeURIComponent(parsedURL[5])));
  urls[10] = (
    encodeURIComponent(encodeURIComponent("//")) +
    encodeURIComponent(encodeURIComponent(parsedURL[1])) +
    encodeURIComponent(encodeURIComponent(parsedURL[2])) +
    encodeURIComponent(encodeURIComponent(parsedURL[3])) +
    encodeURIComponent(encodeURIComponent(parsedURL[4])) +
    encodeURIComponent(encodeURIComponent(parsedURL[5])));
  urls[11] = (
    encodeURIComponent(encodeURIComponent(parsedURL[1])) +
    encodeURIComponent(encodeURIComponent(parsedURL[2])) +
    encodeURIComponent(encodeURIComponent(parsedURL[3])) +
    encodeURIComponent(encodeURIComponent(parsedURL[4])) +
    encodeURIComponent(encodeURIComponent(parsedURL[5])));
  urls[12] = (
    hexEncodeOneLowerCase("https://") +
    hexEncodeOneLowerCase(parsedURL[1]) +
    hexEncodeOneLowerCase(parsedURL[2]) +
    hexEncodeOneLowerCase(parsedURL[3]) +
    hexEncodeOneLowerCase(parsedURL[4]) +
    hexEncodeOneLowerCase(parsedURL[5]));
  urls[13] = (
    hexEncodeOneLowerCase("http://") +
    hexEncodeOneLowerCase(parsedURL[1]) +
    hexEncodeOneLowerCase(parsedURL[2]) +
    hexEncodeOneLowerCase(parsedURL[3]) +
    hexEncodeOneLowerCase(parsedURL[4]) +
    hexEncodeOneLowerCase(parsedURL[5]));
  urls[14] = (
    hexEncodeOneLowerCase("//") +
    hexEncodeOneLowerCase(parsedURL[1]) +
    hexEncodeOneLowerCase(parsedURL[2]) +
    hexEncodeOneLowerCase(parsedURL[3]) +
    hexEncodeOneLowerCase(parsedURL[4]) +
    hexEncodeOneLowerCase(parsedURL[5]));
  urls[15] = (
    hexEncodeOneLowerCase(parsedURL[1]) +
    hexEncodeOneLowerCase(parsedURL[2]) +
    hexEncodeOneLowerCase(parsedURL[3]) +
    hexEncodeOneLowerCase(parsedURL[4]) +
    hexEncodeOneLowerCase(parsedURL[5]));
  urls[16] = (
    hexEncodeOneLowerCase(encodeURIComponent("https://")) +
    hexEncodeOneLowerCase(encodeURIComponent(parsedURL[1])) +
    hexEncodeOneLowerCase(encodeURIComponent(parsedURL[2])) +
    hexEncodeOneLowerCase(encodeURIComponent(parsedURL[3])) +
    hexEncodeOneLowerCase(encodeURIComponent(parsedURL[4])) +
    hexEncodeOneLowerCase(encodeURIComponent(parsedURL[5])));
  urls[17] = (
    hexEncodeOneLowerCase(encodeURIComponent("http://")) +
    hexEncodeOneLowerCase(encodeURIComponent(parsedURL[1])) +
    hexEncodeOneLowerCase(encodeURIComponent(parsedURL[2])) +
    hexEncodeOneLowerCase(encodeURIComponent(parsedURL[3])) +
    hexEncodeOneLowerCase(encodeURIComponent(parsedURL[4])) +
    hexEncodeOneLowerCase(encodeURIComponent(parsedURL[5])));
  urls[18] = (
    hexEncodeOneLowerCase(encodeURIComponent("//")) +
    hexEncodeOneLowerCase(encodeURIComponent(parsedURL[1])) +
    hexEncodeOneLowerCase(encodeURIComponent(parsedURL[2])) +
    hexEncodeOneLowerCase(encodeURIComponent(parsedURL[3])) +
    hexEncodeOneLowerCase(encodeURIComponent(parsedURL[4])) +
    hexEncodeOneLowerCase(encodeURIComponent(parsedURL[5])));
  urls[19] = (
    hexEncodeOneLowerCase(encodeURIComponent(parsedURL[1])) +
    hexEncodeOneLowerCase(encodeURIComponent(parsedURL[2])) +
    hexEncodeOneLowerCase(encodeURIComponent(parsedURL[3])) +
    hexEncodeOneLowerCase(encodeURIComponent(parsedURL[4])) +
    hexEncodeOneLowerCase(encodeURIComponent(parsedURL[5])));
  urls[20] = (
    hexEncodeOneLowerCase(encodeURIComponent(encodeURIComponent("https://"))) +
    hexEncodeOneLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[1]))) +
    hexEncodeOneLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[2]))) +
    hexEncodeOneLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[3]))) +
    hexEncodeOneLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[4]))) +
    hexEncodeOneLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[5]))));
  urls[21] = (
    hexEncodeOneLowerCase(encodeURIComponent(encodeURIComponent("http://"))) +
    hexEncodeOneLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[1]))) +
    hexEncodeOneLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[2]))) +
    hexEncodeOneLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[3]))) +
    hexEncodeOneLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[4]))) +
    hexEncodeOneLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[5]))));
  urls[22] = (
    hexEncodeOneLowerCase(encodeURIComponent(encodeURIComponent("//"))) +
    hexEncodeOneLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[1]))) +
    hexEncodeOneLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[2]))) +
    hexEncodeOneLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[3]))) +
    hexEncodeOneLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[4]))) +
    hexEncodeOneLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[5]))));
  urls[23] = (
    hexEncodeOneLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[1]))) +
    hexEncodeOneLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[2]))) +
    hexEncodeOneLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[3]))) +
    hexEncodeOneLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[4]))) +
    hexEncodeOneLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[5]))));
  urls[24] = (
    hexEncodeTwoLowerCase("https://") +
    hexEncodeTwoLowerCase(parsedURL[1]) +
    hexEncodeTwoLowerCase(parsedURL[2]) +
    hexEncodeTwoLowerCase(parsedURL[3]) +
    hexEncodeTwoLowerCase(parsedURL[4]) +
    hexEncodeTwoLowerCase(parsedURL[5]));
  urls[25] = (
    hexEncodeTwoLowerCase("http://") +
    hexEncodeTwoLowerCase(parsedURL[1]) +
    hexEncodeTwoLowerCase(parsedURL[2]) +
    hexEncodeTwoLowerCase(parsedURL[3]) +
    hexEncodeTwoLowerCase(parsedURL[4]) +
    hexEncodeTwoLowerCase(parsedURL[5]));
  urls[26] = (
    hexEncodeTwoLowerCase("//") +
    hexEncodeTwoLowerCase(parsedURL[1]) +
    hexEncodeTwoLowerCase(parsedURL[2]) +
    hexEncodeTwoLowerCase(parsedURL[3]) +
    hexEncodeTwoLowerCase(parsedURL[4]) +
    hexEncodeTwoLowerCase(parsedURL[5]));
  urls[27] = (
    hexEncodeTwoLowerCase(parsedURL[1]) +
    hexEncodeTwoLowerCase(parsedURL[2]) +
    hexEncodeTwoLowerCase(parsedURL[3]) +
    hexEncodeTwoLowerCase(parsedURL[4]) +
    hexEncodeTwoLowerCase(parsedURL[5]));
  urls[28] = (
    hexEncodeTwoLowerCase(encodeURIComponent("https://")) +
    hexEncodeTwoLowerCase(encodeURIComponent(parsedURL[1])) +
    hexEncodeTwoLowerCase(encodeURIComponent(parsedURL[2])) +
    hexEncodeTwoLowerCase(encodeURIComponent(parsedURL[3])) +
    hexEncodeTwoLowerCase(encodeURIComponent(parsedURL[4])) +
    hexEncodeTwoLowerCase(encodeURIComponent(parsedURL[5])));
  urls[29] = (
    hexEncodeTwoLowerCase(encodeURIComponent("http://")) +
    hexEncodeTwoLowerCase(encodeURIComponent(parsedURL[1])) +
    hexEncodeTwoLowerCase(encodeURIComponent(parsedURL[2])) +
    hexEncodeTwoLowerCase(encodeURIComponent(parsedURL[3])) +
    hexEncodeTwoLowerCase(encodeURIComponent(parsedURL[4])) +
    hexEncodeTwoLowerCase(encodeURIComponent(parsedURL[5])));
  urls[30] = (
    hexEncodeTwoLowerCase(encodeURIComponent("//")) +
    hexEncodeTwoLowerCase(encodeURIComponent(parsedURL[1])) +
    hexEncodeTwoLowerCase(encodeURIComponent(parsedURL[2])) +
    hexEncodeTwoLowerCase(encodeURIComponent(parsedURL[3])) +
    hexEncodeTwoLowerCase(encodeURIComponent(parsedURL[4])) +
    hexEncodeTwoLowerCase(encodeURIComponent(parsedURL[5])));
  urls[31] = (
    hexEncodeTwoLowerCase(encodeURIComponent(parsedURL[1])) +
    hexEncodeTwoLowerCase(encodeURIComponent(parsedURL[2])) +
    hexEncodeTwoLowerCase(encodeURIComponent(parsedURL[3])) +
    hexEncodeTwoLowerCase(encodeURIComponent(parsedURL[4])) +
    hexEncodeTwoLowerCase(encodeURIComponent(parsedURL[5])));
  urls[32] = (
    hexEncodeTwoLowerCase(encodeURIComponent(encodeURIComponent("https://"))) +
    hexEncodeTwoLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[1]))) +
    hexEncodeTwoLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[2]))) +
    hexEncodeTwoLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[3]))) +
    hexEncodeTwoLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[4]))) +
    hexEncodeTwoLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[5]))));
  urls[33] = (
    hexEncodeTwoLowerCase(encodeURIComponent(encodeURIComponent("http://"))) +
    hexEncodeTwoLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[1]))) +
    hexEncodeTwoLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[2]))) +
    hexEncodeTwoLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[3]))) +
    hexEncodeTwoLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[4]))) +
    hexEncodeTwoLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[5]))));
  urls[34] = (
    hexEncodeTwoLowerCase(encodeURIComponent(encodeURIComponent("//"))) +
    hexEncodeTwoLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[1]))) +
    hexEncodeTwoLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[2]))) +
    hexEncodeTwoLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[3]))) +
    hexEncodeTwoLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[4]))) +
    hexEncodeTwoLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[5]))));
  urls[35] = (
    hexEncodeTwoLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[1]))) +
    hexEncodeTwoLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[2]))) +
    hexEncodeTwoLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[3]))) +
    hexEncodeTwoLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[4]))) +
    hexEncodeTwoLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[5]))));
  urls[36] = (
    hexEncodeThreeLowerCase("https://") +
    hexEncodeThreeLowerCase(parsedURL[1]) +
    hexEncodeThreeLowerCase(parsedURL[2]) +
    hexEncodeThreeLowerCase(parsedURL[3]) +
    hexEncodeThreeLowerCase(parsedURL[4]) +
    hexEncodeThreeLowerCase(parsedURL[5]));
  urls[37] = (
    hexEncodeThreeLowerCase("http://") +
    hexEncodeThreeLowerCase(parsedURL[1]) +
    hexEncodeThreeLowerCase(parsedURL[2]) +
    hexEncodeThreeLowerCase(parsedURL[3]) +
    hexEncodeThreeLowerCase(parsedURL[4]) +
    hexEncodeThreeLowerCase(parsedURL[5]));
  urls[38] = (
    hexEncodeThreeLowerCase("//") +
    hexEncodeThreeLowerCase(parsedURL[1]) +
    hexEncodeThreeLowerCase(parsedURL[2]) +
    hexEncodeThreeLowerCase(parsedURL[3]) +
    hexEncodeThreeLowerCase(parsedURL[4]) +
    hexEncodeThreeLowerCase(parsedURL[5]));
  urls[39] = (
    hexEncodeThreeLowerCase(parsedURL[1]) +
    hexEncodeThreeLowerCase(parsedURL[2]) +
    hexEncodeThreeLowerCase(parsedURL[3]) +
    hexEncodeThreeLowerCase(parsedURL[4]) +
    hexEncodeThreeLowerCase(parsedURL[5]));
  urls[40] = (
    hexEncodeThreeLowerCase(encodeURIComponent("https://")) +
    hexEncodeThreeLowerCase(encodeURIComponent(parsedURL[1])) +
    hexEncodeThreeLowerCase(encodeURIComponent(parsedURL[2])) +
    hexEncodeThreeLowerCase(encodeURIComponent(parsedURL[3])) +
    hexEncodeThreeLowerCase(encodeURIComponent(parsedURL[4])) +
    hexEncodeThreeLowerCase(encodeURIComponent(parsedURL[5])));
  urls[41] = (
    hexEncodeThreeLowerCase(encodeURIComponent("http://")) +
    hexEncodeThreeLowerCase(encodeURIComponent(parsedURL[1])) +
    hexEncodeThreeLowerCase(encodeURIComponent(parsedURL[2])) +
    hexEncodeThreeLowerCase(encodeURIComponent(parsedURL[3])) +
    hexEncodeThreeLowerCase(encodeURIComponent(parsedURL[4])) +
    hexEncodeThreeLowerCase(encodeURIComponent(parsedURL[5])));
  urls[42] = (
    hexEncodeThreeLowerCase(encodeURIComponent("//")) +
    hexEncodeThreeLowerCase(encodeURIComponent(parsedURL[1])) +
    hexEncodeThreeLowerCase(encodeURIComponent(parsedURL[2])) +
    hexEncodeThreeLowerCase(encodeURIComponent(parsedURL[3])) +
    hexEncodeThreeLowerCase(encodeURIComponent(parsedURL[4])) +
    hexEncodeThreeLowerCase(encodeURIComponent(parsedURL[5])));
  urls[43] = (
    hexEncodeThreeLowerCase(encodeURIComponent(parsedURL[1])) +
    hexEncodeThreeLowerCase(encodeURIComponent(parsedURL[2])) +
    hexEncodeThreeLowerCase(encodeURIComponent(parsedURL[3])) +
    hexEncodeThreeLowerCase(encodeURIComponent(parsedURL[4])) +
    hexEncodeThreeLowerCase(encodeURIComponent(parsedURL[5])));
  urls[44] = (
    hexEncodeThreeLowerCase(encodeURIComponent(encodeURIComponent("https://"))) +
    hexEncodeThreeLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[1]))) +
    hexEncodeThreeLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[2]))) +
    hexEncodeThreeLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[3]))) +
    hexEncodeThreeLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[4]))) +
    hexEncodeThreeLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[5]))));
  urls[45] = (
    hexEncodeThreeLowerCase(encodeURIComponent(encodeURIComponent("http://"))) +
    hexEncodeThreeLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[1]))) +
    hexEncodeThreeLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[2]))) +
    hexEncodeThreeLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[3]))) +
    hexEncodeThreeLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[4]))) +
    hexEncodeThreeLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[5]))));
  urls[46] = (
    hexEncodeThreeLowerCase(encodeURIComponent(encodeURIComponent("//"))) +
    hexEncodeThreeLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[1]))) +
    hexEncodeThreeLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[2]))) +
    hexEncodeThreeLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[3]))) +
    hexEncodeThreeLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[4]))) +
    hexEncodeThreeLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[5]))));
  urls[47] = (
    hexEncodeThreeLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[1]))) +
    hexEncodeThreeLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[2]))) +
    hexEncodeThreeLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[3]))) +
    hexEncodeThreeLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[4]))) +
    hexEncodeThreeLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[5]))));
  urls[48] = (
    hexEncodeFourLowerCase("https://") +
    hexEncodeFourLowerCase(parsedURL[1]) +
    hexEncodeFourLowerCase(parsedURL[2]) +
    hexEncodeFourLowerCase(parsedURL[3]) +
    hexEncodeFourLowerCase(parsedURL[4]) +
    hexEncodeFourLowerCase(parsedURL[5]));
  urls[49] = (
    hexEncodeFourLowerCase("http://") +
    hexEncodeFourLowerCase(parsedURL[1]) +
    hexEncodeFourLowerCase(parsedURL[2]) +
    hexEncodeFourLowerCase(parsedURL[3]) +
    hexEncodeFourLowerCase(parsedURL[4]) +
    hexEncodeFourLowerCase(parsedURL[5]));
  urls[50] = (
    hexEncodeFourLowerCase("//") +
    hexEncodeFourLowerCase(parsedURL[1]) +
    hexEncodeFourLowerCase(parsedURL[2]) +
    hexEncodeFourLowerCase(parsedURL[3]) +
    hexEncodeFourLowerCase(parsedURL[4]) +
    hexEncodeFourLowerCase(parsedURL[5]));
  urls[51] = (
    hexEncodeFourLowerCase(parsedURL[1]) +
    hexEncodeFourLowerCase(parsedURL[2]) +
    hexEncodeFourLowerCase(parsedURL[3]) +
    hexEncodeFourLowerCase(parsedURL[4]) +
    hexEncodeFourLowerCase(parsedURL[5]));
  urls[52] = (
    hexEncodeFourLowerCase(encodeURIComponent("https://")) +
    hexEncodeFourLowerCase(encodeURIComponent(parsedURL[1])) +
    hexEncodeFourLowerCase(encodeURIComponent(parsedURL[2])) +
    hexEncodeFourLowerCase(encodeURIComponent(parsedURL[3])) +
    hexEncodeFourLowerCase(encodeURIComponent(parsedURL[4])) +
    hexEncodeFourLowerCase(encodeURIComponent(parsedURL[5])));
  urls[53] = (
    hexEncodeFourLowerCase(encodeURIComponent("http://")) +
    hexEncodeFourLowerCase(encodeURIComponent(parsedURL[1])) +
    hexEncodeFourLowerCase(encodeURIComponent(parsedURL[2])) +
    hexEncodeFourLowerCase(encodeURIComponent(parsedURL[3])) +
    hexEncodeFourLowerCase(encodeURIComponent(parsedURL[4])) +
    hexEncodeFourLowerCase(encodeURIComponent(parsedURL[5])));
  urls[54] = (
    hexEncodeFourLowerCase(encodeURIComponent("//")) +
    hexEncodeFourLowerCase(encodeURIComponent(parsedURL[1])) +
    hexEncodeFourLowerCase(encodeURIComponent(parsedURL[2])) +
    hexEncodeFourLowerCase(encodeURIComponent(parsedURL[3])) +
    hexEncodeFourLowerCase(encodeURIComponent(parsedURL[4])) +
    hexEncodeFourLowerCase(encodeURIComponent(parsedURL[5])));
  urls[55] = (
    hexEncodeFourLowerCase(encodeURIComponent(parsedURL[1])) +
    hexEncodeFourLowerCase(encodeURIComponent(parsedURL[2])) +
    hexEncodeFourLowerCase(encodeURIComponent(parsedURL[3])) +
    hexEncodeFourLowerCase(encodeURIComponent(parsedURL[4])) +
    hexEncodeFourLowerCase(encodeURIComponent(parsedURL[5])));
  urls[56] = (
    hexEncodeFourLowerCase(encodeURIComponent(encodeURIComponent("https://"))) +
    hexEncodeFourLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[1]))) +
    hexEncodeFourLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[2]))) +
    hexEncodeFourLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[3]))) +
    hexEncodeFourLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[4]))) +
    hexEncodeFourLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[5]))));
  urls[57] = (
    hexEncodeFourLowerCase(encodeURIComponent(encodeURIComponent("http://"))) +
    hexEncodeFourLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[1]))) +
    hexEncodeFourLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[2]))) +
    hexEncodeFourLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[3]))) +
    hexEncodeFourLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[4]))) +
    hexEncodeFourLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[5]))));
  urls[58] = (
    hexEncodeFourLowerCase(encodeURIComponent(encodeURIComponent("//"))) +
    hexEncodeFourLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[1]))) +
    hexEncodeFourLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[2]))) +
    hexEncodeFourLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[3]))) +
    hexEncodeFourLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[4]))) +
    hexEncodeFourLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[5]))));
  urls[59] = (
    hexEncodeFourLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[1]))) +
    hexEncodeFourLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[2]))) +
    hexEncodeFourLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[3]))) +
    hexEncodeFourLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[4]))) +
    hexEncodeFourLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[5]))));
  urls[60] = (
    hexEncodeFiveLowerCase("https://") +
    hexEncodeFiveLowerCase(parsedURL[1]) +
    hexEncodeFiveLowerCase(parsedURL[2]) +
    hexEncodeFiveLowerCase(parsedURL[3]) +
    hexEncodeFiveLowerCase(parsedURL[4]) +
    hexEncodeFiveLowerCase(parsedURL[5]));
  urls[61] = (
    hexEncodeFiveLowerCase("http://") +
    hexEncodeFiveLowerCase(parsedURL[1]) +
    hexEncodeFiveLowerCase(parsedURL[2]) +
    hexEncodeFiveLowerCase(parsedURL[3]) +
    hexEncodeFiveLowerCase(parsedURL[4]) +
    hexEncodeFiveLowerCase(parsedURL[5]));
  urls[62] = (
    hexEncodeFiveLowerCase("//") +
    hexEncodeFiveLowerCase(parsedURL[1]) +
    hexEncodeFiveLowerCase(parsedURL[2]) +
    hexEncodeFiveLowerCase(parsedURL[3]) +
    hexEncodeFiveLowerCase(parsedURL[4]) +
    hexEncodeFiveLowerCase(parsedURL[5]));
  urls[63] = (
    hexEncodeFiveLowerCase(parsedURL[1]) +
    hexEncodeFiveLowerCase(parsedURL[2]) +
    hexEncodeFiveLowerCase(parsedURL[3]) +
    hexEncodeFiveLowerCase(parsedURL[4]) +
    hexEncodeFiveLowerCase(parsedURL[5]));
  urls[64] = (
    hexEncodeFiveLowerCase(encodeURIComponent("https://")) +
    hexEncodeFiveLowerCase(encodeURIComponent(parsedURL[1])) +
    hexEncodeFiveLowerCase(encodeURIComponent(parsedURL[2])) +
    hexEncodeFiveLowerCase(encodeURIComponent(parsedURL[3])) +
    hexEncodeFiveLowerCase(encodeURIComponent(parsedURL[4])) +
    hexEncodeFiveLowerCase(encodeURIComponent(parsedURL[5])));
  urls[65] = (
    hexEncodeFiveLowerCase(encodeURIComponent("http://")) +
    hexEncodeFiveLowerCase(encodeURIComponent(parsedURL[1])) +
    hexEncodeFiveLowerCase(encodeURIComponent(parsedURL[2])) +
    hexEncodeFiveLowerCase(encodeURIComponent(parsedURL[3])) +
    hexEncodeFiveLowerCase(encodeURIComponent(parsedURL[4])) +
    hexEncodeFiveLowerCase(encodeURIComponent(parsedURL[5])));
  urls[66] = (
    hexEncodeFiveLowerCase(encodeURIComponent("//")) +
    hexEncodeFiveLowerCase(encodeURIComponent(parsedURL[1])) +
    hexEncodeFiveLowerCase(encodeURIComponent(parsedURL[2])) +
    hexEncodeFiveLowerCase(encodeURIComponent(parsedURL[3])) +
    hexEncodeFiveLowerCase(encodeURIComponent(parsedURL[4])) +
    hexEncodeFiveLowerCase(encodeURIComponent(parsedURL[5])));
  urls[67] = (
    hexEncodeFiveLowerCase(encodeURIComponent(parsedURL[1])) +
    hexEncodeFiveLowerCase(encodeURIComponent(parsedURL[2])) +
    hexEncodeFiveLowerCase(encodeURIComponent(parsedURL[3])) +
    hexEncodeFiveLowerCase(encodeURIComponent(parsedURL[4])) +
    hexEncodeFiveLowerCase(encodeURIComponent(parsedURL[5])));
  urls[68] = (
    hexEncodeFiveLowerCase(encodeURIComponent(encodeURIComponent("https://"))) +
    hexEncodeFiveLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[1]))) +
    hexEncodeFiveLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[2]))) +
    hexEncodeFiveLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[3]))) +
    hexEncodeFiveLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[4]))) +
    hexEncodeFiveLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[5]))));
  urls[69] = (
    hexEncodeFiveLowerCase(encodeURIComponent(encodeURIComponent("http://"))) +
    hexEncodeFiveLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[1]))) +
    hexEncodeFiveLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[2]))) +
    hexEncodeFiveLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[3]))) +
    hexEncodeFiveLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[4]))) +
    hexEncodeFiveLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[5]))));
  urls[70] = (
    hexEncodeFiveLowerCase(encodeURIComponent(encodeURIComponent("//"))) +
    hexEncodeFiveLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[1]))) +
    hexEncodeFiveLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[2]))) +
    hexEncodeFiveLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[3]))) +
    hexEncodeFiveLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[4]))) +
    hexEncodeFiveLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[5]))));
  urls[71] = (
    hexEncodeFiveLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[1]))) +
    hexEncodeFiveLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[2]))) +
    hexEncodeFiveLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[3]))) +
    hexEncodeFiveLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[4]))) +
    hexEncodeFiveLowerCase(encodeURIComponent(encodeURIComponent(parsedURL[5]))));
  urls[72] = (
    hexEncodeOneUpperCase("https://") +
    hexEncodeOneUpperCase(parsedURL[1]) +
    hexEncodeOneUpperCase(parsedURL[2]) +
    hexEncodeOneUpperCase(parsedURL[3]) +
    hexEncodeOneUpperCase(parsedURL[4]) +
    hexEncodeOneUpperCase(parsedURL[5]));
  urls[73] = (
    hexEncodeOneUpperCase("http://") +
    hexEncodeOneUpperCase(parsedURL[1]) +
    hexEncodeOneUpperCase(parsedURL[2]) +
    hexEncodeOneUpperCase(parsedURL[3]) +
    hexEncodeOneUpperCase(parsedURL[4]) +
    hexEncodeOneUpperCase(parsedURL[5]));
  urls[74] = (
    hexEncodeOneUpperCase("//") +
    hexEncodeOneUpperCase(parsedURL[1]) +
    hexEncodeOneUpperCase(parsedURL[2]) +
    hexEncodeOneUpperCase(parsedURL[3]) +
    hexEncodeOneUpperCase(parsedURL[4]) +
    hexEncodeOneUpperCase(parsedURL[5]));
  urls[75] = (
    hexEncodeOneUpperCase(parsedURL[1]) +
    hexEncodeOneUpperCase(parsedURL[2]) +
    hexEncodeOneUpperCase(parsedURL[3]) +
    hexEncodeOneUpperCase(parsedURL[4]) +
    hexEncodeOneUpperCase(parsedURL[5]));
  urls[76] = (
    hexEncodeOneUpperCase(encodeURIComponent("https://")) +
    hexEncodeOneUpperCase(encodeURIComponent(parsedURL[1])) +
    hexEncodeOneUpperCase(encodeURIComponent(parsedURL[2])) +
    hexEncodeOneUpperCase(encodeURIComponent(parsedURL[3])) +
    hexEncodeOneUpperCase(encodeURIComponent(parsedURL[4])) +
    hexEncodeOneUpperCase(encodeURIComponent(parsedURL[5])));
  urls[77] = (
    hexEncodeOneUpperCase(encodeURIComponent("http://")) +
    hexEncodeOneUpperCase(encodeURIComponent(parsedURL[1])) +
    hexEncodeOneUpperCase(encodeURIComponent(parsedURL[2])) +
    hexEncodeOneUpperCase(encodeURIComponent(parsedURL[3])) +
    hexEncodeOneUpperCase(encodeURIComponent(parsedURL[4])) +
    hexEncodeOneUpperCase(encodeURIComponent(parsedURL[5])));
  urls[78] = (
    hexEncodeOneUpperCase(encodeURIComponent("//")) +
    hexEncodeOneUpperCase(encodeURIComponent(parsedURL[1])) +
    hexEncodeOneUpperCase(encodeURIComponent(parsedURL[2])) +
    hexEncodeOneUpperCase(encodeURIComponent(parsedURL[3])) +
    hexEncodeOneUpperCase(encodeURIComponent(parsedURL[4])) +
    hexEncodeOneUpperCase(encodeURIComponent(parsedURL[5])));
  urls[79] = (
    hexEncodeOneUpperCase(encodeURIComponent(parsedURL[1])) +
    hexEncodeOneUpperCase(encodeURIComponent(parsedURL[2])) +
    hexEncodeOneUpperCase(encodeURIComponent(parsedURL[3])) +
    hexEncodeOneUpperCase(encodeURIComponent(parsedURL[4])) +
    hexEncodeOneUpperCase(encodeURIComponent(parsedURL[5])));
  urls[80] = (
    hexEncodeOneUpperCase(encodeURIComponent(encodeURIComponent("https://"))) +
    hexEncodeOneUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[1]))) +
    hexEncodeOneUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[2]))) +
    hexEncodeOneUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[3]))) +
    hexEncodeOneUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[4]))) +
    hexEncodeOneUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[5]))));
  urls[81] = (
    hexEncodeOneUpperCase(encodeURIComponent(encodeURIComponent("http://"))) +
    hexEncodeOneUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[1]))) +
    hexEncodeOneUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[2]))) +
    hexEncodeOneUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[3]))) +
    hexEncodeOneUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[4]))) +
    hexEncodeOneUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[5]))));
  urls[82] = (
    hexEncodeOneUpperCase(encodeURIComponent(encodeURIComponent("//"))) +
    hexEncodeOneUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[1]))) +
    hexEncodeOneUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[2]))) +
    hexEncodeOneUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[3]))) +
    hexEncodeOneUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[4]))) +
    hexEncodeOneUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[5]))));
  urls[83] = (
    hexEncodeOneUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[1]))) +
    hexEncodeOneUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[2]))) +
    hexEncodeOneUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[3]))) +
    hexEncodeOneUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[4]))) +
    hexEncodeOneUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[5]))));
  urls[84] = (
    hexEncodeTwoUpperCase("https://") +
    hexEncodeTwoUpperCase(parsedURL[1]) +
    hexEncodeTwoUpperCase(parsedURL[2]) +
    hexEncodeTwoUpperCase(parsedURL[3]) +
    hexEncodeTwoUpperCase(parsedURL[4]) +
    hexEncodeTwoUpperCase(parsedURL[5]));
  urls[85] = (
    hexEncodeTwoUpperCase("http://") +
    hexEncodeTwoUpperCase(parsedURL[1]) +
    hexEncodeTwoUpperCase(parsedURL[2]) +
    hexEncodeTwoUpperCase(parsedURL[3]) +
    hexEncodeTwoUpperCase(parsedURL[4]) +
    hexEncodeTwoUpperCase(parsedURL[5]));
  urls[86] = (
    hexEncodeTwoUpperCase("//") +
    hexEncodeTwoUpperCase(parsedURL[1]) +
    hexEncodeTwoUpperCase(parsedURL[2]) +
    hexEncodeTwoUpperCase(parsedURL[3]) +
    hexEncodeTwoUpperCase(parsedURL[4]) +
    hexEncodeTwoUpperCase(parsedURL[5]));
  urls[87] = (
    hexEncodeTwoUpperCase(parsedURL[1]) +
    hexEncodeTwoUpperCase(parsedURL[2]) +
    hexEncodeTwoUpperCase(parsedURL[3]) +
    hexEncodeTwoUpperCase(parsedURL[4]) +
    hexEncodeTwoUpperCase(parsedURL[5]));
  urls[88] = (
    hexEncodeTwoUpperCase(encodeURIComponent("https://")) +
    hexEncodeTwoUpperCase(encodeURIComponent(parsedURL[1])) +
    hexEncodeTwoUpperCase(encodeURIComponent(parsedURL[2])) +
    hexEncodeTwoUpperCase(encodeURIComponent(parsedURL[3])) +
    hexEncodeTwoUpperCase(encodeURIComponent(parsedURL[4])) +
    hexEncodeTwoUpperCase(encodeURIComponent(parsedURL[5])));
  urls[89] = (
    hexEncodeTwoUpperCase(encodeURIComponent("http://")) +
    hexEncodeTwoUpperCase(encodeURIComponent(parsedURL[1])) +
    hexEncodeTwoUpperCase(encodeURIComponent(parsedURL[2])) +
    hexEncodeTwoUpperCase(encodeURIComponent(parsedURL[3])) +
    hexEncodeTwoUpperCase(encodeURIComponent(parsedURL[4])) +
    hexEncodeTwoUpperCase(encodeURIComponent(parsedURL[5])));
  urls[90] = (
    hexEncodeTwoUpperCase(encodeURIComponent("//")) +
    hexEncodeTwoUpperCase(encodeURIComponent(parsedURL[1])) +
    hexEncodeTwoUpperCase(encodeURIComponent(parsedURL[2])) +
    hexEncodeTwoUpperCase(encodeURIComponent(parsedURL[3])) +
    hexEncodeTwoUpperCase(encodeURIComponent(parsedURL[4])) +
    hexEncodeTwoUpperCase(encodeURIComponent(parsedURL[5])));
  urls[91] = (
    hexEncodeTwoUpperCase(encodeURIComponent(parsedURL[1])) +
    hexEncodeTwoUpperCase(encodeURIComponent(parsedURL[2])) +
    hexEncodeTwoUpperCase(encodeURIComponent(parsedURL[3])) +
    hexEncodeTwoUpperCase(encodeURIComponent(parsedURL[4])) +
    hexEncodeTwoUpperCase(encodeURIComponent(parsedURL[5])));
  urls[92] = (
    hexEncodeTwoUpperCase(encodeURIComponent(encodeURIComponent("https://"))) +
    hexEncodeTwoUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[1]))) +
    hexEncodeTwoUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[2]))) +
    hexEncodeTwoUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[3]))) +
    hexEncodeTwoUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[4]))) +
    hexEncodeTwoUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[5]))));
  urls[93] = (
    hexEncodeTwoUpperCase(encodeURIComponent(encodeURIComponent("http://"))) +
    hexEncodeTwoUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[1]))) +
    hexEncodeTwoUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[2]))) +
    hexEncodeTwoUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[3]))) +
    hexEncodeTwoUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[4]))) +
    hexEncodeTwoUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[5]))));
  urls[94] = (
    hexEncodeTwoUpperCase(encodeURIComponent(encodeURIComponent("//"))) +
    hexEncodeTwoUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[1]))) +
    hexEncodeTwoUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[2]))) +
    hexEncodeTwoUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[3]))) +
    hexEncodeTwoUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[4]))) +
    hexEncodeTwoUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[5]))));
  urls[95] = (
    hexEncodeTwoUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[1]))) +
    hexEncodeTwoUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[2]))) +
    hexEncodeTwoUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[3]))) +
    hexEncodeTwoUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[4]))) +
    hexEncodeTwoUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[5]))));
  urls[96] = (
    hexEncodeThreeUpperCase("https://") +
    hexEncodeThreeUpperCase(parsedURL[1]) +
    hexEncodeThreeUpperCase(parsedURL[2]) +
    hexEncodeThreeUpperCase(parsedURL[3]) +
    hexEncodeThreeUpperCase(parsedURL[4]) +
    hexEncodeThreeUpperCase(parsedURL[5]));
  urls[97] = (
    hexEncodeThreeUpperCase("http://") +
    hexEncodeThreeUpperCase(parsedURL[1]) +
    hexEncodeThreeUpperCase(parsedURL[2]) +
    hexEncodeThreeUpperCase(parsedURL[3]) +
    hexEncodeThreeUpperCase(parsedURL[4]) +
    hexEncodeThreeUpperCase(parsedURL[5]));
  urls[98] = (
    hexEncodeThreeUpperCase("//") +
    hexEncodeThreeUpperCase(parsedURL[1]) +
    hexEncodeThreeUpperCase(parsedURL[2]) +
    hexEncodeThreeUpperCase(parsedURL[3]) +
    hexEncodeThreeUpperCase(parsedURL[4]) +
    hexEncodeThreeUpperCase(parsedURL[5]));
  urls[99] = (
    hexEncodeThreeUpperCase(parsedURL[1]) +
    hexEncodeThreeUpperCase(parsedURL[2]) +
    hexEncodeThreeUpperCase(parsedURL[3]) +
    hexEncodeThreeUpperCase(parsedURL[4]) +
    hexEncodeThreeUpperCase(parsedURL[5]));
  urls[100] = (
    hexEncodeThreeUpperCase(encodeURIComponent("https://")) +
    hexEncodeThreeUpperCase(encodeURIComponent(parsedURL[1])) +
    hexEncodeThreeUpperCase(encodeURIComponent(parsedURL[2])) +
    hexEncodeThreeUpperCase(encodeURIComponent(parsedURL[3])) +
    hexEncodeThreeUpperCase(encodeURIComponent(parsedURL[4])) +
    hexEncodeThreeUpperCase(encodeURIComponent(parsedURL[5])));
  urls[101] = (
    hexEncodeThreeUpperCase(encodeURIComponent("http://")) +
    hexEncodeThreeUpperCase(encodeURIComponent(parsedURL[1])) +
    hexEncodeThreeUpperCase(encodeURIComponent(parsedURL[2])) +
    hexEncodeThreeUpperCase(encodeURIComponent(parsedURL[3])) +
    hexEncodeThreeUpperCase(encodeURIComponent(parsedURL[4])) +
    hexEncodeThreeUpperCase(encodeURIComponent(parsedURL[5])));
  urls[102] = (
    hexEncodeThreeUpperCase(encodeURIComponent("//")) +
    hexEncodeThreeUpperCase(encodeURIComponent(parsedURL[1])) +
    hexEncodeThreeUpperCase(encodeURIComponent(parsedURL[2])) +
    hexEncodeThreeUpperCase(encodeURIComponent(parsedURL[3])) +
    hexEncodeThreeUpperCase(encodeURIComponent(parsedURL[4])) +
    hexEncodeThreeUpperCase(encodeURIComponent(parsedURL[5])));
  urls[103] = (
    hexEncodeThreeUpperCase(encodeURIComponent(parsedURL[1])) +
    hexEncodeThreeUpperCase(encodeURIComponent(parsedURL[2])) +
    hexEncodeThreeUpperCase(encodeURIComponent(parsedURL[3])) +
    hexEncodeThreeUpperCase(encodeURIComponent(parsedURL[4])) +
    hexEncodeThreeUpperCase(encodeURIComponent(parsedURL[5])));
  urls[104] = (
    hexEncodeThreeUpperCase(encodeURIComponent(encodeURIComponent("https://"))) +
    hexEncodeThreeUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[1]))) +
    hexEncodeThreeUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[2]))) +
    hexEncodeThreeUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[3]))) +
    hexEncodeThreeUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[4]))) +
    hexEncodeThreeUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[5]))));
  urls[105] = (
    hexEncodeThreeUpperCase(encodeURIComponent(encodeURIComponent("http://"))) +
    hexEncodeThreeUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[1]))) +
    hexEncodeThreeUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[2]))) +
    hexEncodeThreeUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[3]))) +
    hexEncodeThreeUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[4]))) +
    hexEncodeThreeUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[5]))));
  urls[106] = (
    hexEncodeThreeUpperCase(encodeURIComponent(encodeURIComponent("//"))) +
    hexEncodeThreeUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[1]))) +
    hexEncodeThreeUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[2]))) +
    hexEncodeThreeUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[3]))) +
    hexEncodeThreeUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[4]))) +
    hexEncodeThreeUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[5]))));
  urls[107] = (
    hexEncodeThreeUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[1]))) +
    hexEncodeThreeUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[2]))) +
    hexEncodeThreeUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[3]))) +
    hexEncodeThreeUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[4]))) +
    hexEncodeThreeUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[5]))));
  urls[108] = (
    hexEncodeFourUpperCase("https://") +
    hexEncodeFourUpperCase(parsedURL[1]) +
    hexEncodeFourUpperCase(parsedURL[2]) +
    hexEncodeFourUpperCase(parsedURL[3]) +
    hexEncodeFourUpperCase(parsedURL[4]) +
    hexEncodeFourUpperCase(parsedURL[5]));
  urls[109] = (
    hexEncodeFourUpperCase("http://") +
    hexEncodeFourUpperCase(parsedURL[1]) +
    hexEncodeFourUpperCase(parsedURL[2]) +
    hexEncodeFourUpperCase(parsedURL[3]) +
    hexEncodeFourUpperCase(parsedURL[4]) +
    hexEncodeFourUpperCase(parsedURL[5]));
  urls[110] = (
    hexEncodeFourUpperCase("//") +
    hexEncodeFourUpperCase(parsedURL[1]) +
    hexEncodeFourUpperCase(parsedURL[2]) +
    hexEncodeFourUpperCase(parsedURL[3]) +
    hexEncodeFourUpperCase(parsedURL[4]) +
    hexEncodeFourUpperCase(parsedURL[5]));
  urls[111] = (
    hexEncodeFourUpperCase(parsedURL[1]) +
    hexEncodeFourUpperCase(parsedURL[2]) +
    hexEncodeFourUpperCase(parsedURL[3]) +
    hexEncodeFourUpperCase(parsedURL[4]) +
    hexEncodeFourUpperCase(parsedURL[5]));
  urls[112] = (
    hexEncodeFourUpperCase(encodeURIComponent("https://")) +
    hexEncodeFourUpperCase(encodeURIComponent(parsedURL[1])) +
    hexEncodeFourUpperCase(encodeURIComponent(parsedURL[2])) +
    hexEncodeFourUpperCase(encodeURIComponent(parsedURL[3])) +
    hexEncodeFourUpperCase(encodeURIComponent(parsedURL[4])) +
    hexEncodeFourUpperCase(encodeURIComponent(parsedURL[5])));
  urls[113] = (
    hexEncodeFourUpperCase(encodeURIComponent("http://")) +
    hexEncodeFourUpperCase(encodeURIComponent(parsedURL[1])) +
    hexEncodeFourUpperCase(encodeURIComponent(parsedURL[2])) +
    hexEncodeFourUpperCase(encodeURIComponent(parsedURL[3])) +
    hexEncodeFourUpperCase(encodeURIComponent(parsedURL[4])) +
    hexEncodeFourUpperCase(encodeURIComponent(parsedURL[5])));
  urls[114] = (
    hexEncodeFourUpperCase(encodeURIComponent("//")) +
    hexEncodeFourUpperCase(encodeURIComponent(parsedURL[1])) +
    hexEncodeFourUpperCase(encodeURIComponent(parsedURL[2])) +
    hexEncodeFourUpperCase(encodeURIComponent(parsedURL[3])) +
    hexEncodeFourUpperCase(encodeURIComponent(parsedURL[4])) +
    hexEncodeFourUpperCase(encodeURIComponent(parsedURL[5])));
  urls[115] = (
    hexEncodeFourUpperCase(encodeURIComponent(parsedURL[1])) +
    hexEncodeFourUpperCase(encodeURIComponent(parsedURL[2])) +
    hexEncodeFourUpperCase(encodeURIComponent(parsedURL[3])) +
    hexEncodeFourUpperCase(encodeURIComponent(parsedURL[4])) +
    hexEncodeFourUpperCase(encodeURIComponent(parsedURL[5])));
  urls[116] = (
    hexEncodeFourUpperCase(encodeURIComponent(encodeURIComponent("https://"))) +
    hexEncodeFourUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[1]))) +
    hexEncodeFourUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[2]))) +
    hexEncodeFourUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[3]))) +
    hexEncodeFourUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[4]))) +
    hexEncodeFourUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[5]))));
  urls[117] = (
    hexEncodeFourUpperCase(encodeURIComponent(encodeURIComponent("http://"))) +
    hexEncodeFourUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[1]))) +
    hexEncodeFourUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[2]))) +
    hexEncodeFourUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[3]))) +
    hexEncodeFourUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[4]))) +
    hexEncodeFourUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[5]))));
  urls[118] = (
    hexEncodeFourUpperCase(encodeURIComponent(encodeURIComponent("//"))) +
    hexEncodeFourUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[1]))) +
    hexEncodeFourUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[2]))) +
    hexEncodeFourUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[3]))) +
    hexEncodeFourUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[4]))) +
    hexEncodeFourUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[5]))));
  urls[119] = (
    hexEncodeFourUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[1]))) +
    hexEncodeFourUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[2]))) +
    hexEncodeFourUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[3]))) +
    hexEncodeFourUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[4]))) +
    hexEncodeFourUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[5]))));
  urls[120] = (
    hexEncodeFiveUpperCase("https://") +
    hexEncodeFiveUpperCase(parsedURL[1]) +
    hexEncodeFiveUpperCase(parsedURL[2]) +
    hexEncodeFiveUpperCase(parsedURL[3]) +
    hexEncodeFiveUpperCase(parsedURL[4]) +
    hexEncodeFiveUpperCase(parsedURL[5]));
  urls[121] = (
    hexEncodeFiveUpperCase("http://") +
    hexEncodeFiveUpperCase(parsedURL[1]) +
    hexEncodeFiveUpperCase(parsedURL[2]) +
    hexEncodeFiveUpperCase(parsedURL[3]) +
    hexEncodeFiveUpperCase(parsedURL[4]) +
    hexEncodeFiveUpperCase(parsedURL[5]));
  urls[122] = (
    hexEncodeFiveUpperCase("//") +
    hexEncodeFiveUpperCase(parsedURL[1]) +
    hexEncodeFiveUpperCase(parsedURL[2]) +
    hexEncodeFiveUpperCase(parsedURL[3]) +
    hexEncodeFiveUpperCase(parsedURL[4]) +
    hexEncodeFiveUpperCase(parsedURL[5]));
  urls[123] = (
    hexEncodeFiveUpperCase(parsedURL[1]) +
    hexEncodeFiveUpperCase(parsedURL[2]) +
    hexEncodeFiveUpperCase(parsedURL[3]) +
    hexEncodeFiveUpperCase(parsedURL[4]) +
    hexEncodeFiveUpperCase(parsedURL[5]));
  urls[124] = (
    hexEncodeFiveUpperCase(encodeURIComponent("https://")) +
    hexEncodeFiveUpperCase(encodeURIComponent(parsedURL[1])) +
    hexEncodeFiveUpperCase(encodeURIComponent(parsedURL[2])) +
    hexEncodeFiveUpperCase(encodeURIComponent(parsedURL[3])) +
    hexEncodeFiveUpperCase(encodeURIComponent(parsedURL[4])) +
    hexEncodeFiveUpperCase(encodeURIComponent(parsedURL[5])));
  urls[125] = (
    hexEncodeFiveUpperCase(encodeURIComponent("http://")) +
    hexEncodeFiveUpperCase(encodeURIComponent(parsedURL[1])) +
    hexEncodeFiveUpperCase(encodeURIComponent(parsedURL[2])) +
    hexEncodeFiveUpperCase(encodeURIComponent(parsedURL[3])) +
    hexEncodeFiveUpperCase(encodeURIComponent(parsedURL[4])) +
    hexEncodeFiveUpperCase(encodeURIComponent(parsedURL[5])));
  urls[126] = (
    hexEncodeFiveUpperCase(encodeURIComponent("//")) +
    hexEncodeFiveUpperCase(encodeURIComponent(parsedURL[1])) +
    hexEncodeFiveUpperCase(encodeURIComponent(parsedURL[2])) +
    hexEncodeFiveUpperCase(encodeURIComponent(parsedURL[3])) +
    hexEncodeFiveUpperCase(encodeURIComponent(parsedURL[4])) +
    hexEncodeFiveUpperCase(encodeURIComponent(parsedURL[5])));
  urls[127] = (
    hexEncodeFiveUpperCase(encodeURIComponent(parsedURL[1])) +
    hexEncodeFiveUpperCase(encodeURIComponent(parsedURL[2])) +
    hexEncodeFiveUpperCase(encodeURIComponent(parsedURL[3])) +
    hexEncodeFiveUpperCase(encodeURIComponent(parsedURL[4])) +
    hexEncodeFiveUpperCase(encodeURIComponent(parsedURL[5])));
  urls[128] = (
    hexEncodeFiveUpperCase(encodeURIComponent(encodeURIComponent("https://"))) +
    hexEncodeFiveUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[1]))) +
    hexEncodeFiveUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[2]))) +
    hexEncodeFiveUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[3]))) +
    hexEncodeFiveUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[4]))) +
    hexEncodeFiveUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[5]))));
  urls[129] = (
    hexEncodeFiveUpperCase(encodeURIComponent(encodeURIComponent("http://"))) +
    hexEncodeFiveUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[1]))) +
    hexEncodeFiveUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[2]))) +
    hexEncodeFiveUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[3]))) +
    hexEncodeFiveUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[4]))) +
    hexEncodeFiveUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[5]))));
  urls[130] = (
    hexEncodeFiveUpperCase(encodeURIComponent(encodeURIComponent("//"))) +
    hexEncodeFiveUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[1]))) +
    hexEncodeFiveUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[2]))) +
    hexEncodeFiveUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[3]))) +
    hexEncodeFiveUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[4]))) +
    hexEncodeFiveUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[5]))));
  urls[131] = (
    hexEncodeFiveUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[1]))) +
    hexEncodeFiveUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[2]))) +
    hexEncodeFiveUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[3]))) +
    hexEncodeFiveUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[4]))) +
    hexEncodeFiveUpperCase(encodeURIComponent(encodeURIComponent(parsedURL[5]))));
  urls[132] = (
    encodeURIComponentLowerCase("https://") +
    encodeURIComponentLowerCase(parsedURL[1]) +
    encodeURIComponentLowerCase(parsedURL[2]) +
    encodeURIComponentLowerCase(parsedURL[3]) +
    encodeURIComponentLowerCase(parsedURL[4]) +
    encodeURIComponentLowerCase(parsedURL[5]));
  urls[133] = (
    encodeURIComponentLowerCase("http://") +
    encodeURIComponentLowerCase(parsedURL[1]) +
    encodeURIComponentLowerCase(parsedURL[2]) +
    encodeURIComponentLowerCase(parsedURL[3]) +
    encodeURIComponentLowerCase(parsedURL[4]) +
    encodeURIComponentLowerCase(parsedURL[5]));
  urls[134] = (
    encodeURIComponentLowerCase("//") +
    encodeURIComponentLowerCase(parsedURL[1]) +
    encodeURIComponentLowerCase(parsedURL[2]) +
    encodeURIComponentLowerCase(parsedURL[3]) +
    encodeURIComponentLowerCase(parsedURL[4]) +
    encodeURIComponentLowerCase(parsedURL[5]));
  urls[135] = (
    encodeURIComponentLowerCase(parsedURL[1]) +
    encodeURIComponentLowerCase(parsedURL[2]) +
    encodeURIComponentLowerCase(parsedURL[3]) +
    encodeURIComponentLowerCase(parsedURL[4]) +
    encodeURIComponentLowerCase(parsedURL[5]));
  urls[136] = (
    encodeURIComponentLowerCase(encodeURIComponentLowerCase("https://")) +
    encodeURIComponentLowerCase(encodeURIComponentLowerCase(parsedURL[1])) +
    encodeURIComponentLowerCase(encodeURIComponentLowerCase(parsedURL[2])) +
    encodeURIComponentLowerCase(encodeURIComponentLowerCase(parsedURL[3])) +
    encodeURIComponentLowerCase(encodeURIComponentLowerCase(parsedURL[4])) +
    encodeURIComponentLowerCase(encodeURIComponentLowerCase(parsedURL[5])));
  urls[137] = (
    encodeURIComponentLowerCase(encodeURIComponentLowerCase("http://")) +
    encodeURIComponentLowerCase(encodeURIComponentLowerCase(parsedURL[1])) +
    encodeURIComponentLowerCase(encodeURIComponentLowerCase(parsedURL[2])) +
    encodeURIComponentLowerCase(encodeURIComponentLowerCase(parsedURL[3])) +
    encodeURIComponentLowerCase(encodeURIComponentLowerCase(parsedURL[4])) +
    encodeURIComponentLowerCase(encodeURIComponentLowerCase(parsedURL[5])));
  urls[138] = (
    encodeURIComponentLowerCase(encodeURIComponentLowerCase("//")) +
    encodeURIComponentLowerCase(encodeURIComponentLowerCase(parsedURL[1])) +
    encodeURIComponentLowerCase(encodeURIComponentLowerCase(parsedURL[2])) +
    encodeURIComponentLowerCase(encodeURIComponentLowerCase(parsedURL[3])) +
    encodeURIComponentLowerCase(encodeURIComponentLowerCase(parsedURL[4])) +
    encodeURIComponentLowerCase(encodeURIComponentLowerCase(parsedURL[5])));
  urls[139] = (
    encodeURIComponentLowerCase(encodeURIComponentLowerCase(parsedURL[1])) +
    encodeURIComponentLowerCase(encodeURIComponentLowerCase(parsedURL[2])) +
    encodeURIComponentLowerCase(encodeURIComponentLowerCase(parsedURL[3])) +
    encodeURIComponentLowerCase(encodeURIComponentLowerCase(parsedURL[4])) +
    encodeURIComponentLowerCase(encodeURIComponentLowerCase(parsedURL[5])));
  return urls;
}

/**
 * Returns an array of all injected permutations of a given URL.
 * (example input: (
 *   "//www.google.com/q=http%3A%2F%2Fgmail%2Ecom%2F",
 *   %2F%2Fmysite%2Ecom%2F",
 * ))
 * (example output: "//www.google.com/q=%2F%2Fmysite%2Ecom%2F")
 */
const getInjectedURLPermutations = (targetURL, redirectURL) => {
  const regexp = new RegExp("=(?:http[^&]*|[/][^&]*|%2f[^&]*)", "ig");
  let regexpMatches = [];
  let match;
  while (match = regexp.exec(targetURL)) {
    regexpMatches.push({match: match[0], index: match.index});
  }
  arrayPermutations = [];
  getArrayPermutations([], regexpMatches);
  let injectedURLs = [];
  for (let a = 0; a < arrayPermutations.length; a++) {
    let matchSets = arrayPermutations[a];
    let injectedURL = targetURL;
    for (let b = 0; b < matchSets.length; b++) {
      const matchSet = matchSets[b];
      const lengthLeadingMatches = matchSets.slice(0, b)
        .map(set => { return set.match }).join("").length;
      const url_ = injectedURL.slice(
        0,
        matchSet.index
          + (b * (redirectURL.length + 1))
          - lengthLeadingMatches);
      const _url = injectedURL.slice(
        matchSet.index
          + ((b * (redirectURL.length + 1)) - lengthLeadingMatches)
          + (matchSet.match.length));
      injectedURL = url_ + "=" + redirectURL + _url;
    }
    injectedURLs.push(injectedURL);
  }
  return injectedURLs;
}

/**
 * Returns true if a given origin matches an origin specifier that's in the specified scope.
 * (example input: "http://www.in.scope.domain.com")
 * (example output given "*://*.in.scope.*" is in the scope: true)
 */
const isInScopeOrigin = origin => {
  for (let a = 0; a < scope.length; a++) {
    const regexpInScopeOrigin = new RegExp(
      "^" +
      scope[a]
        .replace(/([^*a-z0-9\]])/ig, "[$1]")
        .replace(/^([a-z0-9.+-]*)[*]([a-z0-9.+-]*):/ig, "$1[a-z0-9.+-]+$2:")
        .replace(/[*]/ig, "(?:(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?.)+)"),
      "ig");
    if (origin.match(regexpInScopeOrigin)) {
      return true;
    }
  }
  return false;
}

/**
 * Returns an array of all string values that were found in a given object.
 */
const getAllStringValues = obj => {
  let strings = [];
  const keys = Object.keys(obj);
  keys.forEach(key=>{
    if (typeof(obj[key]) == "object" && obj[key]) {
      strings = [].concat(strings, getAllStringValues(obj[key]));
    } else if (typeof(globalThis[key]) == "string") {
      strings = [].concat(strings, [obj[key]]);
    }
  });
  return strings;
}

/**
 * Chunks the given array of redirect URLs to a length equal to the specified amount of
 * threads.
 */
const chunkURLArray = urls => {
  const chunkSize = Math.ceil(urls.length / threads);
  const chunks = [];
  for (let a = 0; a < threads; a++) {
    chunks[a] = urls.slice(chunkSize * a, (chunkSize * a) + chunkSize);
  }
  return chunks;
}

/**
 * Returns the full URL based on a given URI that was found in the current document.
 */
const toFullURL = uri => {
  const parsedURL = parseURL(uri);
  if (
       parsedURL[0] === "" /* protocol */
    && parsedURL[1] === "" /* host */
    && parsedURL[3] === "" /* path */
    && parsedURL[4] === "" /* search */
    && parsedURL[5] !== "" /* anchor */
  ) {
    return location.origin +
      location.pathname +
      (location.search ? location.search : "") +
      uri;
  }
  if (
       parsedURL[0] === "" /* protocol */
    && parsedURL[1] === "" /* host */
    && parsedURL[3] === "" /* path */
    && parsedURL[4] !== "" /* search */
  ) {
    return location.origin + location.pathname + uri;
  }
  if (
       parsedURL[0] === "" /* protocol */
    && parsedURL[1] === "" /* host */
    && parsedURL[3] !== "" /* path */
  ) {
    return location.origin + uri;
  }
  return uri;
}

/**
 * Attempts to load a given URL in a new window.
 */
const loadURL = async url => {
  const date = new Date();
  const timestamp = date.toLocaleDateString() + " " + date.toLocaleTimeString();
  console.log("%cfuzzer-open-redirect", consoleCSS,
    timestamp, "Fetching", url);
  let callbackURL = parsedCallbackURLRequestTimestamps.slice(0,4).join("");
  if (parsedCallbackURLRequestTimestamps[4] !== "") {
    callbackURL = callbackURL + parsedCallbackURLRequestTimestamps[4] +
      "&fuzzer-open-redirect-request-callback=" +
      encodeURIComponent(timestamp + " - " + url);
  } else {
    callbackURL = callbackURL + "?fuzzer-open-redirect-request-callback=" +
      encodeURIComponent(timestamp + " - " + url);
  }
  callbackURL = callbackURL + parsedCallbackURLRequestTimestamps.slice(5);
  while (paused) {
    await sleep(4000);
  }
  globalThis.open(callbackURL, "_blank")
  globalThis.open(url, "_blank");
}

/**
 * Sleeps an awaited promise value for the given amount of milliseconds.
 */
const sleep = ms => {
  return new Promise(res=>{
    setTimeout(res, ms);
  });
}

/**
 * Strips trailing single/double quote.
 */
const stripTrailingQuotes = str => {
  return str.replace(/^["'](.*)["']$/g, "$1");
}

/**
 * Strips all trailing whitespace.
 */
const stripAllTrailingWhitespaces = str => {
  return str.replace(/^\s*(.*)\s*$/g, "$1");
}

/**
 * Opens all pending and unique URLs.
 */
const openPendingURLs = () => {
  return new Promise(async(res) => {
    while (scanCount != 0) {
      await sleep(4000);
    }
    pendingURLs = pendingURLs.filter((url, index, arr) => {
      return arr.indexOf(url) == index;
    });
    chunkedPendingURLs = chunkURLArray(pendingURLs);
    console.log("%copen-redirect-fuzzer", consoleCSS,
      "Chunked URL queue:", chunkedPendingURLs);
    for (let a = 0; a < threads; a++) {
      (async () => {
        for (let c = 0; c < chunkedPendingURLs[a].length; c++) {
          if (shuttingDown) return;
          while (paused) {
            await sleep(4000);
          }
          const thisURLCandidate = chunkedPendingURLs[a][c];
          loadURL(thisURLCandidate);
          chunkedPendingURLs[a] = chunkedPendingURLs[a].filter(pendingURL => {
            return pendingURL != thisURLCandidate;
          });
          pendingURLs = pendingURLs.filter(pendingURL => {
            return pendingURL != thisURLCandidate;
          });
          await sleep(getIntFromRange(
            delayRangeRequests[0],
            delayRangeRequests[1]));
        }
      })();
    }
    while (
         !shuttingDown
      && pendingURLs.length != 0
    ) {
      await sleep(4000);
    }
    while (paused) {
      await sleep(4000);
    }
    res();
  });
}

/**
 * Starts scanning an array of potentially vulnerable URLs that is chunked to the specified
 * amount of threads.
 */
const scanForExploitableURIsAndQueue = async () => {
  return new Promise(async(res) => {
    scanCount++;
    discoveredURLs = discoveredURLs.concat(
       document.documentElement.innerHTML
         .match(regexpSelectorURLWithURIParameterHTML) || []);
    const nonRecursiveGlobalThis = JSON.parse(JSON.prune(globalThis));
    const globalThisStringValues = getAllStringValues(nonRecursiveGlobalThis);
    for (let a = 0; a < globalThisStringValues.length; a++) {
      if (globalThisStringValues[a].match(regexpSelectorURLWithURIParameterPlain)) {
        const parsedURL = parseURL(globalThisStringValues[a]);
        if (
             parsedURL[1] != "" /* host */
          || parsedURL[3] != "" /* path */
          || parsedURL[4] != "" /* search */
        ) {
          discoveredURLs.push(toFullURL(globalThisStringValues[a]));
        }
      }
    }
    if (discoveredURLs && discoveredURLs.length > 0) {
      console.log("%cfuzzer-open-redirect", consoleCSS,
        "Scan finished.",
        "Found " + discoveredURLs.length + " potentially exploitable URI(s). Converting them to full URLs.");
      for (let a = 0; a < discoveredURLs.length; a++) {
        discoveredURLs[a] = toFullURL(unescapeHTML(stripTrailingQuotes(discoveredURLs[a])));
      }
      let filteredDiscoveredURLs = [];
      for (let a = 0; a < discoveredURLs.length; a++) {
        const parsedURL = parseURL(discoveredURLs[a]);
        if (
             filteredDiscoveredURLs.indexOf(discoveredURLs[a]) === -1
          && isInScopeOrigin(parsedURL[0] + parsedURL[1])
        ) {
          filteredDiscoveredURLs.push(discoveredURLs[a]);
        }
      }
      console.log("%cfuzzer-open-redirect", consoleCSS,
        "Discovered URLs that are potentially vulnerable and in scope:");
      console.log(filteredDiscoveredURLs);
      for (let a = 0; a < filteredDiscoveredURLs.length; a++) {
        let thisURLCandidate = filteredDiscoveredURLs[a];
        for (let b = 0; b < redirectURLs.length; b++) {
          const redirectURLVariants = getURLVariants(redirectURLs[b]);
          for (let c = 0; c < redirectURLVariants.length; c++) {
            const injectedURLPermutations = getInjectedURLPermutations(
              thisURLCandidate,
              redirectURLVariants[c]);
            pendingURLs = pendingURLs.concat(injectedURLPermutations);
            allInjectedURLs = allInjectedURLs.concat(injectedURLPermutations);
          }
        }
      }
    } else {
      console.log("%cfuzzer-open-redirect", consoleCSS,
        "No exploitable URIs found.");
    }
    scanCount--;
    res();
  });
}

/**
 * Init fuzzer.
 */
(async () => {
  /* Register message listeners if scanning recursively. */
  if (scanRecursively) {
    globalThis.addEventListener("message", message => {
      if (
           message.data.sessionID === sessionID
        && message.data.discoveredURLs
      ) {
        message.data.discoveredURLs = message.data.discoveredURLs
          .filter((url, index, arr) => {
            return (
                 index === arr.indexOf(url)
              && discoveredURLs.indexOf(url) === -1);
          });
        discoveredURLs = discoveredURLs.concat(message.data.discoveredURLs);
        let injectedURLsCallback = [];
        message.data.discoveredURLs.forEach(url => {
          for (let a = 0; a < redirectURLs.length; a++) {
            const redirectURLVariants = getURLVariants(redirectURLs[a]);
            for (let b = 0; b < redirectURLVariants.length; b++) {
              const injectedURLPermutations = getInjectedURLPermutations(
                url,
                redirectURLVariants[b]);
              injectedURLsCallback = injectedURLsCallback.concat(injectedURLPermutations);
            }
          }
        });
        injectedURLsCallback = injectedURLsCallback.filter((url, index, arr) => {
          return allInjectedURLs.indexOf(url) === -1;
        });
        pendingURLs = pendingURLs.concat(injectedURLsCallback);
        allInjectedURLs = allInjectedURLs.concat(injectedURLsCallback);
        const chunkedInjectedURLsCallback = chunkURLArray(injectedURLsCallback);
        for (let a = 0; a < chunkedInjectedURLsCallback.length; a++) {
          chunkedPendingURLs[a].concat(chunkedInjectedURLsCallback[a]);
        }
      }
    });
  }
  /* Parse specified callback URLs for open redirects and requests. */
  parsedCallbackURLOpenRedirectTimestamps = parseURL(callbackURLOpenRedirectTimestamps);
  if (parsedCallbackURLOpenRedirectTimestamps[1] === "") {
    console.error("%cfuzzer-open-redirect", consoleCSS,
      "No valid origin was provided in the specified callback URL for open redirect timestamps (" + callbackURLOpenRedirectTimestamps + ").");
    return;
  }
  if (parsedCallbackURLOpenRedirectTimestamps[0] === "") {
    console.warn("%cfuzzer-open-redirect", consoleCSS,
      "No protocol was provided in the specified callback URL for open redirect timestamps (" + callbackURLOpenRedirectTimestamps + ").",
      "Defaulting to \"http://\".");
    parsedCallbackURLOpenRedirectTimestamps[0] = "http://";
  }
  console.log("%cfuzzer-open-redirect", consoleCSS,
    "Callback URL for open redirect timestamps is parsed: " +
    parsedCallbackURLOpenRedirectTimestamps.join(""));
  parsedCallbackURLRequestTimestamps = parseURL(callbackURLRequestTimestamps);
  if (parsedCallbackURLRequestTimestamps[1] === "") {
    console.error("%cfuzzer-open-redirect", consoleCSS,
      "No valid origin was provided in the specified callback URL for request timestamps (" + callbackURLOpenRedirectTimestamps + ").");
    return;
  }
  if (parsedCallbackURLRequestTimestamps[0] === "") {
    console.warn("%cfuzzer-open-redirect", consoleCSS,
      "No protocol was provided in the specified callback URL for request timestamps (" + callbackURLOpenRedirectTimestamps + ").",
      "Defaulting to \"http://\".");
    parsedCallbackURLRequestTimestamps[0] = "http://";
  }
  console.log("%cfuzzer-open-redirect", consoleCSS,
    "Callback URL for request timestamps is parsed: " +
    parsedCallbackURLRequestTimestamps.join(""));
  /* Automatically close tab if this origin belongs to a specified callback URL. */
  if (
       globalThis.location.origin.toLowerCase() === parsedCallbackURLOpenRedirectTimestamps
         .slice(0,2)
         .join("")
         .toLowerCase()
    || globalThis.location.origin.toLowerCase() === parsedCallbackURLRequestTimestamps
         .slice(0,2)
         .join("")
         .toLowerCase()
  ) {
    setTimeout(globalThis.close, timeoutCallback);
    globalThis.addEventListener("load", globalThis.close);
    if (globalThis.document && globalThis.document.readyState === "complete") {
      globalThis.close();
    }
    return;
  }
  /* If successfully exploited, send a timestamped callback for open redirects. */
  for (let a = 0; a < redirectURLs.length; a++) {
    const redirectHost = parseURL(redirectURLs[a])[1];
    if (location.host.toLowerCase().endsWith(redirectHost.toLowerCase())) {
      const date = new Date();
      const timestamp = date.toLocaleDateString() + " " +  date.toLocaleTimeString();
      let callbackURL = parsedCallbackURLOpenRedirectTimestamps.slice(0,4).join("");
      if (parsedCallbackURLOpenRedirectTimestamps[4] !== "") {
        callbackURL = callbackURL + parsedCallbackURLOpenRedirectTimestamps[4] +
          "&fuzzer-open-redirect-callback=" + encodeURIComponent(timestamp);
      } else {
        callbackURL = callbackURL + "?fuzzer-open-redirect-callback=" +
          encodeURIComponent(timestamp);
      }
      callbackURL = callbackURL + parsedCallbackURLOpenRedirectTimestamps.slice(5);
      globalThis.location = callbackURL;
    } 
  }
  /* Start fuzzer if this origin is in scope or close this tab if fuzzer opened it. */
  if (
       (globalThis.opener && isInScopeOrigin(globalThis.location.origin) && scanRecursively)
    || (globalThis.opener && scanOutOfScopeOrigins && scanRecursively)
    || (!globalThis.opener && isInScopeOrigin(globalThis.location.origin))
    || scanOutOfScopeOrigins
  ) {
    /* This origin is in scope. */
    console.log("%cfuzzer-open-redirect", consoleCSS,
      "Scanning for exploitable URIs.");
    scanForExploitableURIsAndQueue();
    if (globalThis.document) {
      globalThis.document.addEventListener("DOMContentLoaded", async () => {
        scanForExploitableURIsAndQueue();
      });
    }
    if (globalThis.document && globalThis.document.readyState !== "complete") {
      /* Document has not finished loading. */
      globalThis.addEventListener("load", async () => {
        scanForExploitableURIsAndQueue();
        if (pendingURLs.length > 0) {
          if (globalThis.opener) {
            while (scanCount > 0) {
              await sleep(4000);
            }
            globalThis.opener.postMessage({
              sessionID: sessionID,
              discoveredURLs: discoveredURLs
            });
            pendingURLs = [];
          } else {
            await openPendingURLs();
          }
        }
      });
    } else {
      /* Document has finished loading. */
      scanForExploitableURIsAndQueue();
      if (pendingURLs.length > 0) {
        if (globalThis.opener) {
          globalThis.opener.postMessage({
            sessionID: sessionID,
            discoveredURLs: discoveredURLs
          });
          pendingURLs = [];
        } else {
          await openPendingURLs();
        }
      }
    }
    if (globalThis.opener) {
      while (scanCount != 0 || pendingURLs.length > 0 || paused) {
        await sleep(4000);
      }
      await sleep(delayCloseTabs);
      globalThis.close();
    }
  } else {
    /* This origin is out of scope. */
    if (globalThis.opener) {
      (async () => {
        await sleep(delayCloseTabs);
        globalThis.close();
      })();
    }
  }
  console.log("%cfuzzer-open-redirect", consoleCSS,
    "Fuzzer has finished.");
})();

