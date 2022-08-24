/**
 * Content script for fuzzer-open-redirect.
 */

"use strict";

const consoleCSS = "background-color:rgb(80,255,0);text-shadow:0 1px 1px rgba(0,0,0,.3);color:black";
const regexpSelectorAllHTMLAttributes = / [a-z-]+[=]["'][^"']+["']/ig;
const regexpSelectorAnyFileExtension = /[.][a-z]{2,3}$/i;
const regexpSelectorDebrisHTMLAttributeOne = /^ [a-z-]+[=]/ig;
const regexpSelectorDebrisHTMLAttributeTwo = /^["']/;
const regexpSelectorDebrisHTMLAttributeThree = /["']$/;
const regexpSelectorEscapeChars = /([^*a-z0-9\]])/ig;
const regexpSelectorHTMLURLAttribute = /^ (?:action|href|src)[=]/i;
const regexpSelectorJSONPruneWebkitStorageInfoOne = /webkitStorageInfo/;
const regexpSelectorJSONPruneWebkitStorageInfoTwo = /webkitStorageInfo/g;
const regexpSelectorPathWithDirectory = /^[^/]+[/][^/]+/i;
const regexpSelectorURIOne = /^(?:http|\/|[a-z0-9_-]{1,8192}|[a-z0-9_ -]{1,8192}\.[a-z]{1,2}[a-z0-9]{0,1})[/?#]/i;
const regexpSelectorURITwo = /^(?:http|\/|[a-z0-9_-]{1,8192}|[a-z0-9_ -]{1,8192}\.[a-z]{1,2}[a-z0-9]{0,1})[^?]{0,8192}\?/i;
const regexpSelectorURIWithParameterPlain = /(?:(?:http[s]?(?:[:]|%3a))?(?:(?:[/]|%2f){2}))(?:(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{1,63})|(?:25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1-9]?[0-9])\.(?:25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1-9]?[0-9])\.(?:25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1-9]?[0-9])\.(?:25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1-9]?[0-9]))(?:\/[^?# "'`),]{0,8192})?(?:\?[^# "'`),]{0,8192})?(?:[#][^ "'`),]{0,8192})?/ig;
const regexpSelectorURLHost = /^((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.){1,63}(?:[a-z]{1,63})|(?:25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1-9]?[0-9])\.(?:25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1-9]?[0-9])\.(?:25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1-9]?[0-9])\.(?:25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1-9]?[0-9]))?.*$/i;
const regexpSelectorURLPath = /^([^?#]{1,2048})?.*$/i;
const regexpSelectorURLPlain = /(?:(?:http[s]?(?:[:]|%3a))?(?:(?:[/]|%2f){2}))(?:(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{1,63})|(?:25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1-9]?[0-9])\.(?:25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1-9]?[0-9])\.(?:25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1-9]?[0-9])\.(?:25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1-9]?[0-9]))(?:\/[^?# "'`),]{0,8192})?(?:\?[^# "'`),]{0,8192})?(?:[#][^ "'`),]{0,8192})?/ig;
const regexpSelectorURLPort = /^([:](?:6553[0-5]|655[0-2][0-9]|65[0-4][0-9][0-9]|6[0-4][0-9][0-9][0-9]|[0-5][0-9][0-9][0-9][0-9]|[1-9][0-9]{0,3}))?.*$/i;
const regexpSelectorURLProtocol = /^((?:[a-z0-9.+-]{1,256}[:])(?:[/][/])?|(?:[a-z0-9.+-]{1,256}[:])?[/][/])?.*$/i;
const regexpSelectorURLScheme = /^([a-z0-9.+-]*)[*]([a-z0-9.+-]*):/ig;
const regexpSelectorURLSearch = /^([?][^#]{0,2048})?.*$/i;
const regexpSelectorWildcard = /[*]/g;

let injectableParameterURLs = [];
let scannableURLs = [];
let paused = false;
let scanCount = 0;

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
    if (obj == null) return;
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
    if (regexpSelectorJSONPruneWebkitStorageInfoOne.test(key)) key = replace(regexpSelectorJSONPruneWebkitStorageInfoTwo, "navigator.webkitTemporaryStorage");
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
        if (depthDecr <= 0 || seen.indexOf(value) !== -1) {
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
    if (typeof depthDecr === "object") {
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
 * Buffered and throttled method that returns the index of a given target object in a given
 * array.
 */
const bufferedIndexOf = async (arr, target, bufferLength, throttleDuration) => {
  const amountOfChunks = Math.ceil(arr.length / bufferLength);
  for (let a = 0; a < amountOfChunks; a++) {
    for (
      let b = a * bufferLength;
         b < arr.length
      && b < (a * bufferLength) + bufferLength - 1;
      b++
    ) {
      if (arr[b] === target) {
        return b;
      }
    }
    if (throttleDuration !== 0) await sleep(throttleDuration);
  }
  return -1;
};

/**
 * Returns an array of all string values that were found in a given object.
 */
const getAllStringValues = obj => {
  let strings = [];
  Object.keys(obj).forEach(key => {
    if (typeof(obj[key]) === "object" && obj[key]) {
      strings = strings.concat(getAllStringValues(obj[key]));
    } else if (typeof(obj[key]) === "string") {
      strings.push(obj[key]);
    }
  });
  return strings;
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
    .replace(/&#38;/ig,  "&")
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
    .replace(/&#60;/ig,  "<")
    .replace(/&#61;/ig,  "=")
    .replace(/&gt;/ig,   ">")
    .replace(/&#62;/ig,  ">")
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
 * Returns an array containing the protocol, host, port, path, search and hash of a
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
  const strippedURL = trimWhitespaces(url);
  const retval = ["","","","","",""];
  /* protocol */
  retval[0] = strippedURL.replace(regexpSelectorURLProtocol, "$1");
  const protocol = retval[0].toLowerCase();
  if (protocol.length !== 0) {
    if (
         protocol === "data:"
      || protocol === "javascript:"
    ) {
      retval[3] = url.slice(retval[0].length);
      return retval;
    }
    /* host */
    retval[1] = strippedURL.slice(retval[0].length).replace(regexpSelectorURLHost, "$1");
  }
  /* port */
  retval[2] = strippedURL.slice(retval[0].length + retval[1].length).replace(regexpSelectorURLPort, "$1");
  /* path */
  retval[3] = strippedURL.slice(retval[0].length + retval[1].length + retval[2].length).replace(regexpSelectorURLPath, "$1");
  /* search */
  retval[4] = strippedURL.slice(retval[0].length + retval[1].length + retval[2].length + retval[3].length).replace(regexpSelectorURLSearch, "$1");
  /* hash */
  retval[5] = strippedURL.slice(retval[0].length + retval[1].length + retval[2].length + retval[3].length + retval[4].length);
  return retval;
};

/**
 * (example input: "http://www.in.scope.domain.com")
 * (example output given "\*://\*.in.scope.*" is in the scope: true)
 */
const isInScopeOrigin = origin => {
  for (let a = 0; a < scope.length; a++) {
    const regexpInScopeOrigin = new RegExp(
      "^" + scope[a]
        .replace(regexpSelectorEscapeChars, "[$1]") /* escape chars */
        .replace(regexpSelectorURLScheme, "$1[a-z0-9.+-]+$2:") /* scheme */
        .replace(regexpSelectorWildcard, "(?:(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?.)+)"), /* host wildcard */
      "ig");
    if (regexpInScopeOrigin.test(origin)) {
      return true;
    }
  }
  return false;
}

/**
 * Returns the full URL based on a given URI that was found in the
 * current document.
 */
const toFullURL = uri => {
  const parsedURL = parseURL(uri);
  if (
       parsedURL[0].length === 0 /* protocol */
    && parsedURL[1].length === 0 /* host */
    && parsedURL[3].length === 0 /* path */
    && parsedURL[4].length === 0 /* search */
    && parsedURL[5].length !== 0 /* hash */
  ) {
    return location.origin + location.pathname + location.search + uri;
  }
  if (
       parsedURL[0].length === 0 /* protocol */
    && parsedURL[1].length === 0 /* host */
    && parsedURL[3].length === 0 /* path */
    && parsedURL[4].length !== 0 /* search */
  ) {
    return location.origin + location.pathname + uri;
  }
  if (
       parsedURL[0].length === 0 /* protocol */
    && parsedURL[1].length === 0 /* host */
    && parsedURL[3].length !== 0 /* path */
  ) {
    if (uri.startsWith("/")) {
      return location.origin + uri;
    } else {
      return location.origin + "/" + uri;
    }
  }
  return uri;
}

/**
 * Trims all leading and trailing whitespaces off a given string.
 * (example input: " https://example.com/  \n")
 * (example output: "https://example.com/")
 */
const trimWhitespaces = str => {
  return str.replace(/^\s*(.*)\s*$/g, "$1");
};

/**
 * Sleeps an awaited promise value for the given amount of
 * milliseconds.
 */
const sleep = async ms => {
  return new Promise(res => {
    setTimeout(res, ms);
  });
}

/**
 * Starts automatically scrolling the window from the top left to
 * the bottom right indefinitely.
 */
const startAutoScrolling = async () => {
  const allNodes = document.querySelectorAll("*");
  for (let a = 0; a < allNodes.length; a++) {
    (async()=>{
      const node = allNodes[a];
      while (true) {
        node.scrollTo(9999999999, 9999999999);
        await sleep(1000);
        node.scrollTo(0, 0);
        await sleep(1000);
      }
      await sleep(delayThrottleAutoScrollNode);
    })();
  }
}

/**
 * Strips leading and trailing single/double quote from a given string.
 */
const stripLeadingAndTrailingQuotes = str => {
  return str.replace(/^["'](.*)["']$/g, "$1");
}

/**
 * Strips leading and trailing whitespace from a given string.
 */
const stripLeadingAndTrailingWhitespace = str => {
  return str.replace(/^\s*(.*)\s*$/g, "$1");
}

/**
 * Scans this document's source and DOM tree for potentially
 * vulnerable URLs that are in scope and returns them in an array.
 */
const scanForExploitableURIs = async () => {
  return new Promise(async res => {
    scanCount++;
    let URLs = [];
    if (document.documentElement) {
      if (document.documentElement.innerText) {
        let match;
        while (
          match = regexpSelectorURIWithParameterPlain.exec(
            document.documentElement.innerText)
        ) {
          URLs.push(toFullURL(match[0]));
        }
      }
      const allNodes = document.querySelectorAll("*");
      for (let a = 0; a < allNodes.length; a++) {
        const node = allNodes[a];
        for (let b = 0; b < node.attributes.length; b++) {
          const attributeValue = node.attributes[b].value;
          if (regexpSelectorURITwo.test(attributeValue)) {
            URLs.push(toFullURL(attributeValue));
          }
        }
      }
    }
    const prunedGlobalThis = JSON.parse(JSON.prune(globalThis));
    // more of this
    if (prunedGlobalThis.document) {
      prunedGlobalThis.document.location = null;
    }
    prunedGlobalThis.location = null;
    prunedGlobalThis.origin = null;
    const globalThisStringValues = getAllStringValues(prunedGlobalThis);
    const amountOfChunks = Math.ceil(globalThisStringValues.length / bufferLengthURLs);
    for (let a = 0; a < amountOfChunks; a++) {
      for (
        let b = a * bufferLengthURLs;
           b < globalThisStringValues.length
        && b < (a * bufferLengthURLs) + bufferLengthURLs - 1;
        b++
      ) {
        const parsedFullURL = parseURL(globalThisStringValues[b]);
        if (parsedFullURL[4].length !== 0) {
          const fullURL = parsedFullURL.join("");
          if (
               fullURL !== location.href
            && (
                 scanOutOfScopeOrigins
              || isInScopeOrigin(parsedFullURL.slice(0, 2).join(""))
            )
            && await bufferedIndexOf(
                 URLs,
                 fullURL,
                 bufferLengthURLs,
                 delayThrottleURLIndexing) === -1
            && await bufferedIndexOf(
                 injectableParameterURLs,
                 fullURL,
                 bufferLengthURLs,
                 delayThrottleURLIndexing) === -1
          ) {
            URLs.push(fullURL);
          }
        }
      }
     await sleep(delayThrottleURLIndexing);
    }
    if (URLs.length > 0) {
      injectableParameterURLs = injectableParameterURLs.concat(URLs);
      scannableURLs = scannableURLs.concat(URLs);
      console.log("%cfuzzer-open-redirect", consoleCSS,
        "Discovered " + URLs.length + " new URL(s) that are potentially vulnerable and in scope.");
    } else {
      console.log("%cfuzzer-open-redirect", consoleCSS,
        "No exploitable, in-scope URIs found.");
    }
    scanCount--;
console.log("completed scanForExploitableURIs()")
    res();
  });
}

/**
 * Scans this document's source and DOM tree for URIs that are in
 * scope and returns them in an array of URLs.
 */
const scanForURIs = async () => {
  return new Promise(async res => {
    scanCount++;
    let URLs = [];
    if (document.documentElement) {
      if (document.documentElement.innerText) {
        let match;
        while (
          match = regexpSelectorURLPlain.exec(document.documentElement.innerText)
        ) {
          const parsedURL = parseURL(match[0]);
          if (
               match[0] !== location.href
            && (
                 scanOutOfScopeOrigins
              || isInScopeOrigin(parsedURL.slice(0, 2).join(""))
            )
            && await bufferedIndexOf(
                 URLs,
                 match[0],
                 bufferLengthURLs,
                 delayThrottleURLIndexing) === -1
            && await bufferedIndexOf(
                 scannableURLs,
                 match[0],
                 bufferLengthURLs,
                 delayThrottleURLIndexing) === -1
          ) {
            URLs.push(match[0]);
          }
          await sleep(delayThrottleRegexpSearch);
        }
      }
      const allNodes = document.querySelectorAll("*");
      for (let a = 0; a < allNodes.length; a++) {
        const node = allNodes[a];
        for (let b = 0; b < node.attributes.length; b++) {
          const attributeValue = node.attributes[b].value;
          if (regexpSelectorURIOne.test(attributeValue)) {
            URLs.push(toFullURL(attributeValue));
          }
        }
      }
    } else {
console.log("no document.documentElement found in scanForURIs")
    }
    const prunedGlobalThis = JSON.parse(JSON.prune(globalThis));
    if (prunedGlobalThis.document) {
      prunedGlobalThis.document.location = null;
    }
    prunedGlobalThis.location = null;
    prunedGlobalThis.origin = null;
    const globalThisStringValues = getAllStringValues(prunedGlobalThis);
    const amountOfChunks = Math.ceil(globalThisStringValues.length / bufferLengthURLs);
    for (let a = 0; a < amountOfChunks; a++) {
      for (
        let b = a * bufferLengthURLs;
           b < globalThisStringValues.length
        && b < (a * bufferLengthURLs) + bufferLengthURLs - 1;
        b++
      ) {
        const parsedURL = parseURL(globalThisStringValues[b]);
        if (
             parsedURL[1].length !== 0 /* host */
          || parsedURL[4].length !== 0 /* search */
          || parsedURL[5].length !== 0 /* hash */
          || (
               parsedURL[3].length !== 0 /* path */
            && (
                 parsedURL[3].charAt(0) === "/" /* path */
              || regexpSelectorAnyFileExtension.test(parsedURL[3]) /* path */
              || regexpSelectorPathWithDirectory.test(parsedURL[3]) /* path */
            )
          )
        ) {
          const fullURL = toFullURL(globalThisStringValues[[b]]);
          if (
               fullURL !== location.href
            && await bufferedIndexOf(
                 URLs,
                 fullURL,
                 bufferLengthURLs,
                 delayThrottleURLIndexing) === -1
            && await bufferedIndexOf(
                 scannableURLs,
                 fullURL,
                 bufferLengthURLs,
                 delayThrottleURLIndexing) === -1
          ) {
            if (scanOutOfScopeOrigins) {
              URLs.push(fullURL);
            } else {
              const parsedFullURL = parseURL(fullURL);
              if (isInScopeOrigin(parsedFullURL[0] + parsedFullURL[1])) {
                URLs.push(fullURL);
              }
            }
          }
        }
      }
      await sleep(delayThrottleURLIndexing);
    }
    if (URLs.length > 0) {
      scannableURLs = scannableURLs.concat(URLs);
      console.log("%cfuzzer-open-redirect", consoleCSS,
        "Discovered " + URLs.length +  " new URL(s) that are in scope.");
    } else {
      console.log("%cfuzzer-open-redirect", consoleCSS,
        "No in-scope URIs found.");
    }
    scanCount--;
console.log("completed scanForURIs()")
    res();
  });
}

/**
 * Init fuzzer.
 */
(async () => {
  /* If successfully exploited, send a timestamped callback for open redirects. */
  startAutoScrolling();
  let redirectHosts = [];
  for (let a = 0; a < redirectURLs.length; a++) {
    const parsedURL = parseURL(redirectURLs[a]);
    const protocol = parsedURL[0].toLowerCase();
    if (
         parsedURL[1].length !== 0
      && protocol !== "data:"
      && protocol !== "javascript:"
    ) {
      const redirectHost = parsedURL[1].toLowerCase();
      if (redirectHosts.indexOf(redirectHost) === -1) {
        redirectHosts.push(redirectHost);
      }
    }
  }
  for (let a = 0; a < redirectHosts.length; a++) {
    if (location.hostname.endsWith(redirectHosts[a])) {
      const date = new Date();
      const timestamp = date.toLocaleDateString() + " " +  date.toLocaleTimeString();
      chrome.runtime.sendMessage({timestamp: timestamp});
    }
  }
  /* Start scanning document for redirect URLs. */
  console.log("%cfuzzer-open-redirect", consoleCSS,
    "Scanning for URLs.");
  while (!globalThis.document) {
    await sleep(300);
  }
  if (globalThis.document.readyState === "loading") {
    globalThis.document.addEventListener("DOMContentLoaded", async () => {
      scanForExploitableURIs();
      scanForURIs();
      while (scanCount !== 0) {
        await sleep(1000);
      }
      chrome.runtime.sendMessage({
        injectableParameterURLs: injectableParameterURLs,
        message: "FRAME_READYSTATE_COMPLETE",
        scannableURLs: scannableURLs,
      });
    });
    globalThis.document.addEventListener("DOMContentLoaded", () => {
      chrome.runtime.sendMessage({message: "FRAME_READYSTATE_INTERACTIVE"});
    });
  } else {
    chrome.runtime.sendMessage({message: "FRAME_READYSTATE_INTERACTIVE"});
    if (globalThis.document.readyState !== "complete") {
      /* Document has not finished loading. */
      globalThis.addEventListener("load", async () => {
        scanForExploitableURIs();
        scanForURIs();
        while (scanCount !== 0) {
          await sleep(1000);
        }
        chrome.runtime.sendMessage({
          injectableParameterURLs: injectableParameterURLs,
          message: "FRAME_READYSTATE_COMPLETE",
          scannableURLs: scannableURLs,
        });
      });
    } else {
      /* Document has finished loading. */
      scanForExploitableURIs();
      scanForURIs();
      while (scanCount !== 0) {
        await sleep(1000);
      }
      chrome.runtime.sendMessage({
        injectableParameterURLs: injectableParameterURLs,
        message: "FRAME_READYSTATE_COMPLETE",
        scannableURLs: scannableURLs,
      });
    }
  }
})();
