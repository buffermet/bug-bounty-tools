// anchor communication structure
//
// #{session_id}
//

// onBeforeSendHeaders
// 
// Example headers:
//
// Host: www.inscope.com
// Location: https://some.unexpected.subdomain.myredirecturl.com/
// X-Open-Redirect-Scanner-Session-ID: 2y5jti4nj53454j6k53
// X-Open-Redirect-Scanner-Cookie: a=2839ht493t374h9
// X-Open-Redirect-Scanner-Host: myredirecturl.com
//

"use strict";

let pendingURLs = [];

const redirectURLs = [
  "https://www.runescape.com",
  "https://www.runescape.com/",
  "https://www.runescape.com/splash",
  "https://www.runescape.com/splash?nothing"
];

const anchor = location.anchor;
const regexpSelectorURLWithURIParameter = /["'](?:http[s]?(?:[:]|%3a)(?:(?:[/]|%2f){2})?)?(?:(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{1,63}))?(?:[^'"()=&?\[\]\{\}<>]+)?[?][^"']+[=](?:http|[/]|%2f)[^"'()\[\]\{\}]*['"]/ig;
const regexpSelectorFullURL = /^()$/ig;

let protocols = ["http://", "https://"];
let requestDelay = [2000, 6000];
let session_id = "2y5jti4nj53454j6k53";
let threads = 4;

(function () {
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
}());

/*
 * Returns an integer value between a minimum and maximum range of milliseconds.
 */
const getIntFromRange = (min, max) => {
  return parseInt(min + (Math.random() * (max - min)));
}

/*
 * 
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

/*
 * Returns an array containing the protocol, host, port, path, query and anchor of a
 * given URL if found.
 */
const parseURL = url => {
  const strippedURL = stripAllTrailingWhitespaces(url);
  console.log("parsing: " + strippedURL);
  const retval = ["","","","","",""];
  // protocol
  if (strippedURL.match(/^((?:\w+:)?\/\/).*$/i)) {
    retval[0] = strippedURL.replace(/^((?:\w+:)?\/\/).*$/i, "$1");
  }
  // host
  if (strippedURL.match(/^(?:(?:(?:\w+:)?\/\/)((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{1,63}))(?:[:][1-9][0-9]{0,4})?)(?:[/][^/].*$|[/]$|[?#].*$|$)/i)) {
    retval[1] = strippedURL.replace(/^(?:(?:(?:\w+:)?\/\/)((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{1,63}))(?:[:][1-9][0-9]{0,4})?)(?:[/][^/].*$|[/]$|[?#].*$|$)/i, "$1");
  }
  // port
  if (strippedURL.match(/^(?:(?:(?:\w+:)?\/\/)?(?:(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{1,63})))([:][1-9][0-9]{0,4}).*/i)) {
    retval[2] = strippedURL.replace(/^(?:(?:(?:\w+:)?\/\/)?(?:(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{1,63})))([:][1-9][0-9]{0,4}).*$/i, "$1");
  }
  // path
  if (strippedURL.match(/^(?:(?:\w+:)?\/\/(?:(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{1,63}))(?:[:][1-9][0-9]{0,4})?)?([/][^?#]*).*/i)) {
    retval[3] = strippedURL.replace(/^(?:(?:\w+:)?\/\/)?[^/?#]*([/][^/?#]*).*$/i, "$1");
  }
  // query
  if (strippedURL.match(/^.*?([?][^#]*).*/i)) {
    retval[4] = strippedURL.replace(/^.*?([?][^#]*).*$/i, "$1");
  }
  // anchor
  if (strippedURL.match(/^[^#]*([#].*)/i)) {
    retval[5] = strippedURL.replace(/^[^#]*([#].*)/i, "$1");
  }
  console.log(retval);
  return retval;
}

/*
 * Removes the anchor part of a given URL.
 */
const stripURLAnchor = url => {
  return url.replace(/(^[^#]*)/ig, "");
}

/*
 * Returns an array of 4 potential URLs that lead to the same address as a given URL.
 */
const getURLVariants = url => {
  let urls = [];
  const parsedURL = parseURL(url);
  urls = [].concat(urls, [ 
    "https://",
    parsedURL[1],
    parsedURL[2],
    parsedURL[3],
    parsedURL[4],
    parsedURL[5]
  ]);
  urls = [].concat(urls, [ 
    "http://",
    parsedURL[1],
    parsedURL[2],
    parsedURL[3],
    parsedURL[4],
    parsedURL[5]
  ]);
  urls = [].concat(urls, [ 
    "//",
    parsedURL[1],
    parsedURL[2],
    parsedURL[3],
    parsedURL[4],
    parsedURL[5]
  ]);
  urls = [].concat(urls, [ 
    parsedURL[1],
    parsedURL[2],
    parsedURL[3],
    parsedURL[4],
    parsedURL[5]
  ]);
  urls = [].concat(urls, [ 
    encodeURIComponent("https://"),
    encodeURIComponent(parsedURL[1]),
    encodeURIComponent(parsedURL[2]),
    encodeURIComponent(parsedURL[3]),
    encodeURIComponent(parsedURL[4]),
    encodeURIComponent(parsedURL[5])
  ]);
  urls = [].concat(urls, [ 
    encodeURIComponent("http://"),
    encodeURIComponent(parsedURL[1]),
    encodeURIComponent(parsedURL[2]),
    encodeURIComponent(parsedURL[3]),
    encodeURIComponent(parsedURL[4]),
    encodeURIComponent(parsedURL[5])
  ]);
  urls = [].concat(urls, [ 
    encodeURIComponent("//"),
    encodeURIComponent(parsedURL[1]),
    encodeURIComponent(parsedURL[2]),
    encodeURIComponent(parsedURL[3]),
    encodeURIComponent(parsedURL[4]),
    encodeURIComponent(parsedURL[5])
  ]);
  urls = [].concat(urls, [ 
    encodeURIComponent(parsedURL[1]),
    encodeURIComponent(parsedURL[2]),
    encodeURIComponent(parsedURL[3]),
    encodeURIComponent(parsedURL[4]),
    encodeURIComponent(parsedURL[5])
  ]);

  urls = [].concat(urls, [ 
    encodeURIComponent(encodeURIComponent("https://")),
    encodeURIComponent(encodeURIComponent(parsedURL[1])),
    encodeURIComponent(encodeURIComponent(parsedURL[2])),
    encodeURIComponent(encodeURIComponent(parsedURL[3])),
    encodeURIComponent(encodeURIComponent(parsedURL[4])),
    encodeURIComponent(encodeURIComponent(parsedURL[5]))
  ]);
  urls = [].concat(urls, [ 
    encodeURIComponent(encodeURIComponent("http://")),
    encodeURIComponent(encodeURIComponent(parsedURL[1])),
    encodeURIComponent(encodeURIComponent(parsedURL[2])),
    encodeURIComponent(encodeURIComponent(parsedURL[3])),
    encodeURIComponent(encodeURIComponent(parsedURL[4])),
    encodeURIComponent(encodeURIComponent(parsedURL[5]))
  ]);
  urls = [].concat(urls, [ 
    encodeURIComponent(encodeURIComponent("//")),
    encodeURIComponent(encodeURIComponent(parsedURL[1])),
    encodeURIComponent(encodeURIComponent(parsedURL[2])),
    encodeURIComponent(encodeURIComponent(parsedURL[3])),
    encodeURIComponent(encodeURIComponent(parsedURL[4])),
    encodeURIComponent(encodeURIComponent(parsedURL[5]))
  ]);
  urls = [].concat(urls, [ 
    encodeURIComponent(encodeURIComponent(parsedURL[1])),
    encodeURIComponent(encodeURIComponent(parsedURL[2])),
    encodeURIComponent(encodeURIComponent(parsedURL[3])),
    encodeURIComponent(encodeURIComponent(parsedURL[4])),
    encodeURIComponent(encodeURIComponent(parsedURL[5]))
  ]);
  return urls;
}

/*
 * Replaces every URI found in query parameters of a given URL. Returns an array of new
 * URLs that contains variations in the query of your specified redirect URL.
 * (example input: (
 *   "//www.google.com/q=http%3A%2F%2Fgmail%2Ecom%2F",
 *   %2F%2Fmysite%2Ecom%2F",
 * ))
 * (example output: "//www.google.com/q=%2F%2Fmysite%2Ecom%2F")
 */
const injectURL = (targetURL, redirectURL) => {
  const parsedURL = parseURL(targetURL);
  const query = parsedURL[4];
  let newQuery = "";
  if (query != "") {
    newQuery = "?";
  }
  const parameters = query.split("&");
  for (let a = 0; a < parameters.length; a++) {
    const parameterName = parameters[a].replace(/([=]*)=.*/, "$1");
    const parameterValue = parameters[a].replace(/.*?=(.*)\s*/, "$1");
    if (parameterValue.match(/^(?:http|[/]|%2f)/i)) {
      const replacedParameter = parameterName + "=" + redirectURL;
      targetURL.replace(parameters[a], replacedParameter);
    }
  }
  return parsedURL[0] +
    parsedURL[1] +
    parsedURL[2] +
    parsedURL[3] +
    newQuery +
    parsedURL[5];
}

/*
 * Returns an array of all string values that were found in a given object.
 */
const getAllStringValues = obj => {
  let strings = [];
  keys = Object.keys(obj);
  keys.forEach(key=>{
    if (typeof(obj[key]) == "object" && obj[key]) {
      strings = [].concat(strings, getAllStringValues(obj[key]));
    } else if (typeof(globalThis[key]) == "string") {
      strings = [].concat(strings, [obj[key]]);
    }
  });
  return strings;
}

/*
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

/*
 * Returns the full URL based off a given URI that was found in the current document.
 */
const toFullURL = uri => {
  if (
       !uri.match(/^(?:http[s]?[:])?[/][/]/i)
    && !uri.match(/^[^/]+/i)
    && !uri.match(/^[/][^?#]*/i)
    && uri.match(/^[?].*/i)
  ) {
    return location.protocol + "//" + location.host + location.pathname + uri;
  }
  if (
       !uri.match(/^(?:http[s]?[:])?[/][/]/i)
    && !uri.match(/^[^/]+/i)
    && uri.match(/^[/][^?#]*/i)
  ) {
    return location.protocol + "//" + location.host + uri;
  }
  if (
       !uri.match(/^(?:http[s]?[:])?[/][/]/i)
    && uri.match(/^[^/]+/i)
  ) {
    return location.protocol + "//" + location.host + uri;
  }
  return uri;
}

/*
 * Attempts to load the resources in a new window with the session ID in the URL anchor,
 * where this script will attempt check if the redirection was successful.
 */
const loadResource = url => {
  console.log("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
  console.log(url);
  const anchoredURL = url.replace(/(?:[#].*|$)/ig, "#" + session_id);
  console.log("Fetching", anchoredURL);
//  setTimeout(globalThis.open(url, "_blank"), 0);
}

/*
 * Sleeps an awaited promise value for the given amount of milliseconds.
 */
const sleep = ms => {
  return new Promise(res=>{
    setTimeout(res, ms);
  });
}

/*
 * Strips trailing single/double quote.
 */
const stripTrailingQuotes = str => {
  return str.replace(/^["'](.*)["']$/g, "$1");
}

/*
 * Strips all trailing whitespace.
 */
const stripAllTrailingWhitespaces = str => {
  return str.replace(/^\s*(.*)\s*$/g, "$1");
}

/*
 * Opens all pending and unique URLs.
 */
const openPendingURLs = () => {
  return new Promise((res, err)=>{
    pendingURLs.filter((url, index)=>{
      return pendingURLs.indexOf(url) == index;
    });
    const chunkedPendingURLs = chunkURLArray(pendingURLs);
    if (chunkedPendingURLs.length != threads) {
      const errorMsg = "Amount of chunked URLs does not match the specified amount of threads.";
      alert(errorMsg);
      err(errorMsg);
    }
    for (let a = 0; a < threads; a++) {
      (async()=>{
        for (let b = 0; b < chunkedPendingURLs.length; b++) {
          loadResource(chunkedPendingURLs[b]);
          await sleep(getIntFromRange(requestDelay[0], requestDelay[1]));
        }
      })();
    }
    res();
  });
}

/*
 * Starts scanning an array of potential open redirect URLs that is chunked to the specified
 * amount of threads.
 */
const scanForExploitableURIsAndQueue = async () => {
  return new Promise(async(res)=>{
    let discoveredURLs = document.documentElement.innerHTML.match(
      regexpSelectorURLWithURIParameter);
//    const nonRecursiveGlobalThis = JSON.parse(JSON.prune(globalThis));
//    for (let a = 0; a < nonRecursiveGlobalThis.length; a++) {
//      discoveredURLs.push(nonRecursiveGlobalThis[a]);
//    }
console.log("Scan finished.",
  "Found " + discoveredURLs.length + " potentially exploitable URL(s).");
console.log(discoveredURLs);
    if (discoveredURLs && discoveredURLs.length > 0) {
      for (let a = 0; a < discoveredURLs.length; a++) {
        discoveredURLs[a] = toFullURL(unescapeHTML(stripTrailingQuotes(discoveredURLs[a])));
      }
      discoveredURLs.filter((url, index)=>{
        return (discoveredURLs.indexOf(url) == index);
      });
      const chunkSize = Math.floor(redirectURLs.length / threads);
      const chunks = [];
      for (let a = 1; a <= threads; a++) {
        chunks[a] = redirectURLs.slice(chunkSize * a, (chunkSize * a) + chunkSize);
      }
      for (let a = 0; a < discoveredURLs.length; a++) {
        let thisURLCandidate = discoveredURLs[a];
console.log("this URL candidate:", thisURLCandidate);
        for (let b = 0; b < redirectURLs.length; b++) {
          const redirectURLVariants = getURLVariants(redirectURLs[b]);
          for (let c = 0; c < redirectURLVariants.length; c++) {
            const thisRedirectVariant = redirectURLVariants[c];
            if (
              globalThis.location.host.toLowerCase()
                .endsWith(parseURL(thisRedirectVariant)[1])
            ) {
              const msg = "--- OPEN REDIRECT FOUND --- PRESS OK TO CONTINUE SCANNING ---";
              alert(msg);
              console.log(msg);
            } 
            const injectedURL = injectURL(thisURLCandidate, thisRedirectVariant);
            pendingURLs.push(injectedURL);
            console.log("Added URL to queue: " + injectedURL);
          }
        }
      }
      await sleep(4000);
      if (globalThis.location.anchor == "#" + session_id) {
        self.close();
      }
    } else {
      console.log("No exploitable URIs found in this document.");
    }
    res();
  });
}

/* 
 * Init.
 */
(async()=>{
  scanForExploitableURIsAndQueue();

  if (globalThis.document) {
    globalThis.document.addEventListener("DOMContentLoaded", async()=>{
      scanForExploitableURIsAndQueue();
    });
  }

  globalThis.addEventListener("load", async()=>{
    scanForExploitableURIsAndQueue();
    if (pendingURLs.length > 0) {
      console.log(pendingURLs);
      openPendingURLs();
    }
  });
})();

