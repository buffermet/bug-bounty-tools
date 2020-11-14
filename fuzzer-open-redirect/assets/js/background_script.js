/**
 * Background script for fuzzer-open-redirect.
 */

/* User configurable. */
let crawlerScripts = [];
let delayForceWakeTabsThread = 1000;
let delayRangeFuzzerThread = [15000, 60000];
let delayRangeScannerThread = [15000, 60000];
let delayRangePendingRetryURLsThread = [8000, 30000];
let delayTabWatcherThread = 30000;
let delayURLInjectionThread = 60000;
let encodingTypes = [
  [0],
  [0,0],
  [0,4],
  [1],
  [2],
  [3],
  [4],
  [4,0],
  [4,4],
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
  [14,0],
  [14,4],
  [15],
  [15,0],
  [15,4],
  [16],
  [16,0],
  [16,4],
  [17],
  [17,0],
  [17,4],
  [18],
  [18,0],
  [18,4],
];
let sessionID = "8230ufjio";
let threadCountFuzzer = 2;
let threadCountScanner = 2;
let timeoutCallback = 16000;
let timeoutCloseTabs = 16000;
let timeoutRequests = 16000;
let isFuzzerThreadPaused = false;
let isScannerThreadPaused = false;
let retryAttempts = 6;

const alphabeticalChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
const consoleCSS = "background-color:rgb(80,255,0);text-shadow:0 1px 1px rgba(0,0,0,.3);color:black";
const redirectURLs = [
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
const regexpSelectorEscapableURICharacters = /[^A-Za-z0-9_.!~*'()-]/ig;

let arrayPermutations = [];
let callbackURLOpenRedirectTimestamps = "http://0.0.0.0:4242";
let callbackURLRequestTimestamps = "http://0.0.0.0:4243";
let chunkedInjectedURLs = [];
let chunkedScannableURLs = [];
let exploitableURLs = [];
let exploitableURLsBuffer = [];
let fuzzerTabs = [];
let fuzzerWindow;
let injectedURLs = [];
let parsedCallbackURLOpenRedirectTimestamps = ["","","","","",""];
let parsedCallbackURLRequestTimestamps = ["","","","","",""];
let pendingRetryURLs = {};
let programs = [];
let scannerTabs = [];
let scannerWindow;
let scannableURLs = [];
let tabWatcherBufferNew = [];
let tabWatcherBufferOld = [];

/**
 * Chunks a given array to a length of a given amount.
 */
const chunkArray = (urls, amountOfChunks) => {
  const chunkSize = Math.ceil(urls.length / amountOfChunks);
  const chunks = [];
  for (let a = 0; a < amountOfChunks; a++) {
    chunks[a] = urls.slice(chunkSize * a, (chunkSize * a) + chunkSize);
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
     * (example output: "https%3A%2F%2Fmyredirectsite%2Ecom%2f")
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
 * Returns an array of all string values that were found in a given object.
 */
const getAllStringValues = obj => {
  let strings = [];
  Object.keys(obj).forEach(key => {
    if (typeof(obj[key]) === "object" && obj[key]) {
      strings = strings.concat(getAllStringValues(obj[key]));
    } else if (typeof(globalThis[key]) === "string") {
      strings = strings.push(obj[key]);
    }
  });
  return strings;
};

/**
 * Appends all possible permutations of a given array to arrayPermutations.
 */
const getArrayPermutations = (prefix, arr) => {
  for (let a = 0; a < arr.length; a++) {
    arrayPermutations.push(prefix.concat(arr[a]));
    getArrayPermutations(prefix.concat(arr[a]), arr.slice(a + 1));
  }
};

/**
 * Returns an array of all injected permutations of a given URL.
 * (example input: (
 *   "//www.google.com/q=http%3A%2F%2Fgmail%2Ecom%2F",
 *   %2F%2Fmysite%2Ecom%2F",
 * ))
 */
const getInjectedURLPermutations = (targetURL, redirectURL) => {
  const regexp = new RegExp("=[^&]+", "ig");
  let regexpMatches = [];
  let match;
  while (match = regexp.exec(targetURL)) {
    regexpMatches.push({match: match[0], index: match.index});
  }
  getArrayPermutations([], regexpMatches);
  let _injectedURLs = [];
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
    _injectedURLs.push(injectedURL);
  }
  arrayPermutations = [];
  return _injectedURLs;
};

/**
 * Returns an integer value between a minimum and maximum range of milliseconds.
 */
const getIntFromRange = (min, max) => {
  return parseInt(min + (Math.random() * (max - min)));
};

/**
 * Returns an array of URLs that are encoded as per the specified encodingTypes value.
 */
const getURLVariants = url => {
  if (url === "") {
    console.error("Empty string parameter passed through getURLVariants().");
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
 * Opens a given URL in a new fuzzer tab.
 */
const openURLInNewFuzzerTab = async url => {
  return new Promise((res, err) => {
    let callbackURL;
    const date = new Date();
    const timestamp = date.toLocaleDateString() + " " +  date.toLocaleTimeString();
    if (parsedCallbackURLRequestTimestamps[4] !== "") {
      callbackURL = parsedCallbackURLRequestTimestamps.slice(0, 5).join("") +
        "&timestamp=" + encodeURIComponent(timestamp) +
        "&url=" + encodeURIComponent(url) +
        parsedCallbackURLRequestTimestamps[5];
    } else {
      callbackURL = parsedCallbackURLRequestTimestamps.slice(0, 4).join("") +
        "?timestamp=" + encodeURIComponent(timestamp) +
        "&url=" + encodeURIComponent(url) +
        parsedCallbackURLOpenRedirectTimestamps[5];
    }
    chrome.tabs.create({
      url: callbackURL,
      windowId: fuzzerWindow.id,
    }, tab => {
      tabWatcherBufferNew.push(tab.id);
      setTimeout(() => {
        removeTab(tab.id);
        // add to callback retry URLs
      }, timeoutCallback);
      fuzzerTabs.push({
        state: "loading",
        id: tab.id,
      });
    });
    chrome.tabs.create({
      url: url,
      windowId: fuzzerWindow.id,
    }, tab => {
      tabWatcherBufferNew.push(tab.id);
      setTimeout(() => {
        err("Opening tab timed out.");
      }, timeoutRequests);
      fuzzerTabs.push({
        state: "loading",
        id: tab.id,
      });
      // execute crawlerScripts
      res(tab);
    });
  });
};

/**
 * Opens a given URL in a new scanner tab.
 */
const openURLInNewScannerTab = async url => {
  return new Promise((res, err) => {
    setTimeout(() => {
      err("Opening tab timed out.");
    }, timeoutRequests);
    chrome.tabs.create({
      url: url,
      windowId: scannerWindow.id,
    }, tab => {
      tabWatcherBufferNew.push(tab.id);
      scannerTabs.push({
        state: "loading",
        id: tab.id,
      });
      // execute crawlerScripts
      res(tab);
    });
  });
};

/**
 * Opens new windows for fuzzing and scanning.
 */
const openFuzzerAndScannerWindows = async () => {
  return new Promise((res, err) => {
    setTimeout(() => {
      err("openFuzzerAndScannerWindows() timed out.")
    }, timeoutRequests);
    /* Open fuzzer window. */
    chrome.windows.create({
      url: "data:text/html,<title>about:black</title><body bgcolor=black>",
    }, frame => {
      fuzzerWindow = frame;
      /* Open scanner window. */
      chrome.windows.create({
        url: "data:text/html,<title>about:black</title><body bgcolor=black>",
      }, frame => {
        scannerWindow = frame;
        res();
      });
    });
  });
};

const parseCallbackURLs = async () => {
  return new Promise((res, err) => {
    /* Parse specified callback URLs for open redirects and requests. */
    parsedCallbackURLOpenRedirectTimestamps = parseURL(callbackURLOpenRedirectTimestamps);
    if (parsedCallbackURLOpenRedirectTimestamps[1] === "") {
      console.error("%cfuzzer-open-redirect", consoleCSS,
        "No valid origin was provided in the specified callback URL for open redirect timestamps (" + callbackURLOpenRedirectTimestamps + ").");
      err();
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
      err();
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
    res();
  });
};

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
  /* anchor */
  retval[5] = strippedURL.slice(retval[0].length + retval[1].length + retval[2].length + retval[3].length + retval[4].length);
  return retval;
};

/**
 * Register message listener.
 */
const registerMessageListener = () => {
  chrome.runtime.onMessage.addListener(async (message, sender) => {
    if (
         message.sessionID
      && message.sessionID === sessionID
    ) {
      if (message.timestamp) {
        let callbackURL;
        const date = new Date();
        const timestamp = date.toLocaleDateString() + " " +  date.toLocaleTimeString();
        console.log("Open redirect found at ", timestamp);
        if (parsedCallbackURLOpenRedirectTimestamps[4] !== "") {
          callbackURL = parsedCallbackURLOpenRedirectTimestamps.slice(0, 5).join("") +
            "&timestamp=" + encodeURIComponent(timestamp) +
            parsedCallbackURLOpenRedirectTimestamps[5];
        } else {
          callbackURL = parsedCallbackURLOpenRedirectTimestamps.slice(0, 4).join("") +
            "?timestamp=" + encodeURIComponent(timestamp) +
            parsedCallbackURLOpenRedirectTimestamps[5];
        }
        chrome.tabs.create({
          url: callbackURL,
          windowId: fuzzerWindow.id,
        }, tab => {
          tabWatcherBufferNew.push(tab.id);
          setTimeout(() => {
            removeTab(tab.id);
            // add to callback retry URLs
          }, timeoutCallback);
          fuzzerTabs.push({
            state: "loading",
            id: tab.id,
          });
        });
        console.log("Open redirect found at ", timestamp);
      }
      if (message.message) {
        if (
             message.message === "CALLBACK_FRAME_READYSTATE_COMPLETE"
          || message.message === "FRAME_READYSTATE_COMPLETE"
        ) {
          removeTab(sender.tab.id);
          fuzzerTabs = fuzzerTabs.filter(tab => {
            return tab.id !== sender.tab.id;
          });
          scannerTabs = scannerTabs.filter(tab => {
            return tab.id !== sender.tab.id;
          });
        }
      }
      if (
           message.exploitableURLs
        && message.exploitableURLs.length !== 0
      ) {
        (async () => {
          const filteredURLs = message.exploitableURLs.filter(url => {
            return exploitableURLsBuffer.indexOf(url) === -1;
          });
          exploitableURLsBuffer = exploitableURLsBuffer.concat(filteredURLs);
        })();
      }
      if (
           message.scannableURLs
        && message.scannableURLs.length !== 0
      ) {
        (async () => {
          const filteredURLs = message.scannableURLs.filter(url => {
            return scannableURLs.indexOf(url) === -1;
          });
          scannableURLs = scannableURLs.concat(filteredURLs);
          const chunkedURLs = chunkArray(
            filteredURLs,
            threadCountScanner);
          for (let a = 0; a < chunkedURLs.length; a++) {
            chunkedScannableURLs[a] = chunkedScannableURLs[a].concat(chunkedURLs[a]);
          }
        })();
      }
    }
  });
};

/**
 * Registers webRequest listeners.
 */
const registerWebRequestListeners = () => {
  chrome.webRequest.onErrorOccurred.addListener(
    details => {
      if (details.type === "main_frame") {
        chrome.tabs.get(details.tabId, tab => {
          if (!chrome.runtime.lastError && tab) {
            if (
                 tab.windowId === fuzzerWindow.id
              || tab.windowId === scannerWindow.id
            ) {
              if (!pendingRetryURLs[details.url]) {
                pendingRetryURLs[details.url] = {attempts: 0};
              }
              removeTab(details.tabId);
            }
          }
        });
      }
    },
    {"urls": ["<all_urls>"]},
    [],
  );
//  chrome.webRequest.onHeadersReceived.addListener(
//    details => {
//      if (visitedURLs.indexOf(details.url) === -1) {
//        visitedURLs.push(details.url);
//      }
//    },
//    {"urls": ["<all_urls>"]},
//    ["blocking", "extraHeaders", "responseHeaders"]
//  );
};

/**
 * Returns a promise to remove a tab from fuzzer/scanner window.
 */
const removeTab = async id => {
  return new Promise(res => {
    chrome.tabs.get(id, tab => {
      if (!chrome.runtime.lastError && tab) {
        if (
             tab.windowId === fuzzerWindow.id
          || tab.windowId === scannerWindow.id
        ) {
          chrome.tabs.remove(id);
          res();
        }
      }
    });
  });
};

/**
 * Sleeps an awaited promise value for the given amount of milliseconds.
 */
const sleep = ms => {
  return new Promise(res=>{
    setTimeout(res, ms);
  });
};

/**
 * Starts fuzzing an indefinite amount of potentially vulnerable URLs that are in scope.
 */
const startFuzzerThread = async () => {
  while (injectedURLs.length === 0) {
    await sleep(1000);
  }
  for (let a = 0; a < chunkedInjectedURLs.length; a++) {
    (async () => {
      while (true) {
        const URL = chunkedInjectedURLs[a][0];
        if (URL && URL !== "") {
          chunkedInjectedURLs[a] = chunkedInjectedURLs[a].slice(1);
          openURLInNewFuzzerTab(URL);
        }
        await sleep(getIntFromRange(
          delayRangeFuzzerThread[0],
          delayRangeFuzzerThread[1]));
      }
    })();
  }
};

/**
 * Force-wakes all tabs indefinitely.
 */
const startForceWakeTabsThread = async () => {
  while (true) {
    if (fuzzerTabs.length === 0 && scannerTabs.length === 0) {
      await sleep(delayForceWakeTabsThread);
    }
    for (let a = 0; a < fuzzerTabs.length; a++) {
      chrome.tabs.get(fuzzerTabs[a].id, tab => {
        if (!chrome.runtime.lastError && tab) {
          chrome.tabs.update(tab.id, {
            active: true,
            selected: true,
          });
        }
      });
      await sleep(delayForceWakeTabsThread);
    }
    for (let a = 0; a < scannerTabs.length; a++) {
      chrome.tabs.get(scannerTabs[a].id, tab => {
        if (!chrome.runtime.lastError && tab) {
          chrome.tabs.update(tab.id, {
            active: true,
            selected: true,
          });
        }
      });
      await sleep(delayForceWakeTabsThread);
    }
  }
};

/**
 * Tries to request pending URLs that timed out (for ??????????).
 */
const startPendingRetryURLsThread = async () => {
//  while (true) {
//    pendingRetryURLs.forEach(url => {
//      if (
//            parseURL(url).slice(0, 2)
//        === parseURL(callbackURLOpenRedirectTimestamps).slice(0, 2)
//      ) {
//        openURLInNewTab(url).then(() => {
//          pendingRetryURLs = pendingRetryURLs.filter(_url => {
//            return url !== _url;
//          });
//        });
//      }
//    });
//    await sleep(delayPendingRetryURLsThread);
//  }
};

/**
 * Starts scanning an indefinite amount of URLs that are in scope.
 */
const startScannerThread = async () => {
  for (let a = 0; a < chunkedScannableURLs.length; a++) {
    (async () => {
      while (true) {
        const URL = chunkedScannableURLs[a][0];
        if (URL && URL !== "") {
          chunkedScannableURLs[a] = chunkedScannableURLs[a].slice(1);
          openURLInNewScannerTab(URL);
        }
        await sleep(getIntFromRange(
          delayRangeScannerThread[0],
          delayRangeScannerThread[1]));
      }
    })();
  }
};

/**
 * Starts looking for idle tabs in fuzzer/scanner window and removes them.
 */
const startTabWatcherThread = async () => {
  while (true) {
    for (let a = 0; a < tabWatcherBufferOld.length; a++) {
      chrome.tabs.get(tabWatcherBufferOld[a], tab => {
        if (!chrome.runtime.lastError && tab) {
          chrome.tabs.remove(tabWatcherBufferOld[a]);
        }
      });
    }
    tabWatcherBufferOld = [];
    for (let a = 0; a < tabWatcherBufferNew.length; a++) {
      tabWatcherBufferOld.push(tabWatcherBufferNew[a]);
    }
    tabWatcherBufferNew = [];
    await sleep(delayTabWatcherThread);
  }
};

/**
 * Starts creating injected permutations of an indefinite amount of exploitable URLs.
 */
const startURLInjectionThread = async () => {
  while (exploitableURLsBuffer.length === 0) {
    await sleep(1000);
  }
  while (true) {
    if (exploitableURLsBuffer.length !== 0) {
      let _injectedURLs = [];
      if (exploitableURLs.indexOf(exploitableURLsBuffer[0]) === -1) {
        for (let a = 0; a < redirectURLs.length; a++) {
          const redirectURLVariants = getURLVariants(redirectURLs[a]);
          for (let b = 0; b < redirectURLVariants.length; b++) {
            _injectedURLs = _injectedURLs.concat(
              getInjectedURLPermutations(
                exploitableURLsBuffer[0],
                redirectURLVariants[b]));
          }
        }
        exploitableURLs.push(exploitableURLsBuffer[0]);
      }
      exploitableURLsBuffer = exploitableURLsBuffer.slice(1);
      if (_injectedURLs.length !== 0) {
        _injectedURLs = _injectedURLs.filter((url, index, arr) => {
          return (
               arr.indexOf(url) === index
            && injectedURLs.indexOf(url) === -1);
        });
        injectedURLs = injectedURLs.concat(_injectedURLs);
        const chunkedURLs = chunkArray(
          _injectedURLs,
          threadCountFuzzer);
        for (let a = 0; a < chunkedInjectedURLs.length; a++) {
          chunkedInjectedURLs[a] = chunkedInjectedURLs[a].concat(chunkedURLs[a]);
        }
      }
    }
    await sleep(delayURLInjectionThread);
  }
};

/**
 * Trims all leading and trailing whitespaces off a given string.
 * (example input: " https://example.com/  \n")
 * (example output: "https://example.com/")
 */
const trimWhitespaces = str => {
  return str.replace(/^\s*(.*)\s*$/g, "$1");
};

/**
 * Init background script.
 */
parseCallbackURLs().then(async () => {
  for (let a = 0; a < threadCountFuzzer; a++) {
    chunkedInjectedURLs[a] = [];
  }
  for (let a = 0; a < threadCountScanner; a++) {
    chunkedScannableURLs[a] = [];
  }
  await registerMessageListener();
  await registerWebRequestListeners();
  await openFuzzerAndScannerWindows();
  startForceWakeTabsThread();
  startPendingRetryURLsThread();
  startScannerThread();
  startFuzzerThread();
  startURLInjectionThread();
  startTabWatcherThread();

  openURLInNewScannerTab("https://store.playstation.com/");
});

