/**
 * Background script for fuzzer-open-redirect.
 */

/* User configurable. */
let crawlerScripts = [];
let delayCycleTabFocus = 1000;
let delayRangeRequests = [4000, 30000];
let delayRetryCallbackRequest = 10000;
let delayURLDiscoveryThread = 4000;
let hexEncodingTypes = [
  [0],
  [0,0],
  [1],
  [2],
  [3],
  [4],
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
];
let sessionID = "8230ufjio";
let threads = 4;
let timeoutCallback = 8000;
let timeoutCloseTabs = 8000;
let timeoutRequests = 8000;
let pendingRetryURLAttempts = 6;

const alphabeticalChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
const consoleCSS = "background-color:rgb(80,255,0);text-shadow:0 1px 1px rgba(0,0,0,.3);color:black";
const redirectURLs = [
  "https://runescape.com",
  "https://runescape.com/",
  "https://runescape.com/splash",
  "https://runescape.com/splash?ing"
];
const regexpSelectorEscapableURICharacters = /[^A-Za-z0-9_.!~*'()-]/ig;

let allInjectedURLs = [];
let allInjectedURLsBuffer = [];
let arrayPermutations = [];
let callbackURLOpenRedirectTimestamps = "http://0.0.0.0:4242";
let callbackURLRequestTimestamps = "http://0.0.0.0:4243";
let chunkedPendingURLs = [];
let crawlingTabs = [];
let discoveredExploitableURLs = [];
let discoveredURLs = [];
let pendingRetryURLs = [];
let pendingRequests = [];
let programs = [];
let streamingInjectedURLsBuffer = false;

/**
 * Chunks a given array to a length of a given amount.
 */
const chunkArray = (urls, amountOfChunks) => {
  const chunkSize = Math.ceil(urls.length / threads);
  const chunks = [];
  for (let a = 0; a < amountOfChunks; a++) {
    chunks[a] = urls.slice(chunkSize * a, (chunkSize * a) + chunkSize);
  }
  return chunks;
}

/**
 * An object that contains all the various methods to encode a given URI parameter string.
 */
const encodeMethods = {
  0: encodeURIComponent,
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
  }
}

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
 * Returns an array of all injected permutations of a given URL.
 * (example input: (
 *   "//www.google.com/q=http%3A%2F%2Fgmail%2Ecom%2F",
 *   %2F%2Fmysite%2Ecom%2F",
 * ))
 */
const getInjectedURLPermutations = (targetURL, redirectURL) => {
  const regexp = new RegExp("=(?:http[^&]*|[/][^&]*|%2f[^&]*)", "ig");
  let regexpMatches = [];
  let match;
  while (match = regexp.exec(targetURL)) {
    regexpMatches.push({match: match[0], index: match.index});
  }
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
  arrayPermutations = [];
  return injectedURLs;
}

/**
 * Returns an integer value between a minimum and maximum range of milliseconds.
 */
const getIntFromRange = (min, max) => {
  return parseInt(min + (Math.random() * (max - min)));
}

/**
 * Returns an array of URLs that could lead to the same address as a given URL based on
 * the specified hexEncodingTypes value.
 */
const getURLVariants = url => {
  const parsedURL = parseURL(url);
  const slicedURL = parsedURL.slice(1).join("");
  const protocolVariants = [
    "https://" + slicedURL,
     "http://" + slicedURL,
          "//" + slicedURL,
                 slicedURL
  ];
  let URLVariants = protocolVariants;
  for (let a = 0; a < hexEncodingTypes.length; a++) {
    const hexEncodingTypeSet = hexEncodingTypes[a];
    let encodedURLs = [];
    for (let b = 0; b < protocolVariants.length; b++) {
      let URLVariant = protocolVariants[b];
      for (let c = 0; c < hexEncodingTypeSet.length; c++) {
        URLVariant = encodeMethods[hexEncodingTypeSet[c]](URLVariant);
      }
      encodedURLs.push(URLVariant);
    }
    URLVariants = URLVariants.concat(encodedURLs);
  }
  return URLVariants;
}

/**
 * Opens a given URL in a new tab.
 */
const openURLInNewTab = async url => {
  return new Promise((res, err) => {
    setTimeout(() => {
      if (pendingRetryURLs.indexOf(url) === -1) {
        pendingRetryURLs.push(url);
      }
      err("Request timed out.");
    }, timeoutRequests);
    chrome.tabs.create({url: url}, async tab => {
      pendingRequests.push({
        state: "loading",
        tabId: tab.id,
      });
      crawlingTabs.push(tab);
      // execute crawlerScripts
//      while (false) {
        await sleep(6000);
//      }
      res(tab);
    });
  });
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
  const strippedURL = trimWhitespaces(url);
  const retval = ["","","","","",""];
  /* protocol */
  if (strippedURL.match(/^((?:[a-z0-9.+-]+:)?\/\/).*$/i)) {
    retval[0] = strippedURL.replace(/^((?:[a-z0-9.+-]+:)?\/\/).*$/i, "$1");
  }
  /* host */
  if (strippedURL.match(/^(?:(?:(?:[a-z0-9.+-]+:)?\/\/)((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{1,63})|[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})(?:[:][1-9][0-9]{0,4})?)(?:[/][^/].*$|[/]$|[?#].*$|$)/i)) {
    retval[1] = strippedURL.replace(/^(?:(?:(?:[a-z0-9.+-]+:)?\/\/)((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{1,63})|[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})(?:[:][1-9][0-9]{0,4})?)(?:[/][^/].*$|[/]$|[?#].*$|$)/i, "$1");
  }
  /* port */
  if (strippedURL.match(/^(?:(?:(?:[a-z0-9.+-]+:)?\/\/)?(?:(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{1,63})|[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}))([:][1-9][0-9]{0,4}).*/i)) {
    retval[2] = strippedURL.replace(/^(?:(?:(?:[a-z0-9.+-]+:)?\/\/)?(?:(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{1,63})|[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}))([:][1-9][0-9]{0,4}).*$/i, "$1");
  }
  /* path */
  if (strippedURL.match(/^(?:(?:[a-z0-9.+-]+:)?\/\/(?:(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{1,63})|[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})(?:[:][1-9][0-9]{0,4})?)?([/][^?#]*).*/i)) {
    retval[3] = strippedURL.replace(/^(?:(?:[a-z0-9.+-]+:)?\/\/)?[^/?#]*([/][^?#]*).*$/i, "$1");
  }
  /* search */
  if (strippedURL.match(/^.*?([?][^#]*).*$/i)) {
    retval[4] = strippedURL.replace(/^.*?([?][^#]*).*$/i, "$1");
  }
  /* anchor */
  if (strippedURL.match(/^[^#]*?([#].*)/i)) {
    retval[5] = strippedURL.replace(/^[^#]*?([#].*)/i, "$1");
  }
  return retval;
}

/**
 * Register message listeners.
 */
const registerMessageListeners = () => {
  chrome.runtime.onMessage.addListener(async (message, sender, callback) => {
    if (
         message.sessionID
      && message.sessionID === sessionID
    ) {
      if (message.timestamp) {
        loadURL(callbackURLOpenRedirectTimestamps);
      }
      if (
           message.discoveredExploitableURLs
        && message.discoveredExploitableURLs.length !== 0
      ) {
        while (streamingInjectedURLsBuffer) {
          await sleep(1000);
        }
        const filteredDiscoveredURLs = message.discoveredExploitableURLs
          .filter((url, index, arr) => {
            return (
                 arr.indexOf(url) === index
              && discoveredExploitableURLs.indexOf(url) === -1);
          });
        discoveredExploitableURLs = discoveredExploitableURLs.concat(
          filteredDiscoveredURLs);
        let injectedURLs = [];
        for (let a = 0; a < redirectURLs.length; a++) {
          const redirectURLVariants = getURLVariants(redirectURLs[a]);
          for (let b = 0; b < redirectURLVariants.length; b++) {
            for (let c = 0; c < filteredDiscoveredURLs.length; c++) {
              injectedURLs = injectedURLs.concat(
                getInjectedURLPermutations(
                  filteredDiscoveredURLs[c],
                  redirectURLVariants[b]));
            }
          }
        }
        allInjectedURLsBuffer = allInjectedURLsBuffer.concat(injectedURLs);
      }
    }
  });
}

/**
 * Registers webRequest listeners.
 */
const registerWebRequestListeners = () => {
  chrome.webRequest.onErrorOccurred.addListener(
    details => {
      if (details.type === "main_frame") {
        if (pendingRetryURLs.indexOf(details.url) === -1) {
          pendingRetryURLs.push(details.url);
          chrome.tabs.remove(details.tabId);
        }
      }
    },
    {"urls": ["<all_urls>"]},
    [],
  );
  chrome.webRequest.onHeadersReceived.addListener(
    details => {
      details.responseHeaders.forEach(header => {
        if (header.name.toLowerCase() === "content-type") {
          if (
               header.value.toLowerCase().indexOf("text/html") !== -1
            || header.value.toLowerCase().indexOf("image/svg+xml") !== -1
          ) {

          }
        }
      });
      return {
        responseHeaders: details.responseHeaders
      };
    },
    {"urls": ["<all_urls>"]},
    ["blocking", "extraHeaders", "responseHeaders"]
  )
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
 * Starts crawling an indefinite amount of potentially vulnerable URLs.
 */
const startCrawlerThread = async () => {
  const chunkedInjectedURLs = chunkArray(allInjectedURLs, threads);
  for (let a = 0; a < chunkedInjectedURLs.length; a++) {
    (async () => {
      
      await sleep(getIntFromRange(
        delayRangeRequests[0],
        delayRangeRequests[1]));
    })();
  }
}

/**
 * Force-wakes all tabs indefinitely.
 */
const startForceWakeTabsThread = async () => {
  chrome.tabs.query({}, async tabs => {
    for (let a = 0; a < tabs.length; a++) {
      chrome.tabs.update(tabs[a].id, {
        active: true,
        selected: true,
      });
      await sleep(delayCycleTabFocus);
    }
    startForceWakeTabsThread();
  });
}

/**
 * Tries to request pending URLs that timed out (for ??????????).
 */
const startPendingRetryURLsThread = async () => {
  while (true) {
    pendingRetryURLs.forEach(url => {
      if (
            parseURL(url).slice(0, 2)
        === parseURL(callbackURLOpenRedirectTimestamps).slice(0, 2)
      ) {
        loadURL(url).then(() => {
          pendingRetryURLs = pendingRetryURLs.filter(_url => {
            return url !== _url;
          });
        });
      }
    });
    await sleep(delayRetryCallbackRequest);
  }
}

/**
 * Filters newly discovered URLs and adds them as pending URLs indefinitely.
 */
const startURLDiscoveryThread = async () => {
  streamingInjectedURLsBuffer = true;
  const newInjectedURLs = allInjectedURLsBuffer.filter(url => {
    return allInjectedURLs.indexOf(url) === -1;
  });
  allInjectedURLsBuffer = [];
  allInjectedURLs = allInjectedURLs.concat(newInjectedURLs);
  const chunkedInjectedURLsBuffer = chunkArray(
    newInjectedURLs,
    chunkedPendingURLs.length);
  for (let a = 0; a < chunkedPendingURLs.length; a++) {
    chunkedPendingURLs[a] = chunkedPendingURLs[a].concat(chunkedInjectedURLsBuffer[a]);
  }
  streamingInjectedURLsBuffer = false;
  await sleep(delayURLDiscoveryThread);
  startURLDiscoveryThread();
}

/**
 * Trims all leading and trailing whitespaces off a given string.
 * (example input: " https://example.com/  \n")
 * (example output: "https://example.com/")
 */
const trimWhitespaces = str => {
  return str.replace(/^\s*(.*)\s*$/g, "$1");
}

/**
 * Init background script.
 */
(async () => {
  await registerMessageListeners();
  await registerWebRequestListeners();
//  startForceWakeTabsThread();
  startPendingRetryURLsThread();
  startURLDiscoveryThread();
  startCrawlerThread();
})();

