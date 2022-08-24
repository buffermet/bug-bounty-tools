/**
 * Background script for fuzzer-open-redirect.
 */

"use strict";

// (()=>{
let localStorage = {};

const alphabeticalChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
const consoleCSS = "background-color:rgb(80,255,0);text-shadow:0 1px 1px rgba(0,0,0,.3);color:black";
const dataURIAnchor = "data:text/html,<title>about:black</title><body bgcolor=black>";

const regexpSelectorLeadingAndTrailingWhitespace = /^\s*(.*)\s*$/g;
const regexpSelectorURLHost = /^((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.){1,63}(?:[a-z]{1,63})|(?:25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1-9]?[0-9])\.(?:25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1-9]?[0-9])\.(?:25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1-9]?[0-9])\.(?:25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1-9]?[0-9]))?.*$/i;
const regexpSelectorURLPath = /^([^?#]{1,2048})?.*$/i;
const regexpSelectorURLPort = /^([:](?:6553[0-5]|655[0-2][0-9]|65[0-4][0-9][0-9]|6[0-4][0-9][0-9][0-9]|[0-5][0-9][0-9][0-9][0-9]|[1-9][0-9]{0,3}))?.*$/i;
const regexpSelectorURLProtocol = /^((?:[a-z0-9.+-]{1,256}[:])(?:[/][/])?|(?:[a-z0-9.+-]{1,256}[:])?[/][/])?.*$/i;
const regexpSelectorURLSearch = /^([?][^#]{0,2048})?.*$/i;
const regexpSelectorWildcardStatusCode = /[*]/g;

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
 * Returns the current timestamp.
 */
const getTimestamp = () => {
  const date = new Date();
  return date.toLocaleDateString() + " " + date.toLocaleTimeString();
};

/**
 * Returns true if a given status code string matches the specified
 * fail status code specifiers.
 */
const isFailStatusCode = (session, statusCodeString) => {
  for (let a = 0; a < session.statusCodesFail.length; a++) {
    const selector = new RegExp("^" + session.statusCodesFail[a].replace(regexpSelectorWildcardStatusCode, "[0-9]+") + "$");
    if (selector.test(statusCodeString)) {
      return true;
    }
  }
  return false;
};

/**
 * Returns the local storage object pointer.
 */
const loadStorage = async () => {
  return new Promise(async res => {
    chrome.storage.local.get(s => res(s));
  });
};

/**
 * Returns an integer value between a minimum and maximum range of milliseconds.
 */
const newIntFromRange = (min, max) => {
  return parseInt(min + (Math.random() * (max - min)));
};

/**
 * Returns a new session object with default configuration.
 */
const newSession = (redirectURLs, scope) => {
  return {
    callbackURLOpenRedirectTimestamps: null,
    callbackURLRequestTimestamps: null,
    contentScriptConfig: {
      bufferLengthURLs: 80,
      delayThrottleAutoScrollNode: 10,
      delayThrottleRegexpSearch: 10,
      delayThrottleURLIndexing: 10,
      scanOutOfScopeOrigins: false,
    },
    crawlerScripts: [],
    delayForceWakeTabsThread: 1000,
    delayRangeRequests: [6000, 8000],
    delayTabRemovalThread: 300000,
    isFuzzerThreadPaused: false,
    isScannerThreadPaused: false,
    limitOfTabs: 10,
    redirectURLs: [],
    requestPriorities: [
      0, /* injected redirect parameter */
      2, /* any injected parameter */
      1, /* injected path */
      3, /* scan */
    ],
    retryAttempts: 6,
    statusCodesFail: ["4*", "5*"],
    injectedParameterURLsQueue: [],
    injectedPathURLsQueue: [],
    injectedRedirectParameterURLsQueue: [],
    parsedCallbackURLOpenRedirectTimestamps: null,
    parsedCallbackURLRequestTimestamps: null,
    pendingRetryURLs: {},
    pendingRetryCallbackURLs: {},
    scannableURLs: [],
    scannableURLsQueue: [],
    workerPointer: null,
    sessionId: randomString(newIntFromRange(8, 16)),
    tabAnchorId: null,
    tabIds: [],
    tabRemovalBuffer: [],
    threadCount: 2,
    timeoutCallback: 40000,
    timeoutRequests: 40000,
    windowId: null,
    workerConfig: {
      bufferLengthURLs: 30,
      delayThrottleURLIndexing: 10,
      delayThrottleURLPathInjection: 100,
      delayURLInjectionThread: 2000,
      delayURLScannerThread: 2000,
      encodingTypes: [
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
      ],
      encodedRedirectURLVariants: [],
      injectedRedirectParameterURLs: [],
      injectedParameterURLs: [],
      injectedPathURLs: [],
      injectableParameterURLs: [],
      injectableParameterURLsBuffer: [],
      injectablePathURLs: [],
      injectablePathURLsBuffer: [],
      matchSetPermutations: [],
      redirectURLs: [],
      redirectURLsForPathExploitation: [],
      scannableURLs: [],
      scannableURLsBuffer: [],
      threadCount: null,
    },
  };
};

/**
 * Opens a UI window of a given type.
 */
const openUI = async uiType => {
  return new Promise(res => {
    switch (uiType) {
      case "welcome":
        chrome.windows.create({
          width: 450,
          height: 230,
          type: "popup",
          url: chrome.runtime.getURL("/assets/html/welcome.html"),
        });
        break;
      case "load":
        chrome.windows.create({
          width: 600,
          height: 300,
          type: "popup",
          url: chrome.runtime.getURL("/assets/html/load.html"),
        });
        break;
    }
  });
};

/**
 * Opens a given URL in a new scanner tab.
 */
const openURLInNewTab = async (session, url) => {
  return new Promise(async (res, err) => {
    chrome.tabs.create({
      url: url,
      windowId: session.windowId,
    }, tab => {
      session.tabIds.push(tab.id);
      // execute crawlerScripts
      res(tab);
    });
  });
};

/**
 * Opens new windows for fuzzing and scanning.
 */
const openWindow = async session => {
  return new Promise((res, err) => {
    chrome.windows.create({
      url: dataURIAnchor,
    }, w => {
      chrome.tabs.query({}, tabs => {
        tabs.forEach(tab => {
          if (tab.windowId === w.id) {
            session.tabAnchorId = tab.id;
          }
        });
      });
      session.windowId = w.id;
      res();
    });
  });
};

/**
 * 
 */
const parseCallbackURLs = async session => {
  return new Promise((res, err) => {
    /* Parse specified callback URLs for open redirects and requests. */
    session.parsedCallbackURLOpenRedirectTimestamps = parseURL(session.callbackURLOpenRedirectTimestamps);
    if (session.parsedCallbackURLOpenRedirectTimestamps[1] === "") {
      console.error("%cfuzzer-open-redirect", consoleCSS,
        "No valid origin was provided in the specified callback URL for open redirect timestamps (" + session.callbackURLOpenRedirectTimestamps + ").");
      err();
    }
    if (session.parsedCallbackURLOpenRedirectTimestamps[0] === "") {
      console.warn("%cfuzzer-open-redirect", consoleCSS,
        "No protocol was provided in the specified callback URL for open redirect timestamps (" + session.callbackURLOpenRedirectTimestamps + ").",
        "Defaulting to \"http://\".");
      session.parsedCallbackURLOpenRedirectTimestamps[0] = "http://";
    }
    console.log("%cfuzzer-open-redirect", consoleCSS,
      "Callback URL for open redirect timestamps is parsed: " +
      session.parsedCallbackURLOpenRedirectTimestamps.join(""));
    session.parsedCallbackURLRequestTimestamps = parseURL(callbackURLRequestTimestamps);
    if (session.parsedCallbackURLRequestTimestamps[1] === "") {
      console.error("%cfuzzer-open-redirect", consoleCSS,
        "No valid origin was provided in the specified callback URL for request timestamps (" + session.callbackURLOpenRedirectTimestamps + ").");
      err();
    }
    if (session.parsedCallbackURLRequestTimestamps[0] === "") {
      console.warn("%cfuzzer-open-redirect", consoleCSS,
        "No protocol was provided in the specified callback URL for request timestamps (" + session.callbackURLOpenRedirectTimestamps + ").",
        "Defaulting to \"http://\".");
      session.parsedCallbackURLRequestTimestamps[0] = "http://";
    }
    console.log("%cfuzzer-open-redirect", consoleCSS,
      "Callback URL for request timestamps is parsed: " +
      session.parsedCallbackURLRequestTimestamps.join(""));
    res();
  });
};

/**
 * Returns an array containing the protocol, host, port, path,
 * search and hash of a given URL if found.
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
  const strippedURL = trimLeadingAndTrailingWhitespaces(url);
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
 * Returns a pseudorandom alphabetical string of a given length.
 */
const randomString = length => {
  let buffer = [];
  for (let a = 0; a < length; a++) {
    const index = Math.floor(Math.random() * alphabeticalChars.length);
    buffer.push(alphabeticalChars[index]);
  }
  return buffer.join("");
};

/**
 * Register message listener.
 */
const registerMessageListener = session => {
  chrome.runtime.onMessage.addListener(async (message, sender) => {
console.log(message)
    if (message.sessionId) {
      if (session.sessionId === message.sessionId) {
        if (
             message.injectableParameterURLs
          || message.scannableURLs
        ) {
          session.workerPointer.postMessage(message);
        }
        if (message.timestamp) {
          console.log("Open redirect found at ", message.timestamp);
          sendCallback(message.timestamp, "", "OPEN_REDIRECT_CALLBACK");
        }
        if (message.message) {
          switch (message.message) {
            case "FRAME_READYSTATE_COMPLETE":
              removeTab(sender.tab.id);
              session.tabIds = session.tabIds.filter(tab => {
                return tab.id !== sender.tab.id;
              });
              break;
            case "FRAME_REQUEST_CONTENT_SCRIPT_CONFIG":
              chrome.tabs.sendMessage(
                sender.tab.id,
                {sessionConfig: session.contentScriptConfig});
              break;
          }
        }
      }
    } else {
      // no message.sessionId declared
    }
  });
  session.workerPointer.onmessage = message => {
//    if (message.data.retryCallbackURL) {
//    }
    if (message.data.appendage) {
      if (message.data.appendage.injectedParameterURLsQueue) {
        session.injectedParameterURLsQueue = session.injectedParameterURLsQueue.concat(
          message.data.appendage.injectedParameterURLsQueue);
      }
      if (message.data.appendage.injectedPathURLsQueue) {
        session.injectedPathURLsQueue = session.injectedPathURLsQueue.concat(
          message.data.appendage.injectedPathURLsQueue);
      }
      if (message.data.appendage.injectedRedirectParameterURLsQueue) {
        session.injectedRedirectParameterURLsQueue = session.injectedRedirectParameterURLsQueue.concat(
          message.data.appendage.injectedRedirectParameterURLsQueue);
      }
      if (message.data.appendage.scannableURLsQueue) {
        session.scannableURLsQueue = session.scannableURLsQueue.concat(
          message.data.appendage.scannableURLsQueue);
      }
    }
  };
};

/**
 * Registers webRequest listeners.
 */
const registerWebRequestListeners = session => {
  chrome.webRequest.onErrorOccurred.addListener(
    details => {
      if (details.type === "main_frame") {
        chrome.tabs.get(details.tabId, tab => {
          if (!chrome.runtime.lastError && tab && tab.windowId === windowId) {
            removeTab(details.tabId);
            if (!session.pendingRetryURLs[details.url]) {
              session.pendingRetryURLs[details.url] = {attempts: 0};
            }
          }
        });
      }
    },
    {"urls": ["<all_urls>"]},
    []);
  chrome.webRequest.onHeadersReceived.addListener(
    details => {
      if (isFailStatusCode(session, details.statusCode.toString())) {
        if (!session.pendingRetryURLs[details.url]) {
          session.pendingRetryURLs[details.url] = {attempts: 0};
        }
      }
    },
    {"urls": ["<all_urls>"]},
    []);
};

/**
 * Returns a promise to remove a tab with the specified ID.
 */
const removeTab = async (session, tabId) => {
  return new Promise(res => {
    chrome.tabs.get(tabId, tab => {
      if (!chrome.runtime.lastError && tab) {
        if (tab.windowId === session.windowId) {
          chrome.tabs.remove(tabId);
          res();
        }
      }
    });
  });
};

/**
 * Resumes a session with a given ID.
 */
const resumeSession = async session => {
  return new Promise(async (res, err) => {
    session.workerPointer = new Worker(chrome.runtime.getURL("/assets/js/worker.js"));
    session.workerPointer.postMessage({sessionConfig: session.workerConfig});
    registerMessageListener(session);
    registerWebRequestListeners(session);
    await openWindow(session);
    startForceWakeTabsThread(session);
    startPendingRetryURLsThread(session);
    startRequestThread(session);
    startTabRemovalThread(session);
    openURLInNewTab(session, "https://store.playstation.com/");
  });
};

/**
 * Sends a callback at a given timestamp for a given type.
 * (example input: ("03/12/2020 01:06:05", "...", "OPEN_REDIRECT_CALLBACK"))
 * (example input: ("03/12/2020 01:06:05", "...", "REQUEST_CALLBACK"))
 */
const sendCallback = async (timestamp, url, callbackType) => {
  return new Promise((res, err) => {
    let callbackURL = "";
    switch (callbackType) {
      case "OPEN_REDIRECT_CALLBACK":
        if (parsedCallbackURLOpenRedirectTimestamps[4] !== "") {
          callbackURL = parsedCallbackURLOpenRedirectTimestamps.slice(0, 5).join("") +
            "&timestamp=" + encodeURIComponent(timestamp) +
            "&url=" + encodeURIComponent(url) +
            parsedCallbackURLOpenRedirectTimestamps[5];
        } else {
          callbackURL = parsedCallbackURLOpenRedirectTimestamps.slice(0, 4).join("") +
            "?timestamp=" + encodeURIComponent(timestamp) +
            "&url=" + encodeURIComponent(url) +
            parsedCallbackURLOpenRedirectTimestamps[5];
        }
        break;
      case "REQUEST_CALLBACK":
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
        break;
    }
    if (callbackURL.length !== 0) {
      fetch(callbackURL).then(_res => {
        if (!_res.ok) {
          if (!pendingRetryCallbackURLs[callbackURL]) {
            pendingRetryCallbackURLs[callbackURL] = {attempts: 0};
          }
        }
        res();
      }).catch(e => {
        err(e);
      });
    } else {
      err("Unable to create callback URL, " + "\n" +
        "timestamp: " + timestamp + "\n" +
        "callback type: " + callbackType + "\n" +
        "callback URLs: " + callbackURLRequestTimestamps +
          ", " + session.callbackURLOpenRedirectTimestamps);
    }
  });
};

/**
 * Sleeps an awaited promise value for the given amount of milliseconds.
 */
const sleep = ms => {
  return new Promise(res => {
    setTimeout(res, ms);
  });
};

/**
 * Force-wakes all tabs indefinitely.
 */
const startForceWakeTabsThread = async session => {
  while (true) {
    if (session.tabIds.length === 0) {
      await sleep(session.delayForceWakeTabsThread);
    }
    for (let a = 0; a < session.tabIds.length; a++) {
      chrome.tabs.get(session.tabIds[a], tab => {
        if (!chrome.runtime.lastError && tab) {
          chrome.tabs.update(tab.id, {
            active: true,
            selected: true,
          }, () => {});
        } else {
          session.tabIds = session.tabIds.filter(id => {
            return id !== session.tabIds[a];
          });
        }
      });
      await sleep(session.delayForceWakeTabsThread);
    }
  }
};

/**
 * Tries to request pending URLs that timed out.
 */
const startPendingRetryURLsThread = async () => {
//  while (true) {
//    pendingRetryURLs.forEach(url => {
//      if (
//            parseURL(url).slice(0, 2)
//        === parseURL(session.callbackURLOpenRedirectTimestamps).slice(0, 2)
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
 * Starts requesting an indefinite amount of injected URLs of a given
 * session.
 */
const startRequestThread = async session => {
  for (let a = 0; a < session.threadCount; a++) {
    (async () => {
      while (true) {
        while (session.tabIds.length >= session.limitOfTabs) {
          await sleep(300);
        }
        let URL = "";
        for (let b = 0; b < session.requestPriorities.length; b++) {
          if (URL.length !== 0) {
            break;
          }
          switch (session.requestPriorities[b]) {
            case 0:  /* injected redirect parameter */
              if (session.injectedRedirectParameterURLsQueue.length !== 0) {
                URL = session.injectedRedirectParameterURLsQueue[0];
                session.injectedRedirectParameterURLsQueue = session.injectedRedirectParameterURLsQueue.slice(1);
              }
              break;
            case 1:  /* injected path */
              if (session.injectedPathURLsQueue.length !== 0) {
                URL = session.injectedPathURLsQueue[0];
                session.injectedPathURLsQueue = session.injectedPathURLsQueue.slice(1);
              }
              break;
            case 2:  /* any injected parameter */
              if (session.injectedParameterURLsQueue.length !== 0) {
                URL = session.injectedParameterURLsQueue[0];
                session.injectedParameterURLsQueue = session.injectedParameterURLsQueue.slice(1);
              }
              break;
            case 3:  /* scan */
              if (session.scannableURLsQueue.length !== 0) {
                URL = session.scannableURLsQueue[0];
                session.scannableURLsQueue = session.scannableURLsQueue.slice(1);
              }
              break;
          }
        }
        if (URL.length !== 0) {
          sendCallback(getTimestamp(), URL, "REQUEST_CALLBACK");
          openURLInNewTab(URL);

        }
        await sleep(newIntFromRange(
          session.delayRangeRequests[0],
          session.delayRangeRequests[1]));
      }
    })();
  }
};

/**
 * Starts looking for seemingly idle tabs and removes them.
 */
const startTabRemovalThread = async session => {
  while (true) {
    chrome.tabs.query({}, tabs => {
      tabs.forEach(tab => {
        if (
             tab.windowId === session.windowId
          && tab.id !== session.tabAnchorId
        ) {
          if (session.tabRemovalBuffer.indexOf(tab.id) === -1) {
            session.tabRemovalBuffer.push(tab.id);
          } else {
console.log("removing tab:", tab.id)
            removeTab(tab.id);
            session.tabRemovalBuffer = session.tabRemovalBuffer.filter(id => {
              return id !== tab.id;
            });
          }
        }
      });
    });
    await sleep(session.delayTabRemovalThread);
  }
};

/**
 * Trims all leading and trailing whitespaces off a given string.
 * (example input: " https://example.com/  \n")
 * (example output: "https://example.com/")
 */
const trimLeadingAndTrailingWhitespaces = str => {
  return str.replace(regexpSelectorLeadingAndTrailingWhitespace, "$1");
};

/**
 * Overwrites the localStorage as Chrome's local storage object.
 */
const writeStorage = async () => {
  return new Promise(res => {
    if (localStorage) {
      chrome.storage.local.set(localStorage, res);
    }
  });
};

/**
 * Init background script.
 */
(async()=>{
  localStorage = await loadStorage();
  // openUI("welcome");

  const session = newSession();
    // [
    //   "https://runescape.com",
    //   "https://runescape.com/",
    //   "https://runescape.com/splash",
    //   "https://runescape.com/splash?ing",
    //   "http://runescape.com",
    //   "http://runescape.com/",
    //   "http://runescape.com/splash",
    //   "http://runescape.com/splash?ing",
    //   "//runescape.com",
    //   "//runescape.com/",
    //   "//runescape.com/splash",
    //   "//runescape.com/splash?ing",
    //   "runescape.com",
    //   "runescape.com/",
    //   "runescape.com/splash",
    //   "runescape.com/splash?ing",
    //   "data:text/html,<script>location='https://runescape.com'</script>",
    //   "data:text/html,base64,PHNjcmlwdD5sb2NhdGlvbj0naHR0cHM6Ly9ydW5lc2NhcGUuY29tJzwvc2NyaXB0Pg",
    //   "javascript:location='https://runescape.com'",
    //   "javascript:location='//runescape.com'",
    // ],
    // [
    //   "*://*.playstation.net",
    //   "*://*.sonyentertainmentnetwork.com",
    //   "*://*.api.playstation.com",
    //   "*://my.playstation.com",
    //   "*://store.playstation.com",
    //   "*://social.playstation.com",
    //   "*://transact.playstation.com",
    //   "*://wallets.playstation.com",
    //   "*://direct.playstation.com",
    //   "*://api.direct.playstation.com",
    // ]
  session.callbackURLOpenRedirectTimestamps = "http://0.0.0.0:4242";
  session.callbackURLRequestTimestamps = "http://0.0.0.0:4243";
  resumeSession(session);
  globalThis.debugSession = session;
})();
// })();
