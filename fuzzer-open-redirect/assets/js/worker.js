/**
 * Web worker for fuzzer-open-redirect.
 */

import url from "./url.mjs"

let localStorage = {
	injectableParameterURLs: [],
	injectableParameterURLsBuffer: [],
	injectablePathURLs: [],
	injectablePathURLsBuffer: [],
	injectableRedirectParameterURLs: [],
	injectableRedirectParameterURLsBuffer: [],
	injectedParameterURLs: [],
	injectedParameterURLsRequestQueue: [],
	injectedPathURLs: [],
	injectedPathURLsRequestQueue: [],
	injectedRedirectParameterURLs: [],
	injectedRedirectParameterURLsRequestQueue: [],
	pendingRetryCallbackURLs: [],
	pendingRetryURLs: [],
	requestedURLs: [],
	scannableURLs: [],
	scannableURLsBuffer: [],
	scannableURLsRequestQueue: [],
};

let bufferLengthURLs = 80;
let delayURLIndexing = 10;
let delayURLInjectionThread = 2000;
let delayURLPathInjection = 100;
let delayURLScannerThread = 2000;
let delayURLThread = 10;
let encodingTypes = [
	[0],
	[1],
	[4],
	[6],
	[8],
	[10],
	[12],
	[15],
	[16],
	[17],
	[18],
];
let encodedRedirectURLVariants = [];
let injectableParameterURLsBuffer = [];
let injectablePathURLsBuffer = [];
let injectableRedirectParameterURLsBuffer = [];
let injectedRedirectParameterURLs = [];
let injectedParameterURLs = [];
let injectedPathURLs = [];
let matchSetPermutations = [];
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
let redirectURLsForPathExploitation = [];
let scannableURLs = [];
let scannableURLsBuffer = [];
let threadCount;
let urlPriorities = [
	2, /* injected redirect parameter */
	1, /* injected path */
	0, /* injected parameter */
	3, /* scan */
];

const alphabeticalChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
const regexpSelectorEncodableURICharacters = /[^A-Za-z0-9_.!~*'()-]/ig;
const regexpSelectorLeadingAndTrailingWhitespace = /^\s*(.*)\s*$/g;
const regexpSelectorURLHost = /^((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.){1,63}(?:[a-z]{1,63})|(?:25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1-9]?[0-9])\.(?:25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1-9]?[0-9])\.(?:25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1-9]?[0-9])\.(?:25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1-9]?[0-9]))?.*$/i;
const regexpSelectorURLParameterValue = /=[^&=#]*/g;
const regexpSelectorURLPath = /^([^?#]{1,2048})?.*$/i;
const regexpSelectorURLPathDirectory = /[/][^/]*/g;
const regexpSelectorURLPort = /^([:](?:6553[0-5]|655[0-2][0-9]|65[0-4][0-9][0-9]|6[0-4][0-9][0-9][0-9]|[0-5][0-9][0-9][0-9][0-9]|[1-9][0-9]{0,3}))?.*$/i;
const regexpSelectorURLProtocol = /^((?:[a-z0-9.+-]{1,256}[:])(?:[/][/])?|(?:[a-z0-9.+-]{1,256}[:])?[/][/])?.*$/i;
const regexpSelectorURLRedirectParameter = /^[=](?:http|%68%74%74%70|[/]|[?]|%[23]f|%23|[.]{1,2}[/]|(?:%2e){1,2}%2f)/i;
const regexpSelectorURLSearch = /^([?][^#]{0,2048})?.*$/i;

/**
 * Buffered and throttled method that returns the index of the given
 * target value in a given array.
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
 * Returns an array of URLs that are encoded as per the specified
 * encodingTypes value.
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
 * Returns an array of all injected parameter permutations of a given URL.
 * (example input: (
 *   "//www.google.com/?a=1&b=2",
 *   %2F%2Fmysite%2Ecom%2F",
 * ))
 */
const getInjectedURLParameterPermutations = async (targetURL, redirectURL) => {
	const parsedURL = parseURL(targetURL);
	if (parsedURL[4].length === 0) {
		console.error("URL contains no search:", targetURL);
		return [];
	}
	const injectableURLs = [];
	let match;
	while (match = regexpSelectorURLParameterValue.exec(parsedURL[4])) {
		injectableURLs.push({
			index: match.index,
			match: match[0],
		});
	}
	/* Inject all URL parameters. */
	matchSetPermutations = [];
	getArrayPermutations([], injectableURLs);
postMessage({debug: ['matchSetPermutations', matchSetPermutations]})
	const newInjectedParameterURLs = [];
	for (let a = 0; a < matchSetPermutations.length; a++) {
		let matchSets = matchSetPermutations[a];
		let injectedSearch = parsedURL[4];
		for (let b = 0; b < matchSets.length; b++) {
			const matchSet = matchSets[b];
			const lengthLeadingMatches = matchSets.slice(0, b)
				.map(set => set.match).join("").length;
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
	return newInjectedParameterURLs;
};

/**
 * Returns an array of all injected redirect parameter permutations of a given URL.
 * (example input: (
 *   "//www.google.com/?q=http%3A%2F%2Fgmail%2Ecom%2F",
 *   %2F%2Fmysite%2Ecom%2F",
 * ))
 */
const getInjectedURLRedirectParameterPermutations = async (targetURL, redirectURL) => {
	const parsedURL = parseURL(targetURL);
	if (parsedURL[4].length === 0) {
		console.error("URL contains no search:", targetURL);
		return [];
	}
	const injectableURLs = [];
	let match;
	while (match = regexpSelectorURLParameterValue.exec(parsedURL[4])) {
		if (regexpSelectorURLRedirectParameter.test(match[0])) {
			injectableURLs.push({
				index: match.index,
				match: match[0],
			});
		}
	}
	/* Inject redirect URL parameters. */
	matchSetPermutations = [];
	getArrayPermutations([], injectableURLs);
postMessage({debug: ['matchSetPermutations', matchSetPermutations]})
	const injectedURLs = [];
	for (let a = 0; a < matchSetPermutations.length; a++) {
		let matchSets = matchSetPermutations[a];
		let injectedSearch = parsedURL[4];
		for (let b = 0; b < matchSets.length; b++) {
			const matchSet = matchSets[b];
			const lengthLeadingMatches = matchSets.slice(0, b)
				.map(set => set.match).join("").length;
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
		injectedURLs.push(injectedURL);
	}
	return injectedURLs;
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
 * Creates a filtered array of redirect URLs that can be used to
 * exploit paths.
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
			if (message.data.localStorage) {
				localStorage = message.data.localStorage;
			}
			if (
				   message.data.injectableParameterURLs
				&& message.data.injectableParameterURLs.length !== 0
			) {
				injectableParameterURLsBuffer = injectableParameterURLsBuffer.concat(
					message.data.injectableParameterURLs);
			}
			if (
				   message.data.injectableRedirectParameterURLs
				&& message.data.injectableRedirectParameterURLs.length !== 0
			) {
				injectableParameterURLsBuffer = injectableParameterURLsBuffer.concat(
					message.data.injectableRedirectParameterURLs);
				injectableRedirectParameterURLsBuffer =
					injectableRedirectParameterURLsBuffer.concat(
						message.data.injectableRedirectParameterURLs);
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
const shiftURLParameterInjectionBuffer = async () => {
	return new Promise(async res => {
		if (injectableParameterURLsBuffer.length !== 0) {
			/* Filter already discovered URLs that have injectable parameters. */
			while (
				bufferedIndexOf(
					localStorage.injectableParameterURLs,
					injectableParameterURLsBuffer[0],
					bufferLengthURLs,
					delayURLIndexing) !== -1
			) {
				injectableParameterURLsBuffer.shift();
				postMessage({
					shift: "injectableParameterURLsBuffer"
				});
				await sleep(delayURLThread);
			}
			let newInjectedParameterURLs = [];
			if (injectableParameterURLsBuffer.length !== 0) {
				const newExploitableURL = injectableParameterURLsBuffer[0];
				localStorage.injectableParameterURLs.push(newExploitableURL);
				postMessage({
					appendage: {
						injectableParameterURLs: newExploitableURL
					}
				});
				injectableParameterURLsBuffer.shift();
				postMessage({
					shift: "injectableParameterURLsBuffer"
				});
				/* Generate all permutations of injected parameters. */
				let amountOfChunks = Math.ceil(
					encodedRedirectURLVariants.length / bufferLengthURLs);
				for (let a = 0; a < amountOfChunks; a++) {
					for (
						let b = a * bufferLengthURLs;
						   b < encodedRedirectURLVariants.length
						&& b < (a * bufferLengthURLs) + bufferLengthURLs - 1;
						b++
					) {
						const injectedPermutations = await getInjectedURLParameterPermutations(
							newExploitableURL,
							encodedRedirectURLVariants[b]);
						newInjectedParameterURLs = newInjectedParameterURLs.concat(
							injectedPermutations.newInjectedParameterURLs);
					}
					await sleep(delayURLIndexing);
				}
				/* Filter already injected URLs before shipping to background. */
				let filteredNewInjectedParameterURLs = [];
				for (let a = 0; a < newInjectedParameterURLs.length; a++) {
					if (
						   await bufferedIndexOf(
							filteredNewInjectedParameterURLs,
							newInjectedParameterURLs[a],
							bufferLengthURLs,
							delayURLIndexing) === -1
						&& await bufferedIndexOf(
							injectedParameterURLs,
							newInjectedParameterURLs[a],
							bufferLengthURLs,
							delayURLIndexing) === -1
					) {
						filteredNewInjectedParameterURLs.push(
							newInjectedParameterURLs[a]);
					}
				}
				/* Send new injected URLs to background script. */
				if (filteredNewInjectedParameterURLs.length !== 0) {
					injectedParameterURLs = injectedParameterURLs.concat(
						filteredNewInjectedParameterURLs);
					postMessage({
						appendage: {
							injectedParameterURLsRequestQueue: filteredNewInjectedParameterURLs
						}
					});
				}
			}
		}
		res();
	});
};

/**
 * Starts creating injected permutations of an indefinite amount of injected URLs.
 */
const shiftURLRedirectParameterInjectionBuffer = async () => {
	return new Promise(async res => {
		/* Filter already discovered URLs that have injectable parameters. */
		while (
			   injectableRedirectParameterURLsBuffer.length !== 0
			&& bufferedIndexOf(
				localStorage.injectableRedirectParameterURLs,
				injectableRedirectParameterURLsBuffer[0],
				bufferLengthURLs,
				delayURLIndexing) !== -1
		) {
			injectableRedirectParameterURLsBuffer.shift();
			postMessage({
				shift: "injectableRedirectParameterURLsBuffer"
			});
			await sleep(delayURLThread);
		}
		let newInjectedRedirectParameterURLs = [];
		if (injectableRedirectParameterURLsBuffer.length !== 0) {
			const newExploitableURL = injectableRedirectParameterURLsBuffer[0];
			localStorage.injectableRedirectParameterURLs.push(newExploitableURL);
			postMessage({
				appendage: {
					injectableRedirectParameterURLs: newExploitableURL
				}
			});
			injectableRedirectParameterURLsBuffer.shift();
			postMessage({
				shift: "injectableRedirectParameterURLsBuffer"
			});
			/* Generate all permutations of injected parameters. */
			let amountOfChunks = Math.ceil(
				encodedRedirectURLVariants.length / bufferLengthURLs);
			for (let a = 0; a < amountOfChunks; a++) {
				for (
					let b = a * bufferLengthURLs;
					   b < encodedRedirectURLVariants.length
					&& b < (a * bufferLengthURLs) + bufferLengthURLs - 1;
					b++
				) {
					const injectedPermutations =
						await getInjectedURLRedirectParameterPermutations(
							newExploitableURL,
							encodedRedirectURLVariants[b]);
					newInjectedRedirectParameterURLs = newInjectedRedirectParameterURLs.concat(
						injectedPermutations);
				}
				await sleep(delayURLIndexing);
			}
			let filteredNewInjectedRedirectParameterURLs = [];
			for (let a = 0; a < newInjectedRedirectParameterURLs.length; a++) {
				if (
					   await bufferedIndexOf(
						filteredNewInjectedRedirectParameterURLs,
						newInjectedRedirectParameterURLs[a],
						bufferLengthURLs,
						delayURLIndexing) === -1
					&& await bufferedIndexOf(
						injectedRedirectParameterURLs,
						newInjectedRedirectParameterURLs[a],
						bufferLengthURLs,
						delayURLIndexing) === -1
				) {
					filteredNewInjectedRedirectParameterURLs.push(
						newInjectedRedirectParameterURLs[a]);
				}
			}
			/* Send new injected URLs to background script. */
			if (filteredNewInjectedRedirectParameterURLs.length !== 0) {
				injectedRedirectParameterURLs = injectedRedirectParameterURLs.concat(
					filteredNewInjectedRedirectParameterURLs);
				postMessage({
					appendage: {
						injectedRedirectParameterURLsRequestQueue:
							filteredNewInjectedRedirectParameterURLs
					}
				});
			}
		}
		res();
	});
};

/**
 * Starts injecting an indefinite amount of URLs with paths using the
 * specified redirect URLs that contain a path.
 */
const shiftURLPathInjectionBuffer = async () => {
	return new Promise(async res => {
		/* Filter already discovered URLs that have paths. */
		while (
			   injectablePathURLsBuffer.length !== 0
			&& await bufferedIndexOf(
				localStorage.injectablePathURLs,
				injectablePathURLsBuffer[0],
				bufferLengthURLs,
				delayURLIndexing) !== -1
		) {
			injectablePathURLsBuffer.shift();
			postMessage({
				shift: "injectablePathURLsBuffer"
			});
			await sleep(delayURLIndexing);
		}
		let newInjectedPathURLs = [];
		if (injectablePathURLsBuffer.length !== 0) {
			const newExploitableURL = injectablePathURLsBuffer[0];
			localStorage.injectablePathURLs.push(newExploitableURL);
			postMessage({
				appendage: {
					injectablePathURLs: newExploitableURL
				}
			});
			injectablePathURLsBuffer.shift();
			postMessage({
				shift: "injectablePathURLsBuffer"
			});
			const parsedInjectablePathURL = parseURL(injectablePathURLsBuffer[0]);
			if (parsedInjectablePathURL[3].length !== 0) {
				let matchIndices = [];
				let match;
				while (
					match = regexpSelectorURLPathDirectory.exec(
						parsedInjectablePathURL[3])
				) {
					matchIndices.push(match.index);
				}
				if (matchIndices.length !== 1) {
					matchIndices.push(parsedInjectablePathURL[3].length);
				}
				for (let a = 0; a < matchIndices.length; a++) {
					for (let b = 0; b < redirectURLsForPathExploitation.length; b++) {
						if (
							injectablePathURLsBuffer[0].endsWith(
								redirectURLsForPathExploitation[b].slice(1))
						) continue;
						const injectedURL = parsedInjectablePathURL.slice(0, 3).join("") +
							parsedInjectablePathURL[3].slice(0, matchIndices[a]) +
							redirectURLsForPathExploitation[b] +
							parsedInjectablePathURL.slice(5, 6).join("");
						if (
							   await bufferedIndexOf(
								newInjectedPathURLs,
								injectedURL,
								bufferLengthURLs,
								delayURLIndexing) === -1
							&& await bufferedIndexOf(
								injectedPathURLs,
								injectedURL,
								bufferLengthURLs,
								delayURLIndexing) === -1
						) newInjectedPathURLs.push(injectedURL);
					}
					await sleep(delayURLPathInjection);
				}
				if (newInjectedPathURLs.length !== 0) {
					injectedPathURLs = injectedPathURLs.concat(newInjectedPathURLs);
					postMessage({
						appendage: {
							injectedPathURLsRequestQueue: newInjectedPathURLs
						}
					});
				}
			}
			postMessage({
				shift: "injectablePathURLsBuffer"
			});
		}
		res();
	});
};

/**
 * Starts sorting an indefinite amount of URLs for scanning.
 */
const shiftURLScannerBuffer = async () => {
	return new Promise(async res => {
		while (
			   scannableURLsBuffer.length !== 0
			&& await bufferedIndexOf(
				scannableURLs,
				scannableURLsBuffer[0],
				bufferLengthURLs,
				delayURLIndexing) !== -1
		) {
			/* scannableURLs already contains this URL */
			scannableURLsBuffer.shift();
			postMessage({
				shift: "scannableURLsBuffer"
			});
			await sleep(delayURLThread);
		}
		if (scannableURLsBuffer.length !== 0) {
			const newScannableURL = scannableURLsBuffer[0];
			scannableURLs = scannableURLs.concat(newScannableURL);
			postMessage({
				appendage: {
					scannableURLsRequestQueue: [newScannableURL]
				}
			});
			scannableURLsBuffer.shift();
			postMessage({
				shift: "scannableURLsBuffer"
			});
		}
		res();
	});
};

/**
 * Unified thread for injecting and scanning in accordance with the specified URL priorites.
 */
const startURLThread = async () => {
	while (true) {
		urlPriorityIter:
		for (let a = 0; a < urlPriorities.length; a++) {
			switch (urlPriorities[a]) {
				case 0: /* injected parameter */
					if (injectableParameterURLsBuffer.length === 0) break;
					await shiftURLParameterInjectionBuffer();
					break urlPriorityIter;
				case 1: /* injected path */
					if (injectablePathURLsBuffer.length === 0) break;
					await shiftURLPathInjectionBuffer();
					break urlPriorityIter;
				case 2: /* injected redirect parameter */
					if (injectableRedirectParameterURLsBuffer.length === 0) break;
					await shiftURLRedirectParameterInjectionBuffer();
					break urlPriorityIter;
				case 3: /* scan */
					if (scannableURLsBuffer.length === 0) break;
					await shiftURLScannerBuffer();
					break urlPriorityIter;
			}
		}
		await sleep(delayURLThread)
	}
};

/**
 * Sleeps an awaited promise value for the given amount of
 * milliseconds.
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
const trimLeadingAndTrailingWhitespaces = str => {
	return str.replace(regexpSelectorLeadingAndTrailingWhitespace, "$1");
};

/* Init worker. */
(async () => {
	await prepareRedirectURLsForPathExploitation();
	await encodeRedirectURLs();
	registerMessageListener();
	await sleep(5000); // use a listener for localStorage instead
	startURLThread();
})();
