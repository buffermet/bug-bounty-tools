/**
 * URL module.
 */

import constants from "./constants.mjs"

const module = {
	/**
	 * Returns an array containing the protocol, host, port, path, search and
	 * hash of a given URL if found.
	 * @param {string} url
	 * @returns {string}
	 */
	parse: url => {
		let sliceLength = 0
		const strippedURL = module.trimLeadingAndTrailingWhitespaces(url)
		const retval = ["","","","","",""]
		/* protocol */
		retval[0] = strippedURL
			.replace(constants.regexpSelectorURLProtocol, "$1")
		const protocol = retval[0].toLowerCase()
		if (protocol.length !== 0) {
			if (
				   protocol === "data:"
				|| protocol === "javascript:"
			) {
				retval[3] = url.slice(retval[0].length)
				return retval
			}
			/* host */
			retval[1] = strippedURL
				.slice(retval[0].length)
				.replace(constants.regexpSelectorURLHost, "$1")
		}
		/* port */
		sliceLength = retval[0].length + retval[1].length
		retval[2] = strippedURL
			.slice(sliceLength)
			.replace(constants.regexpSelectorURLPort, "$1")
		/* path */
		sliceLength = sliceLength + retval[2].length
		retval[3] = strippedURL
			.slice(sliceLength)
			.replace(constants.regexpSelectorURLPath, "$1")
		/* search */
		sliceLength = sliceLength + retval[3].length
		retval[4] = strippedURL
			.slice(sliceLength)
			.replace(constants.regexpSelectorURLSearch, "$1")
		/* hash */
		retval[5] = strippedURL.slice(sliceLength + retval[4].length)
		return retval
	},
	/**
	 * 
	 */
	parseCallbackURLs: async session => {
		return new Promise((res, err) => {
			/* Parse specified callback URLs for open redirects and requests. */
			parsedCallbackURLOpenRedirectTimestamps = parseURL(
				session.callbackURLOpenRedirectTimestamps)
			if (parsedCallbackURLOpenRedirectTimestamps[1] === "") {
				console.error("%cfuzzer-open-redirect", consoleCSS,
					"No valid origin was provided in the specified callback " +
					"URL for open redirect timestamps (" +
					session.callbackURLOpenRedirectTimestamps + ").")
				err()
			}
			if (parsedCallbackURLOpenRedirectTimestamps[0] === "") {
				console.warn("%cfuzzer-open-redirect", consoleCSS,
					"No protocol was provided in the specified callback " +
					"URL for open redirect timestamps (" +
					session.callbackURLOpenRedirectTimestamps + ").",
					"Defaulting to \"http://\".")
				parsedCallbackURLOpenRedirectTimestamps[0] = "http://"
			}
			console.log("%cfuzzer-open-redirect", consoleCSS,
				"Callback URL for open redirect timestamps is parsed: " +
				parsedCallbackURLOpenRedirectTimestamps.join(""))
			parsedCallbackURLRequestTimestamps = parseURL(
				session.callbackURLRequestTimestamps)
			if (parsedCallbackURLRequestTimestamps[1] === "") {
				console.error("%cfuzzer-open-redirect", consoleCSS,
					"No valid origin was provided in the specified callback " +
					"URL for request timestamps (" +
					session.callbackURLRequestTimestamps + ").")
				err()
			}
			if (parsedCallbackURLRequestTimestamps[0] === "") {
				console.warn("%cfuzzer-open-redirect", consoleCSS,
					"No protocol was provided in the specified callback " +
					"URL for request timestamps (" +
					session.callbackURLRequestTimestamps + ").",
					"Defaulting to \"http://\".")
				parsedCallbackURLRequestTimestamps[0] = "http://"
			}
			console.log("%cfuzzer-open-redirect", consoleCSS,
				"Callback URL for request timestamps is parsed: " +
				parsedCallbackURLRequestTimestamps.join(""))
			res()
		})
	},
	/**
	 * Trims all leading and trailing whitespaces off a given string.
	 * (example input: " https://example.com/  \n")
	 * (example output: "https://example.com/")
	 * @param {string} str
	 * @returns {string}
	 */
	trimLeadingAndTrailingWhitespaces: str => {
		return str.replace(
			constants.regexpSelectorLeadingAndTrailingWhitespace,
			"$1")
	},
}

Object.freeze(module)

export default module
