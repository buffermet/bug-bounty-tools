/**
 * URL module.
 */

import constants from "./constants.mjs"
import random from "./random.mjs"

const charsAlphabetic = random.charsAlphabeticLowerCase + charsAlphabeticUpperCase

const module = {
  /**
   * An integer mapped collection of methods to encode a given URI
   * parameter string.
   */
  encodeMethods: {
    0: globalThis.encodeURIComponent,
    1: str => {
      /**
       * Returns a string exactly like globalThis.encodeURIComponent
       * does, with lowercase hex encoding.
       */
      let encodedBuffer = new Array(str.length);
      for (let a = 0; a < str.length; a++) {
        if (constants.regexpSelectorEncodableURICharacters.test(str.charAt(a))) {
          encodedBuffer[a] = "%" + str.charCodeAt(a).toString(16).toLowerCase();
        } else {
          encodedBuffer[a] = str.charAt(a);
        }
      }
      return encodedBuffer.join("");
    },
    2: str => {
      /**
       * Returns a lowercase hex encoded string (type 1) using a given
       * string.
       * (example input: "https://myredirectsite.com/")
       * (example output: "https%3a%2f%2fmyredirectsite%2ecom%2f")
       */
      let encodedBuffer = new Array(str.length);
      for (let a = 0; a < str.length; a++) {
        if (charsAlphabetic.indexOf(str.charAt(a) === -1)) {
          encodedBuffer[a] = "%" + str.charCodeAt(a).toString(16).toLowerCase();
        } else {
          encodedBuffer[a] = str.charAt(a);
        }
      }
      return encodedBuffer.join("");
    },
    3: str => {
      /**
       * Returns an uppercase hex encoded string (type 1) using a given
       * string.
       * (example input: "https://myredirectsite.com/")
       * (example output: "https%3A%2F%2Fmyredirectsite%2Ecom%2F")
       */
      let encodedBuffer = new Array(str.length);
      for (let a = 0; a < str.length; a++) {
        if (charsAlphabetic.indexOf(str.charAt(a) === 0)) {
          encodedBuffer[a] = "%" + str.charCodeAt(a).toString(16).toUpperCase();
        } else {
          encodedBuffer[a] = str.charAt(a);
        }
      }
      return encodedBuffer.join("");
    },
    4: str => {
      /**
       * Returns a lowercase hex encoded string (type 2) using a given
       * string.
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
       * Returns an uppercase hex encoded string (type 2) using a given
       * string.
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
       * Returns a lowercase hex encoded string (type 3) using a given
       * string.
       * (example input: "https://myredirectsite.com/")
       * (example output: "https\\u003a\\u002f\\u002fmyredirectsite\\u002ecom\\u002f")
       */
      let encodedBuffer = new Array(str.length);
      for (let a = 0; a < str.length; a++) {
        if (charsAlphabetic.indexOf(str.charAt(a)) === -1) {
          encodedBuffer[a] = "\\u00" + str.charCodeAt(a).toString(16).toLowerCase();
        } else {
          encodedBuffer[a] = str.charAt(a);
        }
      }
      return encodedBuffer.join("");
    },
    7: str => {
      /**
       * Returns an uppercase hex encoded string (type 3) using a given
       * string.
       * (example input: "https://myredirectsite.com/")
       * (example output: "https\\u003A\\u002F\\u002Fmyredirectsite\\u002Ecom\\u002f")
       */
      let encodedBuffer = new Array(str.length);
      for (let a = 0; a < str.length; a++) {
        if (charsAlphabetic.indexOf(str.charAt(a)) === -1) {
          encodedBuffer[a] = "\\u00" + str.charCodeAt(a).toString(16).toUpperCase();
        } else {
          encodedBuffer[a] = str.charAt(a);
        }
      }
      return encodedBuffer.join("");
    },
    8: str => {
      /**
       * Returns a lowercase hex encoded string (type 4) using a given
       * string.
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
       * Returns an uppercase hex encoded string (type 4) using a given
       * string.
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
       * Returns a lowercase hex encoded string (type 5) using a given
       * string.
       * (example input: "https://myredirectsite.com/")
       * (example output: "https\\x3a\\x2f\\x2fmyredirectsite\\x2ecom\\x2f")
       */
      let encodedBuffer = new Array(str.length);
      for (let a = 0; a < str.length; a++) {
        if (charsAlphabetic.indexOf(str.charAt(a)) === -1) {
          encodedBuffer[a] = "\\x" + str.charCodeAt(a).toString(16).toLowerCase();
        } else {
          encodedBuffer[a] = str.charAt(a);
        }
      }
      return encodedBuffer.join("");
    },
    11: str => {
      /**
       * Returns an uppercase hex encoded string (type 5) using a given
       * string.
       * (example input: "https://myredirectsite.com/")
       * (example output: "https\\x3A\\x2F\\x2Fmyredirectsite\\x2Ecom\\x2f")
       */
      let encodedBuffer = new Array(str.length);
      for (let a = 0; a < str.length; a++) {
        if (charsAlphabetic.indexOf(str.charAt(a)) === -1) {
          encodedBuffer[a] = "\\x" + str.charCodeAt(a).toString(16).toUpperCase();
        } else {
          encodedBuffer[a] = str.charAt(a);
        }
      }
      return encodedBuffer.join("");
    },
    12: str => {
      /**
       * Returns a lowercase hex encoded string (type 6) using a given
       * string.
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
       * Returns an uppercase hex encoded string (type 6) using a given
       * string.
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
       * Returns a given string with a null byte between each character.
       */
      let encodedBuffer = new Array(str.length);
      for (let a = 0; a < str.length; a++) {
        encodedBuffer[a] = str.charAt(a);
      }
      return encodedBuffer.join("\x00");
    },
    16: str => {
      /**
       * Returns a given string with a URL encoded null byte between
       * each character.
       */
      let encodedBuffer = new Array(str.length);
      for (let a = 0; a < str.length; a++) {
        encodedBuffer[a] = str.charAt(a);
      }
      return encodedBuffer.join("%00");
    },
    17: str => {
      /**
       * Returns a given string with a hex encoded null byte (type 17)
       * between each character.
       */
      let encodedBuffer = new Array(str.length);
      for (let a = 0; a < str.length; a++) {
        encodedBuffer[a] = str.charAt(a);
      }
      return encodedBuffer.join("\\u0000");
    },
    18: str => {
      /**
       * Returns a given string with a hex encoded null byte (type 18)
       * between each character.
       */
      let encodedBuffer = new Array(str.length);
      for (let a = 0; a < str.length; a++) {
        encodedBuffer[a] = str.charAt(a);
      }
      return encodedBuffer.join("\\x00");
    },
  },
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
