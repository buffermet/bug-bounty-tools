/**
 * Session module.
 */

const module = {
    /**
     * Returns a new session config.
     */
    new: (callbackURLOpenRedirectTimestamps,
          callbackURLRequestTimestamps) => {
        return {
            callbackURLOpenRedirectTimestamps: callbackURLOpenRedirectTimestamps,
            callbackURLRequestTimestamps: callbackURLRequestTimestamps,
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
            urlBuffer: [],
        }
    },
}

export default module

