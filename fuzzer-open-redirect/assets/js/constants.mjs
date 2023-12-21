/**
 * Constants module.
 */

const module = {
    regexpSelectorAllHTMLAttributes: / [a-z-]+[=]["'][^"']+["']/ig,
    regexpSelectorAnyFileExtension: /[.][a-z]{2,3}$/i,
    regexpSelectorDebrisHTMLAttributeOne: /^ [a-z-]+[=]/ig,
    regexpSelectorDebrisHTMLAttributeTwo: /^["']/,
    regexpSelectorDebrisHTMLAttributeThree: /["']$/,
    regexpSelectorEscapeChars: /([^*a-z0-9\]])/ig,
    regexpSelectorHTMLURLAttribute: /^ (?:action|href|src)[=]/i,
    regexpSelectorJSONPruneWebkitStorageInfoOne: /webkitStorageInfo/,
    regexpSelectorJSONPruneWebkitStorageInfoTwo: /webkitStorageInfo/g,
    regexpSelectorLeadingAndTrailingWhitespace: /^\s*(.*)\s*$/g,
    regexpSelectorPathWithDirectory: /^[^/]+[/][^/]+/i,
    regexpSelectorURIOne: /^(?:http|\/|[a-z0-9_-]{1,8192}|[a-z0-9_ -]{1,8192}\.[a-z]{1,2}[a-z0-9]{0,1})[/?#]/i,
    regexpSelectorURITwo: /^(?:http|\/|[a-z0-9_-]{1,8192}|[a-z0-9_ -]{1,8192}\.[a-z]{1,2}[a-z0-9]{0,1})[^?]{0,8192}\?/i,
    regexpSelectorURIWithParameterPlain: /(?:(?:http[s]?(?:[:]|%3a))?(?:(?:[/]|%2f){2}))(?:(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{1,63})|(?:25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1-9]?[0-9])\.(?:25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1-9]?[0-9])\.(?:25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1-9]?[0-9])\.(?:25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1-9]?[0-9]))(?:\/[^?# "'`),]{0,8192})?(?:\?[^# "'`),]{0,8192})?(?:[#][^ "'`),]{0,8192})?/ig,
    regexpSelectorURLHashRemoval: /#.*$/g,
    regexpSelectorURLHost: /^((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.){1,63}(?:[a-z]{1,63})|(?:25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1-9]?[0-9])\.(?:25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1-9]?[0-9])\.(?:25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1-9]?[0-9])\.(?:25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1-9]?[0-9]))?.*$/i,
    regexpSelectorURLParameterValue: /=[^&=#]*/g,
    regexpSelectorURLPath: /^([^?#]{1,2048})?.*$/i,
    regexpSelectorURLPlain: /(?:(?:http[s]?(?:[:]|%3a))?(?:(?:[/]|%2f){2}))(?:(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{1,63})|(?:25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1-9]?[0-9])\.(?:25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1-9]?[0-9])\.(?:25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1-9]?[0-9])\.(?:25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1-9]?[0-9]))(?:\/[^?# "'`),]{0,8192})?(?:\?[^# "'`),]{0,8192})?(?:[#][^ "'`),]{0,8192})?/ig,
    regexpSelectorURLPort: /^([:](?:6553[0-5]|655[0-2][0-9]|65[0-4][0-9][0-9]|6[0-4][0-9][0-9][0-9]|[0-5][0-9][0-9][0-9][0-9]|[1-9][0-9]{0,3}))?.*$/i,
    regexpSelectorURLProtocol: /^((?:[a-z0-9.+-]{1,256}[:])(?:[/][/])?|(?:[a-z0-9.+-]{1,256}[:])?[/][/])?.*$/i,
    regexpSelectorURLRedirectParameter: /^[=](?:http|%68%74%74%70|[/]|[?]|%[23]f|%23|[.]{1,2}[/]|(?:%2e){1,2}%2f)/i,
    regexpSelectorURLSchemeEscaped: /^([a-z0-9.+-]*)\*([a-z0-9.+-]*)\[:\]/ig,
    regexpSelectorURLSearch: /^([?][^#]{0,2048})?.*$/i,
    regexpSelectorWildcardStatusCode: /\*/g,
    regexpSelectorWildcardSubdomainEscaped: /\*\[\.\]/g,
}

Object.freeze(module)

export default module
