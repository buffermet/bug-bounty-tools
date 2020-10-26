chrome.runtime.onMessage.addListener((message, sender, callback) => {
  console.log(message, sender, callback);
});

/**
 * Background script for fuzzer-open-redirect.
 *
 * assets/js/background_script.js
 */

let programs = [];

const sessionID = "8230ufjio";

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
  const strippedURL = stripAllTrailingWhitespaces(url);
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
  if (strippedURL.match(/^(?:(?:[a-z0-9.+-]+:)?\/\/(?:(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{1,63})|[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})(?:[:][1-9][0-9]{0,4})?)?([/][^?]*)(?:[#][^/]*?)?/i)) {
    retval[3] = strippedURL.replace(/^(?:(?:[a-z0-9.+-]+:)?\/\/)?[^/?#]*([/][^?]*)(?:[#][^/]*?)?/i, "$1");
  }
  /* search */
  if (strippedURL.match(/^.*?([?][^#]*).*$/i)) {
    retval[4] = strippedURL.replace(/^.*?([?][^#]*).*$/i, "$1");
  }
  /* anchor */
  if (strippedURL.match(/^[^#]*([#][^/]*$)/i)) {
    retval[5] = strippedURL.replace(/^[^#]*([#][^/]*$)/i, "$1");
  }
  return retval;
}

/* Register message listeners. */
chrome.runtime.onMessage.addListener((message, sender, callback) => {
//  if (
//       message.sessionID
//    && message.sessionID === sessionID
//  ) {
//    if (message.programs) {
//      programs = message.programs;
//      const scannableURLs = programs.filter(program => {
//        return program.url;
//      }).map(program => {
//        return program.url;
//      });
//      callback({
//        sessionID: sessionID,
//        scannableURLs: scannableURLs,
//      });
//    }
//    if (
//         message.inScope
//      && message.outOfScope
//      && message.url
//    ) {
//      for (let a = 0; a < programs.length; a++) {
//        if (programs[a].url.startsWith(message.url)) {
//          programs[a].inScope = message.inScope;
//          programs[a].outOfScope = message.outOfScope;
//        }
//      }
//      callback({sessionID: sessionID});
//    }
//  }
});

/* Send messages to tabs. */
//chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
//  chrome.tabs.sendMessage(tabs[0].id, {greeting: "hello"}, function(response) {
//    console.log(response.farewell);
//  });
//});

