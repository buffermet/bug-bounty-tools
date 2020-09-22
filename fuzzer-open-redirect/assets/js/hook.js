/*
*   
* hook.js
*
* Background script for XSS-FUZZER.
*   
*/

const redirCookieHeaderName = "X-Open-Redirect-Scanner-Cookie";
const redirHostHeaderName = "X-Open-Redirect-Scanner-Host";

/*
 * Returns the host of the specified redirect URL found in the fuzzer's
 * HTTP request header.
 */
const getRedirectHostHeaderValue = requestHeaders => {
  for (let a = 0; a < requestHeaders.length; a++) {
    const thisRequestHeaderSet = requestHeaders[a];
    const headerName = thisRequestHeaderSet.name;
    const headerValue = thisRequestHeaderSet.value;
    if (headerName.toLowerCase() == redirHostHeaderName.toLowerCase()) {
      if (headerValue.replace(/\s*(.*)\s*/, "$1") == "") {
        console.log("Missing header value (" + headerName + ": " + headerValue + ").");
      }
      return headerValue;
    }
  }
  return "";
}

chrome.webRequest.onBeforeSendHeaders.addListener(
  details => {
    const arrNewRequestHeaders = [];
    const arrRequestHeaders = details.requestHeaders;
    const redirectHost = getRedirectHostHeaderValue(arrRequestHeaders);
    for (let a = 0; a < arrRequestHeaders.length; a++) {
      const thisRequestHeaderSet = arrRequestHeaders[a];
      const headerName = thisRequestHeaderSet.name;
      const headerValue = thisRequestHeaderSet.value;
      if (headerName.toLowerCase() == "location") {
        const parsedURL = parseURL(headerValue);
        const host = parsedURL[1];
        
      }
    }
    return {"requestHeaders": arrNewRequestHeaders};
  },
  {"urls": ["<all_urls>"]},
  ["blocking", "requestHeaders"]
);

//setTimeout(location.reload, 10000);

/*
chrome.webRequest.onBeforeRequest.addListener(
  details=>{

  },
  {"urls": ["<all_urls>"]},
  ["blocking", "requestBody"]
);
*/

/*
// Only works in FF
browser.webRequest.onBeforeRequest.addListener(
  details=>{
    let filter = browser.webRequest.filterResponseData(details.requestId);
    console.log(filter);
    let decoder = new TextDecoder("utf-8");
    filter.ondata = event => {
      console.log(event);
//      const str = decoder.decode(event.data, {stream: true});
//      console.log(str);
      filter.write(event.data);
      filter.disconnect();
    }
    return {};
  },
  {"urls": ["<all_urls>"]},
  ["blocking", "requestBody"]
);
*/

/*
chrome.webRequest.onBeforeSendHeaders.addListener(async(details)=>{
    console.log(details.requestBody);
  },
  {"urls": ["<all_urls>"]},
  ["blocking", "requestHeaders"]
);
*/

