/*
*   
*   environment.js
*   
*   Sets the XSS-FUZZER environment.
*   
*/

const app = {}

app.location = {
    "href": self.location.href,
    "headers": [],
    "csp": {}
};
app.config = {
    "reflected": true,
    "stored": true,
    "stored_target": ""
};
app.macros = {};
app.payloads = [];
app.iframes = {
    "reflected": []
}

/*
*   
*   functions.js
*   
*   Sets the XSS-FUZZER functions.
*   
*/

const XSS_CONST_FUNC_ALERT_COPY = alert;

const XSS_CONST_FUNC_INTERCEPTED_ALERT = async message => {
    XSS_CONST_FUNC_ALERT_COPY(message);
    XSS_CONST_FUNC_XSS_FOUND(message);
}

const XSS_CONST_FUNC_XSS_FOUND = async alert_message => {
    console.log("alert message triggered: " + alert_message);
}

const XSS_CONST_FUNC_PARSE_CSP_HEADER = async header_value => {
    let split_csp_headers = header_value.split(";");
    split_csp_header.forEach(csp_string=>{
        csp_string = csp_string.replace(/^\s*/, "").replace(/\s*$/, "")
    });
}

const XSS_CONST_FUNC_FETCH_PAYLOADS = async () {
    req = new XMLHttpRequest();
    req.open("GET", "/assets/payloads/xss.txt");
    req.onreadystatechange = async () => {
        if (req.readyState == 4) {
            const res = req.responseText;
            app.config.payloads = res.split("\n");
        }
    }
    req.send();
}

/*
*   
*   events.js
*   
*   Sets the XSS-FUZZER events.
*   
*/



/*
*   
*   index.js
*   
*   Instantiates index page.
*   
*/

self.addEventListener("load" async()=>{
    alert = XSS_CONST_FUNC_INTERCEPTED_ALERT;

    await XSS_CONST_FUNC_FETCH_PAYLOADS();

    XSS_CONST_FUNC_ALERT_COPY("fuzzer loaded");
});
