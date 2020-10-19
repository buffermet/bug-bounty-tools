A recursive, multi-threaded open redirect URL scanner and fuzzer.

### Description

This works as a single script injection, but will be ported to an interactive browser extension with a GUI soon.

Every time the scanner loads a potentially exploited URL, it sends a timestamped callback to your chosen URL for requests.

Every time the scanner detects a successful exploitation, it sends a timestamped callback to your chosen URL for open redirects.

CORS restrictions are evaded by making use of the `globalThis.open` method and `globalThis.location` setter rather than `XMLHttpRequest` or `fetch`.

Tabs opened by the scanner will automatically close when they've fulfilled their purpose, or timed out.

### How to use

1. Configure your scope in the script.
2. Make your browser inject the script in all pages.
3. Visit a page that is in your scope to start the scanner.
