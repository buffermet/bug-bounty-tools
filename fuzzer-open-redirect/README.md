A recursive, multi-threaded open redirect URL scanner and fuzzer.

### Update

The issue of tabs idling seems to be solved now. Currently running a test and CPU usage is stable with over 745,000 parsed, filtered and injected URLs (and counting). It appears that Chrome extensions are a viable method to crawl for extensive periods of time.

I will build Web Workers to move tasks off the main thread and an API alongside the Chromium instance for concurrency, callbacks, and to minimize the risk of losing our scanning/fuzzing progress.

### Description

This is now an unpacked Chrome extension that you can install manually. GUI = WIP. Configure scope in the content and background scripts for now.

Every time the scanner loads a potentially exploited URL, it sends a timestamped callback to your chosen URL for requests.

Every time the scanner detects a successful exploitation, it sends a timestamped callback to your chosen URL for open redirects.

Tabs opened by the extension will automatically close when they've fulfilled their purpose, or timed out.

### Encoding methods

### 0. (Zero)

This is the same as `globalThis.encodeURIComponent` which is a commonly used method to hex encode a URI parameter value in modern browsers.

```console
$ encodeMethods[0]("//mysite.com")
"%2F%2Fmysite.com"
```

### 1. (One)

This is the same method of encoding as `globalThis.encodeURIComponent` with hex in lowercase.

```console
$ encodeMethods[1]("//mysite.com")
"%2f%2fmysite.com"
```

### 2. (Two)

```console
$ encodeMethods[2]("//mysite.com")
"%2f%2fmysite%2ecom"
```

### 3. (Three)

```console
$ encodeMethods[3]("//mysite.com")
"%2F%2Fmysite%2Ecom"
```

### 4. (Four)

```console
$ encodeMethods[4]("//mysite.com")
"%2f%2f%6d%79%73%69%74%65%2e%63%6f%6d"
```

### 5. (Five)

```console
$ encodeMethods[5]("//mysite.com")
"%2F%2F%6D%79%73%69%74%65%2E%63%6F%6D"
```

### 6. (Six)

```console
$ encodeMethods[6]("//mysite.com")
"\\u002f\\u002fmysite\\u002ecom"
```

### 7. (Seven)

```console
$ encodeMethods[7]("//mysite.com")
"\\u002F\\u002Fmysite\\u002Ecom"
```

### 8. (Eight)

```console
$ encodeMethods[8]("//mysite.com")
"\\u002f\\u002f\\u006d\\u0079\\u0073\\u0069\\u0074\\u0065\\u002e\\u0063\\u006f\\u006d"
```

### 9. (Nine)

```console
$ encodeMethods[9]("//mysite.com")
"\\u002F\\u002F\\u006D\\u0079\\u0073\\u0069\\u0074\\u0065\\u002E\\u0063\\u006F\\u006D"
```

### 10. (Ten)

```console
$ encodeMethods[10]("//mysite.com")
"\\x2f\\x2fmysite\\x2ecom"
```

### 11. (Eleven)

```console
$ encodeMethods[11]("//mysite.com")
"\\x2F\\x2Fmysite\\x2Ecom"
```

### 12. (Twelve)

```console
$ encodeMethods[12]("//mysite.com")
"\\x2f\\x2f\\x6d\\x79\\x73\\x69\\x74\\x65\\x2e\\x63\\x6f\\x6d"
```

### 13. (Thirteen)

```console
$ encodeMethods[13]("//mysite.com")
"\\x2F\\x2F\\x6D\\x79\\x73\\x69\\x74\\x65\\x2E\\x63\\x6F\\x6D"
```

### 14. (Fourteen)

```console
$ encodeMethods[14]("//mysite.com")
"//mysite。com"
```

### 15. (Fifteen)

```console
$ encodeMethods[15]("//mysite.com")
"/\x00/\x00m\x00y\x00s\x00i\x00t\x00e\x00.\x00c\x00o\x00m"
```

### 16. (Sixteen)

```console
$ encodeMethods[16]("//mysite.com")
"/%00/%00m%00y%00s%00i%00t%00e%00.%00c%00o%00m"
```

### 17. (Seventeen)

```console
$ encodeMethods[14]("//mysite.com")
"/\\u0000/\\u0000m\\u0000y\\u0000s\\u0000i\\u0000t\\u0000e\\u0000.\\u0000c\\u0000o\\u0000m"
```

### 18. (Eighteen)

```console
$ encodeMethods[14]("//mysite.com")
"/\\x00/\\x00m\\x00y\\x00s\\x00i\\x00t\\x00e\\x00.\\x00c\\x00o\\x00m"
```
