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

### Encoding methods

### 0. (Zero)

This is a commonly used method to hex encode a URI parameter in modern browsers.

```js
globalThis.encodeURIComponent
```

```console
$ encodeMethods[0]("?url=//mysite.com")
"%3Furl%3D%2F%2Fmysite.com"
```

### 1. (One)

This is the same method of encoding as `globalThis.encodeURIComponent` in lowercase.

```js
str => {
  let encodedBuffer = new Array(str.length);
  for (let a = 0; a < str.length; a++) {
    if (str.charAt(a).match(regexpSelectorEscapableURICharacters)) {
      encodedBuffer[a] = "%" + str.charCodeAt(a).toString(16).toLowerCase();
    } else {
      encodedBuffer[a] = str.charAt(a);
    }
  } 
  return encodedBuffer.join("");
}
```

```console
$ encodeMethods[1]("?url=//mysite.com")
"%3furl%3d%2f%2fmysite.com"
```

### 2. (Two)

```console
$ encodeMethods[2]("?url=//mysite.com")
"%3f%75%72%6c%3d%2f%2f%6d%79%73%69%74%65%2e%63%6f%6d"
```

### 3. (Three)

```console
$ encodeMethods[3]("?url=//mysite.com")
"%3F%75%72%6C%3D%2F%2F%6D%79%73%69%74%65%2E%63%6F%6D"
```

### 4. (Four)

```console
$ encodeMethods[4]("?url=//mysite.com")
"%3f%75%72%6c%3d%2f%2f%6d%79%73%69%74%65%2e%63%6f%6d"
```

### 5. (Five)

```console
encodeMethods[5]("?url=//mysite.com")
"%3F%75%72%6C%3D%2F%2F%6D%79%73%69%74%65%2E%63%6F%6D"
```

### 6. (Six)

```console
$ encodeMethods[6]("?url=//mysite.com")
"\u003furl\u003d\u002f\u002fmysite\u002ecom"
```

### 7. (Seven)

```console
$ encodeMethods[7]("?url=//mysite.com")
"\u003Furl\u003D\u002F\u002Fmysite\u002Ecom"
```

### 8. (Eight)

```console
$ encodeMethods[8]("?url=//mysite.com")
"\u003f\u0075\u0072\u006c\u003d\u002f\u002f\u006d\u0079\u0073\u0069\u0074\u0065\u002e\u0063\u006f\u006d"
```

### 9. (Nine)

```console
$ encodeMethods[9]("?url=//mysite.com")
"\u003F\u0075\u0072\u006C\u003D\u002F\u002F\u006D\u0079\u0073\u0069\u0074\u0065\u002E\u0063\u006F\u006D"
```

### 10. (Ten)

```console
$ encodeMethods[10]("?url=//mysite.com")
"\x3furl\x3d\x2f\x2fmysite\x2ecom"
```

### 11. (Eleven)

```console
$ encodeMethods[11]("?url=//mysite.com")
"\x3Furl\x3D\x2F\x2Fmysite\x2Ecom"
```

### 12. (Twelve)

```console
$ encodeMethods[12]("?url=//mysite.com")
"\x3f\x75\x72\x6c\x3d\x2f\x2f\x6d\x79\x73\x69\x74\x65\x2e\x63\x6f\x6d"
```

### 13. (Thirteen)

```console
$ encodeMethods[13]("?url=//mysite.com")
"\x3F\x75\x72\x6C\x3D\x2F\x2F\x6D\x79\x73\x69\x74\x65\x2E\x63\x6F\x6D"
```
