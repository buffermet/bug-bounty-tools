chrome.devtools.network.onRequestFinished.addListener(function(req) {
    // Displayed sample TCP connection time here
   console.log(req.timings.connect);
});

