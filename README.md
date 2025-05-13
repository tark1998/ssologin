Nodejs script for automatic login to Postech SSO service.

# How to use
## 1. login to POVIS
```node.js
// Node.js
const SSOLogin = require("./src/SSOLogin.js")
var sl = new SSOLogin("[POSTECHID]","[POSTECHPASSWORD]");
var ret = sl.loginPovis();
const Res = await fetch("https://povis.postech.ac.kr/", {
  method: "GET",
  headers: {
    "content-type": "application/x-www-form-urlencoded",
    "cookie": `JSESSIONID=${ret["JSESSION"]}; JSESSIONMARKID=${ret["JSESSIONMARKID"]}`,
    "Referer": "https://povis.postech.ac.kr/irj/servlet/prt/portal/prtroot/postech.ac.kr~postech~usercheck.PSSORedirect",
    "user-agent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
  },
  "redirect": "follow"
});
    
const Html = await Res.text();
console.log("✅ Final HTML length:", Html.length);
```
