// Run with Node.js v18+
const { fetch } = globalThis;
const { parse } = require('node-html-parser');
const { login } = require('./login_script.js');



class SSOLogin {
  constructor(id,password){
    this.url = null;
    this.appId = "";
    this.agt_id = "";
    this.loginjsessionid = null;
    this.agt_r = null;
    this.jsessionid = null;
    this.login_key = null;
    this.pni_data = null;
    this.client_ip = null;
    this.pni_token = null;
    this.loginjsessionmarkid = null;
    //this.pni_token_cookie = null;
    //this.mysapsso2 = null;
    //this.saplb = null;

    this.id = id;
    this.password = password;
  }

  // Util: extract value from input field
  extractInputValue(Html, target, extractor) {
    const HtmlRoot = parse(Html);
    const el = HtmlRoot.querySelector(extractor);
    const value =  el ? el.getAttribute('value') : null;
    if (!value) throw new Error(`❌ Failed to extract ${target}`);
    this.printMsg(`✅ ${target}: ${value}`);
    return value;
  }

  getSetCookie(Res,target,extractor) {
    const SetCookie = (extractor.exec(Res.headers.get('set-cookie')) || [])[1];
    if (!SetCookie) throw new Error(`❌ Failed to get ${target}`);
    this.printMsg(`✅ ${target}: ${SetCookie}`);
    return SetCookie;
  }

  printMsg(msg) {
    // Uncomment for debugging
    console.log(msg);
  }

  async extractAgtR_and_getLoginjsessionid(){
    // ───── STEP 1 ─────
    const step1Res = await fetch(`${this.url}/SSOService.do?targetAppId${this.appId}`, {
      method: "GET",
      headers: {
        "Referer": `${this.url}/rsm/login`
      }
    });

    const step1Html = await step1Res.text();
    
    this.agt_r = this.extractInputValue(step1Html, "agt_r", 'input[name="agt_r"]');
    this.loginjsessionid = this.getSetCookie(step1Res, "Login-JSESSIONID", /JSESSIONID=([^;]+)/); 
  }

  async getJsessionid(){
    // ───── STEP 2 ─────
    const step2Res = await fetch("https://sso.postech.ac.kr/sso/usr/login/link", {
      method: "POST",
      redirect: "manual",
      headers: {
        "Referer": this.url 
      },
      body: new URLSearchParams({
	agt_url: this.url,
	agt_r: this.agt_r,
	agt_id: this.agt_id,
	targetAppId: this.appId,
      }),
    });

    this.jsessionid = this.getSetCookie(step2Res, "JSESSIONID",/JSESSIONID=([^;]+)/);
  }

  async extractLoginKey(){
    // ───── STEP 3 ─────
    const step3Res = await fetch("https://sso.postech.ac.kr/sso/usr/postech/login/view", {
      method: "GET",
      headers: {
        "cookie": `JSESSIONID=${this.jsessionid}`,
        "Referer": this.url 
      }
    });

    const step3Html = await step3Res.text();
    this.login_key = this.extractInputValue(step3Html,"login_key",'#login_key');
  }

  async validateJsessionid_and_Loginkey(){
    // ───── STEP 3.5 ─────
    await login(this.jsessionid, this.login_key, this.id, this.password );
  }

  async extractPniData(){
    // ───── STEP 4 ─────
    const step4Res = await fetch("https://sso.postech.ac.kr/sso/usr/postech/login/link", {
      method: "POST",
      redirect: "manual",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        "cookie": `JSESSIONID=${this.jsessionid}`,
        "Referer": "https://sso.postech.ac.kr/sso/usr/postech/login/view"
      },
      body: `user_data=&login_key=${this.login_key}&login_id=&login_pwd=`
    });

    const step4Html = await step4Res.text();

    this.pni_data = this.extractInputValue(step4Html,"pni_data",'input[name="pni_data"]');
  }

  async validatePniData(){
    // ───── STEP 5 ─────
    const step5Res = await fetch(`${this.url}/SSOService.do?pname=spLoginData`, {
      method: "POST",
      redirect: "manual",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        "cookie": `JSESSIONID=${this.loginjsessionid}`,
        "Referer": "https://sso.postech.ac.kr/"
      },
      body: `pni_data=${this.pni_data}`
    });
    await step5Res.text();
    await new Promise(r => setTimeout(r, 1000));
  }

  async getClientIp(){
    const step6Res = await fetch("https://sso.postech.ac.kr/sso/api/cors/get/ip", {
      method: "POST",
      headers: {
    	"cookie": `JSESSIONID=${this.jsessionid}`,
    	"Referer": this.url ,
	//"content-type": "application/x-www-form-urlencoded",
      },
      body: null,
    });

    const step6Json = await step6Res.json();
    this.client_ip  = step6Json.client_ip;
  }

  async extractPniToken(){
    const step7Res = await fetch(`${this.url}/login`, {
      method: "POST",
      headers: {
    	"cookie": `JSESSIONID=${this.loginjsessionid}`,
    	"Referer": `${this.url}/resources/loginBeforeProc.jsp`,
	"content-type": "application/x-www-form-urlencoded",
      },
      body: `pni_client_ip=${this.client_ip}`,
    });	 
    
    const step7Html = await step7Res.text();
    this.pni_token = this.extractInputValue(step7Html, "pni_token",'input[name="pni_token"]')
  }

  async getCookiesAfterPniToken(){
    const step8Res = await fetch("https://povis.postech.ac.kr/irj/servlet/prt/portal/prtroot/postech.ac.kr~postech~usercheck.PSSOCheck", {
      method: "POST",
      headers: {
    	"Referer": this.url,
	"content-type": "application/x-www-form-urlencoded",
      },
      body: `pni_token=${this.pni_token}`,
    });	

    //this.mysapsso2 = this.getSetCookie(step8Res, "MYSAPSSO2", /MYSAPSSO2=([^;]+)/);
    //this.saplb     = this.getSetCookie(step8Res, "saplb_\*", /saplb_\*=([^;]+)/);
    //this.pni_token_cookie = this.getSetCookie(step8Res, "pni_token", /pni_token=([^;]+)/);
    this.loginjsessionid = this.getSetCookie(step8Res, "JSESSIONID", /JSESSIONID=([^;]+)/);
    this.loginjsessionmarkid = this.getSetCookie(step8Res, "JSESSIONMARKID", /JSESSIONMARKID=([^;]+)/);

    //const step8Html = await step8Res.text();
    //this.pni_token = this.extractInputValue(step8Html, "pni_token", 'input[name="pni_token"]')
  }

  /*
  async extractPniTokenAfterPniToken(){
    const step9Res = await fetch("https://povis.postech.ac.kr/irj/servlet/prt/portal/prtroot/postech.ac.kr~postech~usercheck.PSSORedirect", {
      method: "POST",
      headers: {
    	"cookie": `JSESSIONID=${this.loginjsessionid};`,// JSESSIONMARKID=${this.loginjsessionmarkid}`,
    	//"cookie": `MYSAPSSO2=${this.mysapsso2}; saplb_*=${this.saplb}; pni_token=${this.pni_token_cookie}; JSESSIONID=${this.loginjsessionid}; JSESSIONMARKID=${this.loginjsessionmarkid}`,
    	"Referer": "https://povis.postech.ac.kr/irj/servlet/prt/portal/prtroot/postech.ac.kr~postech~usercheck.PSSOCheck",
	"content-type": "application/x-www-form-urlencoded",
      },
      body: `success_url=https%3A%2F%2Fpovis.postech.ac.kr%2F&action=login_ok&location_url=S&colTarget=S&searchTerm=S&pni_token=${this.pni_token}`,
    });

    const step9Html = await step9Res.text();
    this.pni_token = this.extractInputValue(step9Html, "pni_token", 'input[name="pni_token"]')
  }
  */

  async goPovisPortal(){
    const step10Res = await fetch("https://povis.postech.ac.kr/", {
      method: "GET",
      headers: {
    	"content-type": "application/x-www-form-urlencoded",
    	//"cookie": `MYSAPSSO2=${this.mysapsso2}; saplb_*=${this.saplb}; pni_token=${this.pni_token_cookie}; JSESSIONID=${this.loginjsessionid}; JSESSIONMARKID=${this.loginjsessionmarkid}`,
    	"cookie": `JSESSIONID=${this.loginjsessionid}; JSESSIONMARKID=${this.loginjsessionmarkid}`,
    	"Referer": "https://povis.postech.ac.kr/irj/servlet/prt/portal/prtroot/postech.ac.kr~postech~usercheck.PSSORedirect",
	"user-agent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
      },
      //"body": `pni_token=${this.pni_token}`,
      "redirect": "follow"
    });
    
    const step10Html = await step10Res.text();
    console.log(step10Html);
    console.log("✅ Final HTML length:", step10Html.length);
  }

  async validateLoginjsessionid(){
    // ───── STEP 7 ─────
    const step7Res = await fetch("https://trp.postech.ac.kr/rsm/loginProc", {
      method: "GET",
      redirect: "manual",
      headers: {
        "cookie": `JSESSIONID=${this.loginjsessionid}`,
        "Referer": `${this.url}/passni/sample/loginProc.jsp`
      }
    });
    await step7Res.text(); 	
  }
  
  async loginTrp(){
    try {
      this.url = "https://trp.postech.ac.kr";
      this.agt_id = "postech-trp";
      await this.extractAgtR_and_getLoginjsessionid();
      await this.getJsessionid();
      await this.extractLoginKey();
      await this.validateJsessionid_and_Loginkey();
      await this.extractPniData();
      await this.validatePniData();
      await this.validateLoginjsessionid();
  
      return {
        JSESSIONID: this.loginjsessionid, 
      };
    } catch (err) {
      throw new Error("❌ Error during login automation:", err);
    }
  }

  async loginPovis(){
    this.url = "https://login.postech.ac.kr" 
    this.agt_id = "postech-semiportal-web";
    this.appId = "postech-povis-web" 
    await this.extractAgtR_and_getLoginjsessionid();
    await this.getJsessionid();
    await this.extractLoginKey();
    await this.validateJsessionid_and_Loginkey();
    await this.extractPniData();
    await this.validatePniData();
    await this.getClientIp();
    await this.extractPniToken();
    await this.getCookiesAfterPniToken();
    //await this.extractPniTokenAfterPniToken();
    //await this.goPovisPortal();
    return {
      JSESSIONID: this.loginjsessionid, 
      JSESSIONMARKID: this.loginjsessionmarkid
    };
  }
}

module.exports = SSOLogin;

