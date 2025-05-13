/**
 * ************************************************************************************************
 * 
 * 로그인 스크립트 파일입니다. 이 파일을 임의로 수정 후 발생한 오류에 대해서는 책임지지 않습니다.
 * 
 * ************************************************************************************************
 */
 
const crypto = require('crypto').webcrypto;
function alert(msg){console.error(msg);}
function print_msg(msg,arg){
	//console.log(msg,arg);
	return;
}

var client_calkey = '';

var keyModule = (function () {
	
	var ec_name = 'secp256r1';
	
	var server_url;

	var ec_q;
	var ec_a;
	var ec_b;
	var ec_gx;
	var ec_gy;
	var ec_n;
	var rng;
	
	var client_prikey;
	var client_pubkey;
	
	function fn_set_ec_params() {
		var ec_curve = getSECCurveByName(ec_name);

		ec_q = ec_curve.getCurve().getQ().toString(16);
		ec_a = ec_curve.getCurve().getA().toBigInteger().toString(16);
		ec_b = ec_curve.getCurve().getB().toBigInteger().toString(16);
		ec_gx = ec_curve.getG().getX().toBigInteger().toString(16);
		ec_gy = ec_curve.getG().getY().toBigInteger().toString(16);
		ec_n = ec_curve.getN().toString(16);
	}

	function fn_set_client_prikey() {
		var n = new BigInteger(ec_n, 16);
		var n1 = n.subtract(BigInteger.ONE);
		var r = new BigInteger(n.bitLength(), rng);
		var rand = r.mod(n1).add(BigInteger.ONE);

		client_prikey = r.toString(16);
		print_msg("client_prikey: ", client_prikey);
	}

	function fn_set_client_pubkey() {
		var curve = get_curve();
		var G = get_G(curve);
		var a = new BigInteger(client_prikey, 16);
		var P = G.multiply(a);

		var pubkey_x = P.getX().toBigInteger().toString(16);
		var pubkey_y = P.getY().toBigInteger().toString(16);

		if (pubkey_x.length < 64) {
			var zlen = 64 - pubkey_x.length;
			for (i = 0; i < zlen; i++) {
				pubkey_x = '0' + pubkey_x;
			}
		}

		if (pubkey_y.length < 64) {
			var zlen = 64 - pubkey_y.length;
			for (i = 0; i < zlen; i++) {
				pubkey_y = '0' + pubkey_y;
			}
		}

		client_pubkey = pubkey_x + pubkey_y;
		print_msg("client_pubkey: ",client_pubkey);
	}

	async function fn_set_client_calkey(jsessionid) {
		/*
		await $.ajax({
			url: "https://sso.postech.ac.kr/sso/usr/postech/login/init",
			type: 'post',
			data: 'user_ec_publickey=' + client_pubkey,
			dataType: 'json',
			async: false,
			success: function (responseData)
			{
				var result = responseData.code;

				if (result == 'SS0001') {
					var pubkey_x = responseData.svr_qx;
					var pubkey_y = responseData.svr_qy;

					var curve = get_curve();
					var P = new ECPointFp(curve, curve.fromBigInteger(new BigInteger(
							pubkey_x, 16)), curve.fromBigInteger(new BigInteger(
							pubkey_y, 16)));
					var a = new BigInteger(client_prikey, 16);
					var S = P.multiply(a);

					var calkey_x = S.getX().toBigInteger().toString(16);
					var calkey_y = S.getY().toBigInteger().toString(16);

					if (calkey_x.length < 64) {
						var zlen = 64 - calkey_x.length;
						for (i = 0; i < zlen; i++) {
							calkey_x = '0' + calkey_x;
						}
					}

					if (calkey_y.length < 64) {
						var zlen = 64 - calkey_y.length;
						for (i = 0; i < zlen; i++) {
							calkey_y = '0' + calkey_y;
						}
					}

					client_calkey = calkey_x + calkey_y;
				}
			},
			error: function ()
			{}
		});
		*/

		const response = await fetch("https://sso.postech.ac.kr/sso/usr/postech/login/init", {
		  "headers": {
			"accept": "application/json",
			"accept-language": "ko;q=0.5",
			"cache-control": "no-cache",
			"content-type": "application/x-www-form-urlencoded",
			"cookie": `JSESSIONID=${jsessionid}`,
			"pragma": "no-cache",
			"sec-ch-ua": "\"Not(A:Brand\";v=\"99\", \"Brave\";v=\"133\", \"Chromium\";v=\"133\"",
			"sec-ch-ua-mobile": "?0",
			"sec-ch-ua-platform": "\"Linux\"",
			"sec-fetch-dest": "empty",
			"sec-fetch-mode": "cors",
			"sec-fetch-site": "same-origin",
			"sec-gpc": "1",
			"upgrade-insecure-requests": "1",
			"Referer": "https://sso.postech.ac.kr/sso/usr/postech/login/view",
			"Referrer-Policy": "strict-origin-when-cross-origin"
		  },
		  "body": `user_ec_publickey=${client_pubkey}`,
		  "method": "POST",
		  "redirect":"manual"
		})
		
		const responseData = await response.json();
		
		var result = responseData.code;

		if (result == 'SS0001') {
			var pubkey_x = responseData.svr_qx;
			var pubkey_y = responseData.svr_qy;

			var curve = get_curve();
			var P = new ECPointFp(curve, curve.fromBigInteger(new BigInteger(
					pubkey_x, 16)), curve.fromBigInteger(new BigInteger(
					pubkey_y, 16)));
			var a = new BigInteger(client_prikey, 16);
			var S = P.multiply(a);

			var calkey_x = S.getX().toBigInteger().toString(16);
			var calkey_y = S.getY().toBigInteger().toString(16);

			if (calkey_x.length < 64) {
				var zlen = 64 - calkey_x.length;
				for (i = 0; i < zlen; i++) {
					calkey_x = '0' + calkey_x;
				}
			}

			if (calkey_y.length < 64) {
				var zlen = 64 - calkey_y.length;
				for (i = 0; i < zlen; i++) {
					calkey_y = '0' + calkey_y;
				}
			}
			client_calkey = calkey_x + calkey_y;
		}


	}

	function get_curve() {
		return new ECCurveFp(new BigInteger(ec_q, 16), new BigInteger(ec_a, 16),
				new BigInteger(ec_b, 16));
	}

	function get_G(curve) {
		return new ECPointFp(curve,
				curve.fromBigInteger(new BigInteger(ec_gx, 16)), curve
						.fromBigInteger(new BigInteger(ec_gy, 16)));
	}
	
	return {
		
		init: async function(url, lang, jsessionid) {
			server_url = url;
			
			fn_set_ec_params();

			rng = new SecureRandom();
			
			var error = '';

			fn_set_client_prikey();

			if (client_prikey.length == 0) {
				error = '[PrivateKey]';
			}
			
			if (error == '' ) {
				fn_set_client_pubkey();

				if (client_pubkey.length == 0) {
					error = '[PublicKey]';
				}
			}
			
			if (error == '' ) {
				await fn_set_client_calkey(jsessionid).then(()=>{
					print_msg('client_calkey: ',client_calkey);
					if (client_calkey == '' || client_calkey.length == 0) {
						error = '[CalculateKey]';
						console.log(error);
			
						if (error != '' ) {
							if (lang) {
								if (lang == 'ko') {
									alert('시스템 오류가 발생하였습니다. 관리자에게 문의하시기 바랍니다. ' + error);
								} else {
									alert('A system error has occurred. Please contact your administrator. ' + error);
								}
								
							} else {
								alert('시스템 오류가 발생하였습니다. 관리자에게 문의하시기 바랍니다. (A system error has occurred. Please contact your administrator.) ' + error);
							}
						}
					}
				});
			}
			
		}
	};
	
})();


var loginModule = (function () {
	
	var server_url;
	var language;
	
	function fn_encrypt_data(data) {
		
		var passni_key = CryptoJS.enc.Hex.parse(client_calkey.substring(0, 64));
		var passni_iv = CryptoJS.enc.Hex.parse(client_calkey.substring(64, 96));
		//console.log("passni_key:", passni_key);
		//console.log("passni_iv:", passni_iv);
		
		var byte_data = CryptoJS.SEED.encrypt(data, passni_key, {
			iv : passni_iv,
			mode : CryptoJS.mode.CBC,
			padding : CryptoJS.pad.AnsiX923
		});
		
		var encrypt_data = byte_data.ciphertext.toString();
		
		return encrypt_data;
	}
	
	async function fn_server_request(req_data,jsessionid) {
		
		var obj_data;
		//console.log("req_data: ",req_data);
		const response = await fetch("https://sso.postech.ac.kr/sso/usr/postech/login/auth", {
		  "headers": {
			"accept": "application/json, text/javascript, */*; q=0.01",
			"accept-language": "ko;q=0.7",
			"cache-control": "no-cache",
			"content-type": "application/x-www-form-urlencoded; charset=UTF-8",
			"cookie": `JSESSIONID=${jsessionid}`, 
			"pragma": "no-cache",
			"sec-ch-ua": "\"Not(A:Brand\";v=\"99\", \"Brave\";v=\"133\", \"Chromium\";v=\"133\"",
			"sec-ch-ua-mobile": "?0",
			"sec-ch-ua-platform": "\"Linux\"",
			"sec-fetch-dest": "empty",
			"sec-fetch-mode": "cors",
			"sec-fetch-site": "same-origin",
			"sec-gpc": "1",
			"x-requested-with": "XMLHttpRequest",
			"upgrade-insecure-requests": "1"
		  },
		  "referrer": "https://sso.postech.ac.kr/sso/usr/postech/login/view",
		  "referrerPolicy": "strict-origin-when-cross-origin",
		  "body": req_data,
		  "method": "POST",
		  "mode": "cors",
		  "credentials": "include",
		  "redirect":"manual"
		})
				
		obj_data = await response.json();
		print_msg("obj_data: ",obj_data);
		//console.log(response);
		/*
		$.ajax({
			url: 'https://sso.postech.ac.kr/sso/usr/postech/login/auth',//server_url,
			type: 'post',
			data: req_data,
			dataType: 'json',
			async: false,
			success: function (responseData)
			{
				obj_data = responseData;
			},
			error: function (err)
			{
				console.log(err);
				if (language == 'ko') {
					alert('시스템 오류가 발생하였습니다. 관리자에게 문의하시기 바랍니다. [connect]');
				} else {
					alert('A system error has occurred. Please contact your administrator. [connect]');
				}
			}
		});
		*/
		
		return obj_data;
	}
	
	return {
		
		auth: async function(url, lang, jsessionid, login_key, id, password) {
			
			var ko_msg_system_error = '시스템 오류가 발생하였습니다. 관리자에게 문의하시기 바랍니다. [CalculateKey]';
			var ko_msg_id_empty = '아이디를 입력해 주세요.';
			var ko_msg_pw_empty = '비밀번호를  입력해 주세요.';
			
			var en_msg_system_error = 'A system error has occurred. Please contact your administrator. [CalculateKey]';
			var en_msg_id_empty = 'Please enter your ID.';
			var en_msg_pw_empty = 'Please enter your Password.';
			
			server_url = url;
			language = lang;
			
			if (client_calkey == '' || client_calkey.length == 0) {
				alert( eval(lang + '_msg_system_error') );
				return null;
			}
			
			var login_id = id;
			var login_pwd = password;
			
			if (login_id == '') {
				$('#login_fail').html( eval(lang + '_msg_id_empty') );
				$('#login_id').focus();
				return null;
			}
			
			if (login_pwd == '') {
				$('#login_fail').html( eval(lang + '_msg_pw_empty') );
				$('#login_pwd').focus();
				return null;
			}
			
			//$('#login_id').val('');
			//$('#login_pwd').val('');
			
			var jsonObj = {'login_id':login_id,'login_pwd':login_pwd};
			var jsonStr = JSON.stringify( jsonObj );
			
			//console.log("jsonStr: ",jsonStr);
			var user_data = fn_encrypt_data( jsonStr );
			//console.log("user_data: ",user_data);
			
			var req_data = 'user_data=' + user_data + '&login_key=' + login_key;//$('#login_key').val();

			print_msg('req_data: ',req_data);
			var obj_data = await fn_server_request( req_data , jsessionid );

			
			return obj_data;
		},
	
		message:function(obj_data, lang) {
			
			var ko_msg_fail = '아이디 또는 비밀번호가 올바르지 않습니다.';
			var ko_msg_SS0004 = '최초 로그인 하여 비밀번호 변경화면으로 이동합니다.\n\n비밀번호를 변경하여 주십시요.';
			var ko_msg_SS0005 = '초기화된 비밀번호를 사용하여 비밀번호 변경화면으로 이동합니다.\n\n비밀번호를 변경하여 주십시요.';
			var ko_msg_SS0006 = '휴면 계정 입니다.';
			var ko_msg_SS0007 = '재가입 동의가 필요하여 약관 동의 화면으로 이동합니다.\n\n약관에 동의하여 주십시요.';
			var ko_msg_SS0008 = '오래된 비밀번호를 사용하고 있어 비밀번호 변경화면으로 이동합니다.\n\n비밀번호를 변경하여 주십시요.';
			var ko_msg_EAU003 = '접속 기간이 시작전이거나 만료되었습니다.<br/>관리자에게 문의하시기 바랍니다.';
			var ko_msg_EAU004 = '접속 가능한 아이피 정보가 아닙니다.<br/>관리자에게 문의하시기 바랍니다.';
			var ko_msg_EAU005 = '정상적인 접근 경로가 아닙니다.\n\n잠시후 다시 시도하여 주십시요.';
			var ko_msg_EAU009 = '아이디 또는 비밀번호 오류 횟수를 초과하여 접속이 불가합니다.<br/>관리자에게 문의하시기 바랍니다.';
			var ko_msg_EAU013 = '세션이 만료되었습니다.\n\n잠시후 다시 시도하여 주십시요.';
			var ko_msg_EOP001 = '해당 시스템에 대한 접속 권한이 없습니다.<br/>관리자에게 문의하시기 바랍니다.<br/>* 졸업생은 접속 불가하며, 메일시스템은 https://mail.postech.ac.kr로 접속 바랍니다.';
			var ko_msg_EOTP001 = '[2차 인증] 필수 파라미터가 누락 되었습니다.';
			var ko_msg_EOTP004 = '[2차 인증] 기관 정보가 존재하지 않습니다.';
			var ko_msg_EOTP005 = '[2차 인증] 서비스 정보가 존재하지 않습니다.\n ※ 2차인증 APP을 등록하지 않으셨나요?\n 교외 인터넷망에서 접속 시 2차 인증이 필요합니다.\n 본인 소유의 스마트폰에 2차인증APP설치가 필요하오니 \n 로그인 화면의 “2차인증 등록 안내”를 참고하여\n 2차인증 APP을 설치하고 로그인을 재시도하기 바랍니다. \n문의처: 054-279-2514, security@postech.ac.kr';
			var ko_msg_EOTP006 = '[2차 인증] 사용자 정보가 존재하지 않습니다.<br/>스톤패스 앱을 설치 및 사용자 등록 후 다시 시도 해 주시기 바랍니다.';
			var ko_msg_EOTP007 = '[2차 인증] 간편인증 등록을 미 완료 하셨습니다.<br/>스톤패스 앱에서 간편인증을 완료 후 다시 시도해 주시기 바랍니다.';
			var ko_msg_EOTP011 = '[2차 인증] 등록된 인증 정보가 존재하지 않습니다. 스톤패스 앱에서 인증수단 정보를 등록 후 다시 시도 해 주시기 바랍니다.';
			var ko_msg_EOTP013 = '[2차 인증] 유효하지 않은 토큰입니다.';
			var ko_msg_EOTP014 = '[2차 인증] 2차인증 유효시간이 초과되었습니다.<br/>다시 로그인 시도 바랍니다. ';
			var ko_msg_etc = '시스템 오류가 발생하였습니다.<br/>관리자에게 문의하시기 바랍니다.';
			
			var en_msg_fail = 'Your id or password is incorrect.';
			var en_msg_SS0004 = 'Log in for the first time and go to the password change screen.\n\nPlease change your password.';
			var en_msg_SS0005 = 'Move to password change screen using reset password.\n\nPlease change your password.';
			var en_msg_SS0006 = 'This is a dormant account.';
			var en_msg_SS0007 = 'You will need to agree to re-join to go to the agreement.\n\nPlease accept the terms.';
			var en_msg_SS0008 = 'You are using an old password and you are redirected to the password change screen.\n\nPlease change your password.';
			var en_msg_EAU003 = 'The connection period is before or expired.<br/>Please contact your administrator.';
			var en_msg_EAU004 = 'It is not accessible IP information.<br/>Please contact your administrator.';
			var en_msg_EAU005 = 'This is not a normal access path.\n\nPlease try again later.';
			var en_msg_EAU009 = 'Unable to access more than the number of userid or password errors.<br/>Please contact your administrator.';
			var en_msg_EAU013 = 'The session has expired.\n\nPlease try again later.';
			var en_msg_EOP001 = 'You do not have permission to access this system.<br/>Please contact your administrator.<br/>* Graduates cannot access. Please access the mail system at https://mail.postech.ac.kr';
			var en_msg_EOTP001 = '[Secondary Authentication] Required parameter is missing.';
			var en_msg_EOTP004 = '[Secondary Authentication] Organization information does not exist.';
			var en_msg_EOTP005 = '[Secondary Authentication] Service information does not exist.\n\n Did not register the APP?\n 1. Search and download StonePASS from the Play Store / App Store.\n2. Service ID(POSTECH) registration and portal login Please check your account information.\n 3. Please register your authentication method.\n 4. When the app is authenticated, it is logged in.';
			var en_msg_EOTP006 = '[Secondary Authentication] User information does not exist.<br/> Please install the Stonepass app and register again and try again.';
			var en_msg_EOTP007 = '[Secondary Authentication] You have not completed the simple authentication registration.<br/>Please try again after completing the simple authentication in the Stone Pass app.';
			var en_msg_EOTP011 = '[Secondary Authentication] The registered authentication information does not exist. Please try again after registering the authentication method information in the Stone Pass app.';
			var en_msg_EOTP013 = '[Secondary Authentication] Invalid token.';
			var en_msg_EOTP014 = '[Secondary Authentication] Token validity timed out.<br/>Please try logging in again.';
			
			var en_msg_etc = 'A system error has occurred.<br/>Please contact your administrator.';
			
				
			var code = obj_data.code;
			var value = '';
			var message = eval(lang + '_msg_fail');
			
			if( code == 'SS0004' ) {
				message = eval(lang + '_msg_SS0004');
			} else if( code == 'SS0005' ) {
				message = eval(lang + '_msg_SS0005');
			} else if( code == 'SS0006' ) {
				message = eval(lang + '_msg_SS0006');
			} else if( code == 'SS0007' ) {
				message = eval(lang + '_msg_SS0007');
			} else if( code == 'SS0008' ) {
				value = obj_data.data;
				message = eval(lang + '_msg_SS0008');
			} else if( code == 'SS0009' ) {
				value = obj_data.data;
				
				if(lang == 'ko') {
					message = '[' + value + '] IP 에서 접속중인 계정입니다.\n\n이전 접속을 종료하고 계속 진행하시겠습니까?';
				} else {
					message = 'This account is being accessed from [' + value + '] IP.\n\nWould you like to close your previous connection and continue?';
				}
			} else if( code == 'EAU001' ) {
				
			} else if( code == 'EAU002' ) {
				
			} else if( code == 'EAU003' ) {
				message = eval(lang + '_msg_EAU003');
			} else if( code == 'EAU004' ) {
				message = eval(lang + '_msg_EAU004');
			} else if( code == 'EAU005' ) {
				message = eval(lang + '_msg_EAU005') + ' [' + code + ']';
			} else if( code == 'EAU006' ) {
				message = eval(lang + '_msg_EAU005') + ' [' + code + ']';
			} else if( code == 'EAU007' ) {
				message = eval(lang + '_msg_EAU005') + ' [' + code + ']';
			} else if( code == 'EAU008' ) {
				value = obj_data.data;
				//message = '아이디 또는 비밀번호 오류 횟수를 초과하여 ' + value + '분 동안 접속이 불가합니다.\n\n잠시후 다시 시도하여 주십시요.';
			
				if(lang == 'ko') {
					message = '아이디 또는 비밀번호 오류 횟수를 초과하여 ' + value + '분 동안 접속이 불가합니다.<br/>잠시후 다시 시도하여 주십시요.';
				} else {
					message = 'You will not be able to connect for ' + value + 'minutes because of too many ID or password errors.<br/>Please try again later.';
				}
			} else if( code == 'EAU009' ) {
				//message = '아이디 또는 비밀번호 오류 횟수를 초과하여 접속이 불가합니다.\n\n관리자에게 문의하시기 바랍니다.';
				message = eval(lang + '_msg_EAU009');
			} else if( code == 'EAU012' ) {
				value = obj_data.data;
				if(lang == 'ko') {
					message = '아이디 또는 비밀번호 오류 횟수를 초과하여 ' + value + '분 동안 접속이 불가합니다.<br/>잠시후 다시 시도하여 주십시요.';
				} else {
					message = 'You will not be able to connect for ' + value + 'minutes because of too many ID or password errors.<br/>Please try again later.';
				}
				//message = '아이디 또는 비밀번호 오류 횟수를 초과하여 ' + value + '분 동안 접속이 불가합니다.\n\n잠시후 다시 시도하여 주십시요.';
			} else if( code == 'EAU013' ) {
				message = eval(lang + '_msg_EAU013');
			} else if( code == 'EOP001' ) {
				message = eval(lang + '_msg_EOP001');
			
			} else if( code == 'EOTP005' || code == 'EOTP006' || code == 'EOTP011' || code == 'EOTP017' ) {
				message = eval(lang + '_msg_EOTP005');
			} else if( code.indexOf( 'EOTP' ) > -1 ) {
				message = eval(lang + '_msg_EOTP') + ' [' + code + ']';
				
			} else {
				message = eval(lang + '_msg_etc') + ' [' + code + ']';
			}
			
			return message;
		}
	};
	
})();


var passwordModule = (function () {
	
	var server_url;
	
	function fn_encrypt_data(data) {
		
		var passni_key = CryptoJS.enc.Hex.parse(client_calkey.substring(0, 64));
		var passni_iv = CryptoJS.enc.Hex.parse(client_calkey.substring(64, 96));

		var byte_data = CryptoJS.SEED.encrypt(data, passni_key, {
			iv : passni_iv,
			mode : CryptoJS.mode.CBC,
			padding : CryptoJS.pad.AnsiX923
		});

		var encrypt_data = byte_data.ciphertext.toString();
		
		return encrypt_data;
	}
	
	function fn_server_request(req_data) {
		
		var obj_data;
		
		$.ajax({
			url: server_url,
			type: 'post',
			data: req_data,
			dataType: 'json',
			async: false,
			success: function (responseData)
			{
				obj_data = responseData;
			},
			error: function ()
			{
				alert('시스템 오류가 발생하였습니다. 관리자에게 문의하시기 바랍니다.[connect](A system error has occurred. Please contact your administrator.)');
			}
		});
		
		return obj_data;
	}
	
	return {
		
		change: function(url) {
			
			server_url = url;
			
			var pw_current_password = $.trim( $('#pw_current_password').val() );
			var pw_new_password = $.trim( $('#pw_new_password').val() );
			var pw_new_password_confirm = $.trim( $('#pw_new_password_confirm').val() );
			
			if (client_calkey == '' || client_calkey.length == 0) {
				alert('시스템 오류가 발생하였습니다. 관리자에게 문의하시기 바랍니다.[CalculateKey](A system error has occurred. Please contact your administrator.)');
				return null;
			}
			
			if (pw_current_password == '') {
				alert('이전 비밀번호를 입력해 주십시오.(Please enter your password.)');
				$('#pw_current_password').focus();
				return null;
			}
			
			if (pw_new_password == '') {
				alert('신규 비밀번호를 입력해 주십시오.(Please enter your new password.)');
				$('#pw_new_password').focus();
				return null;
			}
			
			if (pw_new_password_confirm == '') {
				alert('신규 비밀번호 확인을 입력해 주십시오.(Please re-enter your new password.)');
				$('#pw_new_password_confirm').focus();
				return null;
			}
			
			// 관리자 패스워드 정책 체크
			var passwordPolicyCheckResult = PolicyValidator.checkPasswordPolicy('pw_new_password', 'pw_new_password_confirm', 'pw_current_password');

			if ( !passwordPolicyCheckResult.flag )
			{
				alert(passwordPolicyCheckResult.message);

				$(this).blur();
				$('#pw_new_password').focus();

				return null;
			}
			
			$('#pw_current_password').val('');
			$('#pw_new_password').val('');
			$('#pw_new_password_confirm').val('');
			
			var jsonObj = {'pw_current_password':pw_current_password,'pw_new_password':pw_new_password};
			var jsonStr = JSON.stringify(jsonObj);
			
			var user_data = fn_encrypt_data(jsonStr);
			
			var req_data = 'user_data=' + user_data + '&login_key=' + $('#login_key').val();
			
			var obj_data = fn_server_request(req_data);
			
			return obj_data;
		},
	
		message:function(obj_data) {
				
			var code = obj_data.code;
			var value = '';
			var message = '';
			
			if( code == 'SS0001' ) {
				message = '비밀번호가 정상적으로 변경되었습니다.(Your password has been changed.)';
			} else if( code == 'SS0009' ) {
				value = obj_data.data;
				message = '비밀번호가 정상적으로 변경되었습니다.(Your password has been changed.)\n\n';
				message += '[' + value + '] IP 에서 접속중인 계정입니다.\n\n이전 접속을 종료하고 계속 진행하시겠습니까?';
				message += '(This account is being accessed from [' + value + '] IP.\n\nWould you like to close your previous connection and continue?)';
			} else if( code == 'EAU005' ) {
				message = '정상적인 접근 경로가 아닙니다. 잠시후 다시 시도하여 주십시요.(This is not a normal access path. Please try again later.)';
			} else if( code == 'EAU006' ) {
				message = '정상적인 접근 경로가 아닙니다. 로그인 화면으로 이동합니다.(This is not a normal access path. Go to the login screen.)';
			} else if( code == 'EAU010' ) {
				message = '사용자 정보가 조회되지 않아 비밀번호 변경에 실패하였습니다.(Password change failed because user information was not queried.)';
			} else if( code == 'EAU011' ) {
				message = '이전 비밀번호가 일치하지 않습니다.(Old passwords do not match)';
			} else {
				message = '시스템 오류가 발생하였습니다. 관리자에게 문의하시기 바랍니다.[' + code + '](A system error has occurred. Please contact your administrator.)';
			}
			
			return message;
		}
	};
	
})();



function X9ECParameters(curve,g,n,h) {
    this.curve = curve;
    this.g = g;
    this.n = n;
    this.h = h;
}

function x9getCurve() {
    return this.curve;
}

function x9getG() {
    return this.g;
}

function x9getN() {
    return this.n;
}

function x9getH() {
    return this.h;
}

X9ECParameters.prototype.getCurve = x9getCurve;
X9ECParameters.prototype.getG = x9getG;
X9ECParameters.prototype.getN = x9getN;
X9ECParameters.prototype.getH = x9getH;

// ----------------
// SECNamedCurves

function fromHex(s) { return new BigInteger(s, 16); }

function secp224r1() {
    // p = 2^224 - 2^96 + 1
    var p = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001");
    var a = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE");
    var b = fromHex("B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4");
    //byte[] S = Hex.decode("BD71344799D5C7FCDC45B59FA3B9AB8F6A948BC5");
    var n = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D");
    var h = BigInteger.ONE;
    var curve = new ECCurveFp(p, a, b);
    var G = curve.decodePointHex("04"
                + "B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21"
                + "BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34");
    return new X9ECParameters(curve, G, n, h);
}

function secp256r1() {
    // p = 2^224 (2^32 - 1) + 2^192 + 2^96 - 1
    var p = fromHex("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF");
    var a = fromHex("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC");
    var b = fromHex("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B");
    //byte[] S = Hex.decode("C49D360886E704936A6678E1139D26B7819F7E90");
    var n = fromHex("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");
    var h = BigInteger.ONE;
    var curve = new ECCurveFp(p, a, b);
    var G = curve.decodePointHex("04"
                + "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"
                + "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5");
    return new X9ECParameters(curve, G, n, h);
}

// make this into a proper hashtable
function getSECCurveByName(name) {
    if(name == "secp224r1") return secp224r1();
    if(name == "secp256r1") return secp256r1();
    return null;
}

// Copyright (c) 2005  Tom Wu
// All Rights Reserved.
// See "LICENSE" for details.

// Basic JavaScript BN library - subset useful for RSA encryption.

// Bits per digit
var dbits;

// JavaScript engine analysis
var canary = 0xdeadbeefcafe;
var j_lm = ((canary&0xffffff)==0xefcafe);

// (public) Constructor
function BigInteger(a,b,c) {
  if(a != null)
    if("number" == typeof a) this.fromNumber(a,b,c);
    else if(b == null && "string" != typeof a) this.fromString(a,256);
    else this.fromString(a,b);
}

// return new, unset BigInteger
function nbi() { return new BigInteger(null); }

// am: Compute w_j += (x*this_i), propagate carries,
// c is initial carry, returns final carry.
// c < 3*dvalue, x < 2*dvalue, this_i < dvalue
// We need to select the fastest one that works in this environment.

// am1: use a single mult and divide to get the high bits,
// max digit bits should be 26 because
// max internal value = 2*dvalue^2-2*dvalue (< 2^53)
function am1(i,x,w,j,c,n) {
  while(--n >= 0) {
    var v = x*this[i++]+w[j]+c;
    c = Math.floor(v/0x4000000);
    w[j++] = v&0x3ffffff;
  }
  return c;
}
// am2 avoids a big mult-and-extract completely.
// Max digit bits should be <= 30 because we do bitwise ops
// on values up to 2*hdvalue^2-hdvalue-1 (< 2^31)
function am2(i,x,w,j,c,n) {
  var xl = x&0x7fff, xh = x>>15;
  while(--n >= 0) {
    var l = this[i]&0x7fff;
    var h = this[i++]>>15;
    var m = xh*l+h*xl;
    l = xl*l+((m&0x7fff)<<15)+w[j]+(c&0x3fffffff);
    c = (l>>>30)+(m>>>15)+xh*h+(c>>>30);
    w[j++] = l&0x3fffffff;
  }
  return c;
}
// Alternately, set max digit bits to 28 since some
// browsers slow down when dealing with 32-bit numbers.
function am3(i,x,w,j,c,n) {
  var xl = x&0x3fff, xh = x>>14;
  while(--n >= 0) {
    var l = this[i]&0x3fff;
    var h = this[i++]>>14;
    var m = xh*l+h*xl;
    l = xl*l+((m&0x3fff)<<14)+w[j]+c;
    c = (l>>28)+(m>>14)+xh*h;
    w[j++] = l&0xfffffff;
  }
  return c;
}
if(j_lm && (navigator.appName == "Microsoft Internet Explorer")) {
  BigInteger.prototype.am = am2;
  dbits = 30;
}
else if(j_lm && (navigator.appName != "Netscape")) {
  BigInteger.prototype.am = am1;
  dbits = 26;
}
else { // Mozilla/Netscape seems to prefer am3
  BigInteger.prototype.am = am3;
  dbits = 28;
}

BigInteger.prototype.DB = dbits;
BigInteger.prototype.DM = ((1<<dbits)-1);
BigInteger.prototype.DV = (1<<dbits);

var BI_FP = 52;
BigInteger.prototype.FV = Math.pow(2,BI_FP);
BigInteger.prototype.F1 = BI_FP-dbits;
BigInteger.prototype.F2 = 2*dbits-BI_FP;

// Digit conversions
var BI_RM = "0123456789abcdefghijklmnopqrstuvwxyz";
var BI_RC = new Array();
var rr,vv;
rr = "0".charCodeAt(0);
for(vv = 0; vv <= 9; ++vv) BI_RC[rr++] = vv;
rr = "a".charCodeAt(0);
for(vv = 10; vv < 36; ++vv) BI_RC[rr++] = vv;
rr = "A".charCodeAt(0);
for(vv = 10; vv < 36; ++vv) BI_RC[rr++] = vv;

function int2char(n) { return BI_RM.charAt(n); }
function intAt(s,i) {
  var c = BI_RC[s.charCodeAt(i)];
  return (c==null)?-1:c;
}

// (protected) copy this to r
function bnpCopyTo(r) {
  for(var i = this.t-1; i >= 0; --i) r[i] = this[i];
  r.t = this.t;
  r.s = this.s;
}

// (protected) set from integer value x, -DV <= x < DV
function bnpFromInt(x) {
  this.t = 1;
  this.s = (x<0)?-1:0;
  if(x > 0) this[0] = x;
  else if(x < -1) this[0] = x+this.DV;
  else this.t = 0;
}

// return bigint initialized to value
function nbv(i) { var r = nbi(); r.fromInt(i); return r; }

// (protected) set from string and radix
function bnpFromString(s,b) {
  var k;
  if(b == 16) k = 4;
  else if(b == 8) k = 3;
  else if(b == 256) k = 8; // byte array
  else if(b == 2) k = 1;
  else if(b == 32) k = 5;
  else if(b == 4) k = 2;
  else { this.fromRadix(s,b); return; }
  this.t = 0;
  this.s = 0;
  var i = s.length, mi = false, sh = 0;
  while(--i >= 0) {
    var x = (k==8)?s[i]&0xff:intAt(s,i);
    if(x < 0) {
      if(s.charAt(i) == "-") mi = true;
      continue;
    }
    mi = false;
    if(sh == 0)
      this[this.t++] = x;
    else if(sh+k > this.DB) {
      this[this.t-1] |= (x&((1<<(this.DB-sh))-1))<<sh;
      this[this.t++] = (x>>(this.DB-sh));
    }
    else
      this[this.t-1] |= x<<sh;
    sh += k;
    if(sh >= this.DB) sh -= this.DB;
  }
  if(k == 8 && (s[0]&0x80) != 0) {
    this.s = -1;
    if(sh > 0) this[this.t-1] |= ((1<<(this.DB-sh))-1)<<sh;
  }
  this.clamp();
  if(mi) BigInteger.ZERO.subTo(this,this);
}

// (protected) clamp off excess high words
function bnpClamp() {
  var c = this.s&this.DM;
  while(this.t > 0 && this[this.t-1] == c) --this.t;
}

// (public) return string representation in given radix
function bnToString(b) {
  if(this.s < 0) return "-"+this.negate().toString(b);
  var k;
  if(b == 16) k = 4;
  else if(b == 8) k = 3;
  else if(b == 2) k = 1;
  else if(b == 32) k = 5;
  else if(b == 4) k = 2;
  else return this.toRadix(b);
  var km = (1<<k)-1, d, m = false, r = "", i = this.t;
  var p = this.DB-(i*this.DB)%k;
  if(i-- > 0) {
    if(p < this.DB && (d = this[i]>>p) > 0) { m = true; r = int2char(d); }
    while(i >= 0) {
      if(p < k) {
        d = (this[i]&((1<<p)-1))<<(k-p);
        d |= this[--i]>>(p+=this.DB-k);
      }
      else {
        d = (this[i]>>(p-=k))&km;
        if(p <= 0) { p += this.DB; --i; }
      }
      if(d > 0) m = true;
      if(m) r += int2char(d);
    }
  }
  return m?r:"0";
}

// (public) -this
function bnNegate() { var r = nbi(); BigInteger.ZERO.subTo(this,r); return r; }

// (public) |this|
function bnAbs() { return (this.s<0)?this.negate():this; }

// (public) return + if this > a, - if this < a, 0 if equal
function bnCompareTo(a) {
  var r = this.s-a.s;
  if(r != 0) return r;
  var i = this.t;
  r = i-a.t;
  if(r != 0) return (this.s<0)?-r:r;
  while(--i >= 0) if((r=this[i]-a[i]) != 0) return r;
  return 0;
}

// returns bit length of the integer x
function nbits(x) {
  var r = 1, t;
  if((t=x>>>16) != 0) { x = t; r += 16; }
  if((t=x>>8) != 0) { x = t; r += 8; }
  if((t=x>>4) != 0) { x = t; r += 4; }
  if((t=x>>2) != 0) { x = t; r += 2; }
  if((t=x>>1) != 0) { x = t; r += 1; }
  return r;
}

// (public) return the number of bits in "this"
function bnBitLength() {
  if(this.t <= 0) return 0;
  return this.DB*(this.t-1)+nbits(this[this.t-1]^(this.s&this.DM));
}

// (protected) r = this << n*DB
function bnpDLShiftTo(n,r) {
  var i;
  for(i = this.t-1; i >= 0; --i) r[i+n] = this[i];
  for(i = n-1; i >= 0; --i) r[i] = 0;
  r.t = this.t+n;
  r.s = this.s;
}

// (protected) r = this >> n*DB
function bnpDRShiftTo(n,r) {
  for(var i = n; i < this.t; ++i) r[i-n] = this[i];
  r.t = Math.max(this.t-n,0);
  r.s = this.s;
}

// (protected) r = this << n
function bnpLShiftTo(n,r) {
  var bs = n%this.DB;
  var cbs = this.DB-bs;
  var bm = (1<<cbs)-1;
  var ds = Math.floor(n/this.DB), c = (this.s<<bs)&this.DM, i;
  for(i = this.t-1; i >= 0; --i) {
    r[i+ds+1] = (this[i]>>cbs)|c;
    c = (this[i]&bm)<<bs;
  }
  for(i = ds-1; i >= 0; --i) r[i] = 0;
  r[ds] = c;
  r.t = this.t+ds+1;
  r.s = this.s;
  r.clamp();
}

// (protected) r = this >> n
function bnpRShiftTo(n,r) {
  r.s = this.s;
  var ds = Math.floor(n/this.DB);
  if(ds >= this.t) { r.t = 0; return; }
  var bs = n%this.DB;
  var cbs = this.DB-bs;
  var bm = (1<<bs)-1;
  r[0] = this[ds]>>bs;
  for(var i = ds+1; i < this.t; ++i) {
    r[i-ds-1] |= (this[i]&bm)<<cbs;
    r[i-ds] = this[i]>>bs;
  }
  if(bs > 0) r[this.t-ds-1] |= (this.s&bm)<<cbs;
  r.t = this.t-ds;
  r.clamp();
}

// (protected) r = this - a
function bnpSubTo(a,r) {
  var i = 0, c = 0, m = Math.min(a.t,this.t);
  while(i < m) {
    c += this[i]-a[i];
    r[i++] = c&this.DM;
    c >>= this.DB;
  }
  if(a.t < this.t) {
    c -= a.s;
    while(i < this.t) {
      c += this[i];
      r[i++] = c&this.DM;
      c >>= this.DB;
    }
    c += this.s;
  }
  else {
    c += this.s;
    while(i < a.t) {
      c -= a[i];
      r[i++] = c&this.DM;
      c >>= this.DB;
    }
    c -= a.s;
  }
  r.s = (c<0)?-1:0;
  if(c < -1) r[i++] = this.DV+c;
  else if(c > 0) r[i++] = c;
  r.t = i;
  r.clamp();
}

// (protected) r = this * a, r != this,a (HAC 14.12)
// "this" should be the larger one if appropriate.
function bnpMultiplyTo(a,r) {
  var x = this.abs(), y = a.abs();
  var i = x.t;
  r.t = i+y.t;
  while(--i >= 0) r[i] = 0;
  for(i = 0; i < y.t; ++i) r[i+x.t] = x.am(0,y[i],r,i,0,x.t);
  r.s = 0;
  r.clamp();
  if(this.s != a.s) BigInteger.ZERO.subTo(r,r);
}

// (protected) r = this^2, r != this (HAC 14.16)
function bnpSquareTo(r) {
  var x = this.abs();
  var i = r.t = 2*x.t;
  while(--i >= 0) r[i] = 0;
  for(i = 0; i < x.t-1; ++i) {
    var c = x.am(i,x[i],r,2*i,0,1);
    if((r[i+x.t]+=x.am(i+1,2*x[i],r,2*i+1,c,x.t-i-1)) >= x.DV) {
      r[i+x.t] -= x.DV;
      r[i+x.t+1] = 1;
    }
  }
  if(r.t > 0) r[r.t-1] += x.am(i,x[i],r,2*i,0,1);
  r.s = 0;
  r.clamp();
}

// (protected) divide this by m, quotient and remainder to q, r (HAC 14.20)
// r != q, this != m.  q or r may be null.
function bnpDivRemTo(m,q,r) {
  var pm = m.abs();
  if(pm.t <= 0) return;
  var pt = this.abs();
  if(pt.t < pm.t) {
    if(q != null) q.fromInt(0);
    if(r != null) this.copyTo(r);
    return;
  }
  if(r == null) r = nbi();
  var y = nbi(), ts = this.s, ms = m.s;
  var nsh = this.DB-nbits(pm[pm.t-1]);	// normalize modulus
  if(nsh > 0) { pm.lShiftTo(nsh,y); pt.lShiftTo(nsh,r); }
  else { pm.copyTo(y); pt.copyTo(r); }
  var ys = y.t;
  var y0 = y[ys-1];
  if(y0 == 0) return;
  var yt = y0*(1<<this.F1)+((ys>1)?y[ys-2]>>this.F2:0);
  var d1 = this.FV/yt, d2 = (1<<this.F1)/yt, e = 1<<this.F2;
  var i = r.t, j = i-ys, t = (q==null)?nbi():q;
  y.dlShiftTo(j,t);
  if(r.compareTo(t) >= 0) {
    r[r.t++] = 1;
    r.subTo(t,r);
  }
  BigInteger.ONE.dlShiftTo(ys,t);
  t.subTo(y,y);	// "negative" y so we can replace sub with am later
  while(y.t < ys) y[y.t++] = 0;
  while(--j >= 0) {
    // Estimate quotient digit
    var qd = (r[--i]==y0)?this.DM:Math.floor(r[i]*d1+(r[i-1]+e)*d2);
    if((r[i]+=y.am(0,qd,r,j,0,ys)) < qd) {	// Try it out
      y.dlShiftTo(j,t);
      r.subTo(t,r);
      while(r[i] < --qd) r.subTo(t,r);
    }
  }
  if(q != null) {
    r.drShiftTo(ys,q);
    if(ts != ms) BigInteger.ZERO.subTo(q,q);
  }
  r.t = ys;
  r.clamp();
  if(nsh > 0) r.rShiftTo(nsh,r);	// Denormalize remainder
  if(ts < 0) BigInteger.ZERO.subTo(r,r);
}

// (public) this mod a
function bnMod(a) {
  var r = nbi();
  this.abs().divRemTo(a,null,r);
  if(this.s < 0 && r.compareTo(BigInteger.ZERO) > 0) a.subTo(r,r);
  return r;
}

// Modular reduction using "classic" algorithm
function Classic(m) { this.m = m; }
function cConvert(x) {
  if(x.s < 0 || x.compareTo(this.m) >= 0) return x.mod(this.m);
  else return x;
}
function cRevert(x) { return x; }
function cReduce(x) { x.divRemTo(this.m,null,x); }
function cMulTo(x,y,r) { x.multiplyTo(y,r); this.reduce(r); }
function cSqrTo(x,r) { x.squareTo(r); this.reduce(r); }

Classic.prototype.convert = cConvert;
Classic.prototype.revert = cRevert;
Classic.prototype.reduce = cReduce;
Classic.prototype.mulTo = cMulTo;
Classic.prototype.sqrTo = cSqrTo;

// (protected) return "-1/this % 2^DB"; useful for Mont. reduction
// justification:
//         xy == 1 (mod m)
//         xy =  1+km
//   xy(2-xy) = (1+km)(1-km)
// x[y(2-xy)] = 1-k^2m^2
// x[y(2-xy)] == 1 (mod m^2)
// if y is 1/x mod m, then y(2-xy) is 1/x mod m^2
// should reduce x and y(2-xy) by m^2 at each step to keep size bounded.
// JS multiply "overflows" differently from C/C++, so care is needed here.
function bnpInvDigit() {
  if(this.t < 1) return 0;
  var x = this[0];
  if((x&1) == 0) return 0;
  var y = x&3;		// y == 1/x mod 2^2
  y = (y*(2-(x&0xf)*y))&0xf;	// y == 1/x mod 2^4
  y = (y*(2-(x&0xff)*y))&0xff;	// y == 1/x mod 2^8
  y = (y*(2-(((x&0xffff)*y)&0xffff)))&0xffff;	// y == 1/x mod 2^16
  // last step - calculate inverse mod DV directly;
  // assumes 16 < DB <= 32 and assumes ability to handle 48-bit ints
  y = (y*(2-x*y%this.DV))%this.DV;		// y == 1/x mod 2^dbits
  // we really want the negative inverse, and -DV < y < DV
  return (y>0)?this.DV-y:-y;
}

// Montgomery reduction
function Montgomery(m) {
  this.m = m;
  this.mp = m.invDigit();
  this.mpl = this.mp&0x7fff;
  this.mph = this.mp>>15;
  this.um = (1<<(m.DB-15))-1;
  this.mt2 = 2*m.t;
}

// xR mod m
function montConvert(x) {
  var r = nbi();
  x.abs().dlShiftTo(this.m.t,r);
  r.divRemTo(this.m,null,r);
  if(x.s < 0 && r.compareTo(BigInteger.ZERO) > 0) this.m.subTo(r,r);
  return r;
}

// x/R mod m
function montRevert(x) {
  var r = nbi();
  x.copyTo(r);
  this.reduce(r);
  return r;
}

// x = x/R mod m (HAC 14.32)
function montReduce(x) {
  while(x.t <= this.mt2)	// pad x so am has enough room later
    x[x.t++] = 0;
  for(var i = 0; i < this.m.t; ++i) {
    // faster way of calculating u0 = x[i]*mp mod DV
    var j = x[i]&0x7fff;
    var u0 = (j*this.mpl+(((j*this.mph+(x[i]>>15)*this.mpl)&this.um)<<15))&x.DM;
    // use am to combine the multiply-shift-add into one call
    j = i+this.m.t;
    x[j] += this.m.am(0,u0,x,i,0,this.m.t);
    // propagate carry
    while(x[j] >= x.DV) { x[j] -= x.DV; x[++j]++; }
  }
  x.clamp();
  x.drShiftTo(this.m.t,x);
  if(x.compareTo(this.m) >= 0) x.subTo(this.m,x);
}

// r = "x^2/R mod m"; x != r
function montSqrTo(x,r) { x.squareTo(r); this.reduce(r); }

// r = "xy/R mod m"; x,y != r
function montMulTo(x,y,r) { x.multiplyTo(y,r); this.reduce(r); }

Montgomery.prototype.convert = montConvert;
Montgomery.prototype.revert = montRevert;
Montgomery.prototype.reduce = montReduce;
Montgomery.prototype.mulTo = montMulTo;
Montgomery.prototype.sqrTo = montSqrTo;

// (protected) true iff this is even
function bnpIsEven() { return ((this.t>0)?(this[0]&1):this.s) == 0; }

// (protected) this^e, e < 2^32, doing sqr and mul with "r" (HAC 14.79)
function bnpExp(e,z) {
  if(e > 0xffffffff || e < 1) return BigInteger.ONE;
  var r = nbi(), r2 = nbi(), g = z.convert(this), i = nbits(e)-1;
  g.copyTo(r);
  while(--i >= 0) {
    z.sqrTo(r,r2);
    if((e&(1<<i)) > 0) z.mulTo(r2,g,r);
    else { var t = r; r = r2; r2 = t; }
  }
  return z.revert(r);
}

// (public) this^e % m, 0 <= e < 2^32
function bnModPowInt(e,m) {
  var z;
  if(e < 256 || m.isEven()) z = new Classic(m); else z = new Montgomery(m);
  return this.exp(e,z);
}

// protected
BigInteger.prototype.copyTo = bnpCopyTo;
BigInteger.prototype.fromInt = bnpFromInt;
BigInteger.prototype.fromString = bnpFromString;
BigInteger.prototype.clamp = bnpClamp;
BigInteger.prototype.dlShiftTo = bnpDLShiftTo;
BigInteger.prototype.drShiftTo = bnpDRShiftTo;
BigInteger.prototype.lShiftTo = bnpLShiftTo;
BigInteger.prototype.rShiftTo = bnpRShiftTo;
BigInteger.prototype.subTo = bnpSubTo;
BigInteger.prototype.multiplyTo = bnpMultiplyTo;
BigInteger.prototype.squareTo = bnpSquareTo;
BigInteger.prototype.divRemTo = bnpDivRemTo;
BigInteger.prototype.invDigit = bnpInvDigit;
BigInteger.prototype.isEven = bnpIsEven;
BigInteger.prototype.exp = bnpExp;

// public
BigInteger.prototype.toString = bnToString;
BigInteger.prototype.negate = bnNegate;
BigInteger.prototype.abs = bnAbs;
BigInteger.prototype.compareTo = bnCompareTo;
BigInteger.prototype.bitLength = bnBitLength;
BigInteger.prototype.mod = bnMod;
BigInteger.prototype.modPowInt = bnModPowInt;

// "constants"
BigInteger.ZERO = nbv(0);
BigInteger.ONE = nbv(1);

// Basic Javascript Elliptic Curve implementation
// Ported loosely from BouncyCastle's Java EC code
// Only Fp curves implemented for now

// Requires jsbn.js and jsbn2.js

// ----------------
// ECFieldElementFp

// constructor
function ECFieldElementFp(q,x) {
    this.x = x;
    // if(x.compareTo(q) >= 0) error
    this.q = q;
}

function feFpEquals(other) {
    if(other == this) return true;
    return (this.q.equals(other.q) && this.x.equals(other.x));
}

function feFpToBigInteger() {
    return this.x;
}

function feFpNegate() {
    return new ECFieldElementFp(this.q, this.x.negate().mod(this.q));
}

function feFpAdd(b) {
    return new ECFieldElementFp(this.q, this.x.add(b.toBigInteger()).mod(this.q));
}

function feFpSubtract(b) {
    return new ECFieldElementFp(this.q, this.x.subtract(b.toBigInteger()).mod(this.q));
}

function feFpMultiply(b) {
    return new ECFieldElementFp(this.q, this.x.multiply(b.toBigInteger()).mod(this.q));
}

function feFpSquare() {
    return new ECFieldElementFp(this.q, this.x.square().mod(this.q));
}

function feFpDivide(b) {
    return new ECFieldElementFp(this.q, this.x.multiply(b.toBigInteger().modInverse(this.q)).mod(this.q));
}

ECFieldElementFp.prototype.equals = feFpEquals;
ECFieldElementFp.prototype.toBigInteger = feFpToBigInteger;
ECFieldElementFp.prototype.negate = feFpNegate;
ECFieldElementFp.prototype.add = feFpAdd;
ECFieldElementFp.prototype.subtract = feFpSubtract;
ECFieldElementFp.prototype.multiply = feFpMultiply;
ECFieldElementFp.prototype.square = feFpSquare;
ECFieldElementFp.prototype.divide = feFpDivide;

// ----------------
// ECPointFp

// constructor
function ECPointFp(curve,x,y,z) {
    this.curve = curve;
    this.x = x;
    this.y = y;
    // Projective coordinates: either zinv == null or z * zinv == 1
    // z and zinv are just BigIntegers, not fieldElements
    if(z == null) {
      this.z = BigInteger.ONE;
    }
    else {
      this.z = z;
    }
    this.zinv = null;
    // compression flag
}

function pointFpGetX() {
    if(this.zinv == null) {
      this.zinv = this.z.modInverse(this.curve.q);
    }
    var r = this.x.toBigInteger().multiply(this.zinv);
    this.curve.reduce(r);
    return this.curve.fromBigInteger(r);
}

function pointFpGetY() {
    if(this.zinv == null) {
      this.zinv = this.z.modInverse(this.curve.q);
    }
    var r = this.y.toBigInteger().multiply(this.zinv);
    this.curve.reduce(r);
    return this.curve.fromBigInteger(r);
}

function pointFpEquals(other) {
    if(other == this) return true;
    if(this.isInfinity()) return other.isInfinity();
    if(other.isInfinity()) return this.isInfinity();
    var u, v;
    // u = Y2 * Z1 - Y1 * Z2
    u = other.y.toBigInteger().multiply(this.z).subtract(this.y.toBigInteger().multiply(other.z)).mod(this.curve.q);
    if(!u.equals(BigInteger.ZERO)) return false;
    // v = X2 * Z1 - X1 * Z2
    v = other.x.toBigInteger().multiply(this.z).subtract(this.x.toBigInteger().multiply(other.z)).mod(this.curve.q);
    return v.equals(BigInteger.ZERO);
}

function pointFpIsInfinity() {
    if((this.x == null) && (this.y == null)) return true;
    return this.z.equals(BigInteger.ZERO) && !this.y.toBigInteger().equals(BigInteger.ZERO);
}

function pointFpNegate() {
    return new ECPointFp(this.curve, this.x, this.y.negate(), this.z);
}

function pointFpAdd(b) {
    if(this.isInfinity()) return b;
    if(b.isInfinity()) return this;

    // u = Y2 * Z1 - Y1 * Z2
    var u = b.y.toBigInteger().multiply(this.z).subtract(this.y.toBigInteger().multiply(b.z)).mod(this.curve.q);
    // v = X2 * Z1 - X1 * Z2
    var v = b.x.toBigInteger().multiply(this.z).subtract(this.x.toBigInteger().multiply(b.z)).mod(this.curve.q);

    if(BigInteger.ZERO.equals(v)) {
        if(BigInteger.ZERO.equals(u)) {
            return this.twice(); // this == b, so double
        }
	return this.curve.getInfinity(); // this = -b, so infinity
    }

    var THREE = new BigInteger("3");
    var x1 = this.x.toBigInteger();
    var y1 = this.y.toBigInteger();
    var x2 = b.x.toBigInteger();
    var y2 = b.y.toBigInteger();

    var v2 = v.square();
    var v3 = v2.multiply(v);
    var x1v2 = x1.multiply(v2);
    var zu2 = u.square().multiply(this.z);

    // x3 = v * (z2 * (z1 * u^2 - 2 * x1 * v^2) - v^3)
    var x3 = zu2.subtract(x1v2.shiftLeft(1)).multiply(b.z).subtract(v3).multiply(v).mod(this.curve.q);
    // y3 = z2 * (3 * x1 * u * v^2 - y1 * v^3 - z1 * u^3) + u * v^3
    var y3 = x1v2.multiply(THREE).multiply(u).subtract(y1.multiply(v3)).subtract(zu2.multiply(u)).multiply(b.z).add(u.multiply(v3)).mod(this.curve.q);
    // z3 = v^3 * z1 * z2
    var z3 = v3.multiply(this.z).multiply(b.z).mod(this.curve.q);

    return new ECPointFp(this.curve, this.curve.fromBigInteger(x3), this.curve.fromBigInteger(y3), z3);
}

function pointFpTwice() {
    if(this.isInfinity()) return this;
    if(this.y.toBigInteger().signum() == 0) return this.curve.getInfinity();

    // optimized handling of constants
    var THREE = new BigInteger("3");
    var x1 = this.x.toBigInteger();
    var y1 = this.y.toBigInteger();

    var y1z1 = y1.multiply(this.z);
    var y1sqz1 = y1z1.multiply(y1).mod(this.curve.q);
    var a = this.curve.a.toBigInteger();

    // w = 3 * x1^2 + a * z1^2
    var w = x1.square().multiply(THREE);
    if(!BigInteger.ZERO.equals(a)) {
      w = w.add(this.z.square().multiply(a));
    }
    w = w.mod(this.curve.q);
    //this.curve.reduce(w);
    // x3 = 2 * y1 * z1 * (w^2 - 8 * x1 * y1^2 * z1)
    var x3 = w.square().subtract(x1.shiftLeft(3).multiply(y1sqz1)).shiftLeft(1).multiply(y1z1).mod(this.curve.q);
    // y3 = 4 * y1^2 * z1 * (3 * w * x1 - 2 * y1^2 * z1) - w^3
    var y3 = w.multiply(THREE).multiply(x1).subtract(y1sqz1.shiftLeft(1)).shiftLeft(2).multiply(y1sqz1).subtract(w.square().multiply(w)).mod(this.curve.q);
    // z3 = 8 * (y1 * z1)^3
    var z3 = y1z1.square().multiply(y1z1).shiftLeft(3).mod(this.curve.q);

    return new ECPointFp(this.curve, this.curve.fromBigInteger(x3), this.curve.fromBigInteger(y3), z3);
}

// Simple NAF (Non-Adjacent Form) multiplication algorithm
// modularize the multiplication algorithm
function pointFpMultiply(k) {
    if(this.isInfinity()) return this;
    if(k.signum() == 0) return this.curve.getInfinity();

    var e = k;
    var h = e.multiply(new BigInteger("3"));

    var neg = this.negate();
    var R = this;

    var i;
    for(i = h.bitLength() - 2; i > 0; --i) {
	R = R.twice();

	var hBit = h.testBit(i);
	var eBit = e.testBit(i);

	if (hBit != eBit) {
	    R = R.add(hBit ? this : neg);
	}
    }

    return R;
}

// Compute this*j + x*k (simultaneous multiplication)
function pointFpMultiplyTwo(j,x,k) {
  var i;
  if(j.bitLength() > k.bitLength())
    i = j.bitLength() - 1;
  else
    i = k.bitLength() - 1;

  var R = this.curve.getInfinity();
  var both = this.add(x);
  while(i >= 0) {
    R = R.twice();
    if(j.testBit(i)) {
      if(k.testBit(i)) {
        R = R.add(both);
      }
      else {
        R = R.add(this);
      }
    }
    else {
      if(k.testBit(i)) {
        R = R.add(x);
      }
    }
    --i;
  }

  return R;
}

ECPointFp.prototype.getX = pointFpGetX;
ECPointFp.prototype.getY = pointFpGetY;
ECPointFp.prototype.equals = pointFpEquals;
ECPointFp.prototype.isInfinity = pointFpIsInfinity;
ECPointFp.prototype.negate = pointFpNegate;
ECPointFp.prototype.add = pointFpAdd;
ECPointFp.prototype.twice = pointFpTwice;
ECPointFp.prototype.multiply = pointFpMultiply;
ECPointFp.prototype.multiplyTwo = pointFpMultiplyTwo;

// ----------------
// ECCurveFp

// constructor
function ECCurveFp(q,a,b) {
    this.q = q;
    this.a = this.fromBigInteger(a);
    this.b = this.fromBigInteger(b);
    this.infinity = new ECPointFp(this, null, null);
    this.reducer = new Barrett(this.q);
}

function curveFpGetQ() {
    return this.q;
}

function curveFpGetA() {
    return this.a;
}

function curveFpGetB() {
    return this.b;
}

function curveFpEquals(other) {
    if(other == this) return true;
    return(this.q.equals(other.q) && this.a.equals(other.a) && this.b.equals(other.b));
}

function curveFpGetInfinity() {
    return this.infinity;
}

function curveFpFromBigInteger(x) {
    return new ECFieldElementFp(this.q, x);
}

function curveReduce(x) {
    this.reducer.reduce(x);
}

// for now, work with hex strings because they're easier in JS
function curveFpDecodePointHex(s) {
    switch(parseInt(s.substr(0,2), 16)) { // first byte
    case 0:
	return this.infinity;
    case 2:
    case 3:
	// point compression not supported yet
	return null;
    case 4:
    case 6:
    case 7:
	var len = (s.length - 2) / 2;
	var xHex = s.substr(2, len);
	var yHex = s.substr(len+2, len);

	return new ECPointFp(this,
			     this.fromBigInteger(new BigInteger(xHex, 16)),
			     this.fromBigInteger(new BigInteger(yHex, 16)));

    default: // unsupported
	return null;
    }
}

function curveFpEncodePointHex(p) {
	if (p.isInfinity()) return "00";
	var xHex = p.getX().toBigInteger().toString(16);
	var yHex = p.getY().toBigInteger().toString(16);
	var oLen = this.getQ().toString(16).length;
	if ((oLen % 2) != 0) oLen++;
	while (xHex.length < oLen) {
		xHex = "0" + xHex;
	}
	while (yHex.length < oLen) {
		yHex = "0" + yHex;
	}
	return "04" + xHex + yHex;
}

ECCurveFp.prototype.getQ = curveFpGetQ;
ECCurveFp.prototype.getA = curveFpGetA;
ECCurveFp.prototype.getB = curveFpGetB;
ECCurveFp.prototype.equals = curveFpEquals;
ECCurveFp.prototype.getInfinity = curveFpGetInfinity;
ECCurveFp.prototype.fromBigInteger = curveFpFromBigInteger;
ECCurveFp.prototype.reduce = curveReduce;
ECCurveFp.prototype.decodePointHex = curveFpDecodePointHex;
ECCurveFp.prototype.encodePointHex = curveFpEncodePointHex;

// Copyright (c) 2005-2009  Tom Wu
// All Rights Reserved.
// See "LICENSE" for details.

// Extended JavaScript BN functions, required for RSA private ops.

// Version 1.1: new BigInteger("0", 10) returns "proper" zero
// Version 1.2: square() API, isProbablePrime fix

// (public)
function bnClone() { var r = nbi(); this.copyTo(r); return r; }

// (public) return value as integer
function bnIntValue() {
  if(this.s < 0) {
    if(this.t == 1) return this[0]-this.DV;
    else if(this.t == 0) return -1;
  }
  else if(this.t == 1) return this[0];
  else if(this.t == 0) return 0;
  // assumes 16 < DB < 32
  return ((this[1]&((1<<(32-this.DB))-1))<<this.DB)|this[0];
}

// (public) return value as byte
function bnByteValue() { return (this.t==0)?this.s:(this[0]<<24)>>24; }

// (public) return value as short (assumes DB>=16)
function bnShortValue() { return (this.t==0)?this.s:(this[0]<<16)>>16; }

// (protected) return x s.t. r^x < DV
function bnpChunkSize(r) { return Math.floor(Math.LN2*this.DB/Math.log(r)); }

// (public) 0 if this == 0, 1 if this > 0
function bnSigNum() {
  if(this.s < 0) return -1;
  else if(this.t <= 0 || (this.t == 1 && this[0] <= 0)) return 0;
  else return 1;
}

// (protected) convert to radix string
function bnpToRadix(b) {
  if(b == null) b = 10;
  if(this.signum() == 0 || b < 2 || b > 36) return "0";
  var cs = this.chunkSize(b);
  var a = Math.pow(b,cs);
  var d = nbv(a), y = nbi(), z = nbi(), r = "";
  this.divRemTo(d,y,z);
  while(y.signum() > 0) {
    r = (a+z.intValue()).toString(b).substr(1) + r;
    y.divRemTo(d,y,z);
  }
  return z.intValue().toString(b) + r;
}

// (protected) convert from radix string
function bnpFromRadix(s,b) {
  this.fromInt(0);
  if(b == null) b = 10;
  var cs = this.chunkSize(b);
  var d = Math.pow(b,cs), mi = false, j = 0, w = 0;
  for(var i = 0; i < s.length; ++i) {
    var x = intAt(s,i);
    if(x < 0) {
      if(s.charAt(i) == "-" && this.signum() == 0) mi = true;
      continue;
    }
    w = b*w+x;
    if(++j >= cs) {
      this.dMultiply(d);
      this.dAddOffset(w,0);
      j = 0;
      w = 0;
    }
  }
  if(j > 0) {
    this.dMultiply(Math.pow(b,j));
    this.dAddOffset(w,0);
  }
  if(mi) BigInteger.ZERO.subTo(this,this);
}

// (protected) alternate constructor
function bnpFromNumber(a,b,c) {
  if("number" == typeof b) {
    // new BigInteger(int,int,RNG)
    if(a < 2) this.fromInt(1);
    else {
      this.fromNumber(a,c);
      if(!this.testBit(a-1))	// force MSB set
        this.bitwiseTo(BigInteger.ONE.shiftLeft(a-1),op_or,this);
      if(this.isEven()) this.dAddOffset(1,0); // force odd
      while(!this.isProbablePrime(b)) {
        this.dAddOffset(2,0);
        if(this.bitLength() > a) this.subTo(BigInteger.ONE.shiftLeft(a-1),this);
      }
    }
  }
  else {
    // new BigInteger(int,RNG)
    var x = new Array(), t = a&7;
    x.length = (a>>3)+1;
    b.nextBytes(x);
    if(t > 0) x[0] &= ((1<<t)-1); else x[0] = 0;
    this.fromString(x,256);
  }
}

// (public) convert to bigendian byte array
function bnToByteArray() {
  var i = this.t, r = new Array();
  r[0] = this.s;
  var p = this.DB-(i*this.DB)%8, d, k = 0;
  if(i-- > 0) {
    if(p < this.DB && (d = this[i]>>p) != (this.s&this.DM)>>p)
      r[k++] = d|(this.s<<(this.DB-p));
    while(i >= 0) {
      if(p < 8) {
        d = (this[i]&((1<<p)-1))<<(8-p);
        d |= this[--i]>>(p+=this.DB-8);
      }
      else {
        d = (this[i]>>(p-=8))&0xff;
        if(p <= 0) { p += this.DB; --i; }
      }
      if((d&0x80) != 0) d |= -256;
      if(k == 0 && (this.s&0x80) != (d&0x80)) ++k;
      if(k > 0 || d != this.s) r[k++] = d;
    }
  }
  return r;
}

function bnEquals(a) { return(this.compareTo(a)==0); }
function bnMin(a) { return(this.compareTo(a)<0)?this:a; }
function bnMax(a) { return(this.compareTo(a)>0)?this:a; }

// (protected) r = this op a (bitwise)
function bnpBitwiseTo(a,op,r) {
  var i, f, m = Math.min(a.t,this.t);
  for(i = 0; i < m; ++i) r[i] = op(this[i],a[i]);
  if(a.t < this.t) {
    f = a.s&this.DM;
    for(i = m; i < this.t; ++i) r[i] = op(this[i],f);
    r.t = this.t;
  }
  else {
    f = this.s&this.DM;
    for(i = m; i < a.t; ++i) r[i] = op(f,a[i]);
    r.t = a.t;
  }
  r.s = op(this.s,a.s);
  r.clamp();
}

// (public) this & a
function op_and(x,y) { return x&y; }
function bnAnd(a) { var r = nbi(); this.bitwiseTo(a,op_and,r); return r; }

// (public) this | a
function op_or(x,y) { return x|y; }
function bnOr(a) { var r = nbi(); this.bitwiseTo(a,op_or,r); return r; }

// (public) this ^ a
function op_xor(x,y) { return x^y; }
function bnXor(a) { var r = nbi(); this.bitwiseTo(a,op_xor,r); return r; }

// (public) this & ~a
function op_andnot(x,y) { return x&~y; }
function bnAndNot(a) { var r = nbi(); this.bitwiseTo(a,op_andnot,r); return r; }

// (public) ~this
function bnNot() {
  var r = nbi();
  for(var i = 0; i < this.t; ++i) r[i] = this.DM&~this[i];
  r.t = this.t;
  r.s = ~this.s;
  return r;
}

// (public) this << n
function bnShiftLeft(n) {
  var r = nbi();
  if(n < 0) this.rShiftTo(-n,r); else this.lShiftTo(n,r);
  return r;
}

// (public) this >> n
function bnShiftRight(n) {
  var r = nbi();
  if(n < 0) this.lShiftTo(-n,r); else this.rShiftTo(n,r);
  return r;
}

// return index of lowest 1-bit in x, x < 2^31
function lbit(x) {
  if(x == 0) return -1;
  var r = 0;
  if((x&0xffff) == 0) { x >>= 16; r += 16; }
  if((x&0xff) == 0) { x >>= 8; r += 8; }
  if((x&0xf) == 0) { x >>= 4; r += 4; }
  if((x&3) == 0) { x >>= 2; r += 2; }
  if((x&1) == 0) ++r;
  return r;
}

// (public) returns index of lowest 1-bit (or -1 if none)
function bnGetLowestSetBit() {
  for(var i = 0; i < this.t; ++i)
    if(this[i] != 0) return i*this.DB+lbit(this[i]);
  if(this.s < 0) return this.t*this.DB;
  return -1;
}

// return number of 1 bits in x
function cbit(x) {
  var r = 0;
  while(x != 0) { x &= x-1; ++r; }
  return r;
}

// (public) return number of set bits
function bnBitCount() {
  var r = 0, x = this.s&this.DM;
  for(var i = 0; i < this.t; ++i) r += cbit(this[i]^x);
  return r;
}

// (public) true iff nth bit is set
function bnTestBit(n) {
  var j = Math.floor(n/this.DB);
  if(j >= this.t) return(this.s!=0);
  return((this[j]&(1<<(n%this.DB)))!=0);
}

// (protected) this op (1<<n)
function bnpChangeBit(n,op) {
  var r = BigInteger.ONE.shiftLeft(n);
  this.bitwiseTo(r,op,r);
  return r;
}

// (public) this | (1<<n)
function bnSetBit(n) { return this.changeBit(n,op_or); }

// (public) this & ~(1<<n)
function bnClearBit(n) { return this.changeBit(n,op_andnot); }

// (public) this ^ (1<<n)
function bnFlipBit(n) { return this.changeBit(n,op_xor); }

// (protected) r = this + a
function bnpAddTo(a,r) {
  var i = 0, c = 0, m = Math.min(a.t,this.t);
  while(i < m) {
    c += this[i]+a[i];
    r[i++] = c&this.DM;
    c >>= this.DB;
  }
  if(a.t < this.t) {
    c += a.s;
    while(i < this.t) {
      c += this[i];
      r[i++] = c&this.DM;
      c >>= this.DB;
    }
    c += this.s;
  }
  else {
    c += this.s;
    while(i < a.t) {
      c += a[i];
      r[i++] = c&this.DM;
      c >>= this.DB;
    }
    c += a.s;
  }
  r.s = (c<0)?-1:0;
  if(c > 0) r[i++] = c;
  else if(c < -1) r[i++] = this.DV+c;
  r.t = i;
  r.clamp();
}

// (public) this + a
function bnAdd(a) { var r = nbi(); this.addTo(a,r); return r; }

// (public) this - a
function bnSubtract(a) { var r = nbi(); this.subTo(a,r); return r; }

// (public) this * a
function bnMultiply(a) { var r = nbi(); this.multiplyTo(a,r); return r; }

// (public) this^2
function bnSquare() { var r = nbi(); this.squareTo(r); return r; }

// (public) this / a
function bnDivide(a) { var r = nbi(); this.divRemTo(a,r,null); return r; }

// (public) this % a
function bnRemainder(a) { var r = nbi(); this.divRemTo(a,null,r); return r; }

// (public) [this/a,this%a]
function bnDivideAndRemainder(a) {
  var q = nbi(), r = nbi();
  this.divRemTo(a,q,r);
  return new Array(q,r);
}

// (protected) this *= n, this >= 0, 1 < n < DV
function bnpDMultiply(n) {
  this[this.t] = this.am(0,n-1,this,0,0,this.t);
  ++this.t;
  this.clamp();
}

// (protected) this += n << w words, this >= 0
function bnpDAddOffset(n,w) {
  if(n == 0) return;
  while(this.t <= w) this[this.t++] = 0;
  this[w] += n;
  while(this[w] >= this.DV) {
    this[w] -= this.DV;
    if(++w >= this.t) this[this.t++] = 0;
    ++this[w];
  }
}

// A "null" reducer
function NullExp() {}
function nNop(x) { return x; }
function nMulTo(x,y,r) { x.multiplyTo(y,r); }
function nSqrTo(x,r) { x.squareTo(r); }

NullExp.prototype.convert = nNop;
NullExp.prototype.revert = nNop;
NullExp.prototype.mulTo = nMulTo;
NullExp.prototype.sqrTo = nSqrTo;

// (public) this^e
function bnPow(e) { return this.exp(e,new NullExp()); }

// (protected) r = lower n words of "this * a", a.t <= n
// "this" should be the larger one if appropriate.
function bnpMultiplyLowerTo(a,n,r) {
  var i = Math.min(this.t+a.t,n);
  r.s = 0; // assumes a,this >= 0
  r.t = i;
  while(i > 0) r[--i] = 0;
  var j;
  for(j = r.t-this.t; i < j; ++i) r[i+this.t] = this.am(0,a[i],r,i,0,this.t);
  for(j = Math.min(a.t,n); i < j; ++i) this.am(0,a[i],r,i,0,n-i);
  r.clamp();
}

// (protected) r = "this * a" without lower n words, n > 0
// "this" should be the larger one if appropriate.
function bnpMultiplyUpperTo(a,n,r) {
  --n;
  var i = r.t = this.t+a.t-n;
  r.s = 0; // assumes a,this >= 0
  while(--i >= 0) r[i] = 0;
  for(i = Math.max(n-this.t,0); i < a.t; ++i)
    r[this.t+i-n] = this.am(n-i,a[i],r,0,0,this.t+i-n);
  r.clamp();
  r.drShiftTo(1,r);
}

// Barrett modular reduction
function Barrett(m) {
  // setup Barrett
  this.r2 = nbi();
  this.q3 = nbi();
  BigInteger.ONE.dlShiftTo(2*m.t,this.r2);
  this.mu = this.r2.divide(m);
  this.m = m;
}

function barrettConvert(x) {
  if(x.s < 0 || x.t > 2*this.m.t) return x.mod(this.m);
  else if(x.compareTo(this.m) < 0) return x;
  else { var r = nbi(); x.copyTo(r); this.reduce(r); return r; }
}

function barrettRevert(x) { return x; }

// x = x mod m (HAC 14.42)
function barrettReduce(x) {
  x.drShiftTo(this.m.t-1,this.r2);
  if(x.t > this.m.t+1) { x.t = this.m.t+1; x.clamp(); }
  this.mu.multiplyUpperTo(this.r2,this.m.t+1,this.q3);
  this.m.multiplyLowerTo(this.q3,this.m.t+1,this.r2);
  while(x.compareTo(this.r2) < 0) x.dAddOffset(1,this.m.t+1);
  x.subTo(this.r2,x);
  while(x.compareTo(this.m) >= 0) x.subTo(this.m,x);
}

// r = x^2 mod m; x != r
function barrettSqrTo(x,r) { x.squareTo(r); this.reduce(r); }

// r = x*y mod m; x,y != r
function barrettMulTo(x,y,r) { x.multiplyTo(y,r); this.reduce(r); }

Barrett.prototype.convert = barrettConvert;
Barrett.prototype.revert = barrettRevert;
Barrett.prototype.reduce = barrettReduce;
Barrett.prototype.mulTo = barrettMulTo;
Barrett.prototype.sqrTo = barrettSqrTo;

// (public) this^e % m (HAC 14.85)
function bnModPow(e,m) {
  var i = e.bitLength(), k, r = nbv(1), z;
  if(i <= 0) return r;
  else if(i < 18) k = 1;
  else if(i < 48) k = 3;
  else if(i < 144) k = 4;
  else if(i < 768) k = 5;
  else k = 6;
  if(i < 8)
    z = new Classic(m);
  else if(m.isEven())
    z = new Barrett(m);
  else
    z = new Montgomery(m);

  // precomputation
  var g = new Array(), n = 3, k1 = k-1, km = (1<<k)-1;
  g[1] = z.convert(this);
  if(k > 1) {
    var g2 = nbi();
    z.sqrTo(g[1],g2);
    while(n <= km) {
      g[n] = nbi();
      z.mulTo(g2,g[n-2],g[n]);
      n += 2;
    }
  }

  var j = e.t-1, w, is1 = true, r2 = nbi(), t;
  i = nbits(e[j])-1;
  while(j >= 0) {
    if(i >= k1) w = (e[j]>>(i-k1))&km;
    else {
      w = (e[j]&((1<<(i+1))-1))<<(k1-i);
      if(j > 0) w |= e[j-1]>>(this.DB+i-k1);
    }

    n = k;
    while((w&1) == 0) { w >>= 1; --n; }
    if((i -= n) < 0) { i += this.DB; --j; }
    if(is1) {	// ret == 1, don't bother squaring or multiplying it
      g[w].copyTo(r);
      is1 = false;
    }
    else {
      while(n > 1) { z.sqrTo(r,r2); z.sqrTo(r2,r); n -= 2; }
      if(n > 0) z.sqrTo(r,r2); else { t = r; r = r2; r2 = t; }
      z.mulTo(r2,g[w],r);
    }

    while(j >= 0 && (e[j]&(1<<i)) == 0) {
      z.sqrTo(r,r2); t = r; r = r2; r2 = t;
      if(--i < 0) { i = this.DB-1; --j; }
    }
  }
  return z.revert(r);
}

// (public) gcd(this,a) (HAC 14.54)
function bnGCD(a) {
  var x = (this.s<0)?this.negate():this.clone();
  var y = (a.s<0)?a.negate():a.clone();
  if(x.compareTo(y) < 0) { var t = x; x = y; y = t; }
  var i = x.getLowestSetBit(), g = y.getLowestSetBit();
  if(g < 0) return x;
  if(i < g) g = i;
  if(g > 0) {
    x.rShiftTo(g,x);
    y.rShiftTo(g,y);
  }
  while(x.signum() > 0) {
    if((i = x.getLowestSetBit()) > 0) x.rShiftTo(i,x);
    if((i = y.getLowestSetBit()) > 0) y.rShiftTo(i,y);
    if(x.compareTo(y) >= 0) {
      x.subTo(y,x);
      x.rShiftTo(1,x);
    }
    else {
      y.subTo(x,y);
      y.rShiftTo(1,y);
    }
  }
  if(g > 0) y.lShiftTo(g,y);
  return y;
}

// (protected) this % n, n < 2^26
function bnpModInt(n) {
  if(n <= 0) return 0;
  var d = this.DV%n, r = (this.s<0)?n-1:0;
  if(this.t > 0)
    if(d == 0) r = this[0]%n;
    else for(var i = this.t-1; i >= 0; --i) r = (d*r+this[i])%n;
  return r;
}

// (public) 1/this % m (HAC 14.61)
function bnModInverse(m) {
  var ac = m.isEven();
  if((this.isEven() && ac) || m.signum() == 0) return BigInteger.ZERO;
  var u = m.clone(), v = this.clone();
  var a = nbv(1), b = nbv(0), c = nbv(0), d = nbv(1);
  while(u.signum() != 0) {
    while(u.isEven()) {
      u.rShiftTo(1,u);
      if(ac) {
        if(!a.isEven() || !b.isEven()) { a.addTo(this,a); b.subTo(m,b); }
        a.rShiftTo(1,a);
      }
      else if(!b.isEven()) b.subTo(m,b);
      b.rShiftTo(1,b);
    }
    while(v.isEven()) {
      v.rShiftTo(1,v);
      if(ac) {
        if(!c.isEven() || !d.isEven()) { c.addTo(this,c); d.subTo(m,d); }
        c.rShiftTo(1,c);
      }
      else if(!d.isEven()) d.subTo(m,d);
      d.rShiftTo(1,d);
    }
    if(u.compareTo(v) >= 0) {
      u.subTo(v,u);
      if(ac) a.subTo(c,a);
      b.subTo(d,b);
    }
    else {
      v.subTo(u,v);
      if(ac) c.subTo(a,c);
      d.subTo(b,d);
    }
  }
  if(v.compareTo(BigInteger.ONE) != 0) return BigInteger.ZERO;
  if(d.compareTo(m) >= 0) return d.subtract(m);
  if(d.signum() < 0) d.addTo(m,d); else return d;
  if(d.signum() < 0) return d.add(m); else return d;
}

var lowprimes = [2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97,101,103,107,109,113,127,131,137,139,149,151,157,163,167,173,179,181,191,193,197,199,211,223,227,229,233,239,241,251,257,263,269,271,277,281,283,293,307,311,313,317,331,337,347,349,353,359,367,373,379,383,389,397,401,409,419,421,431,433,439,443,449,457,461,463,467,479,487,491,499,503,509,521,523,541,547,557,563,569,571,577,587,593,599,601,607,613,617,619,631,641,643,647,653,659,661,673,677,683,691,701,709,719,727,733,739,743,751,757,761,769,773,787,797,809,811,821,823,827,829,839,853,857,859,863,877,881,883,887,907,911,919,929,937,941,947,953,967,971,977,983,991,997];
var lplim = (1<<26)/lowprimes[lowprimes.length-1];

// (public) test primality with certainty >= 1-.5^t
function bnIsProbablePrime(t) {
  var i, x = this.abs();
  if(x.t == 1 && x[0] <= lowprimes[lowprimes.length-1]) {
    for(i = 0; i < lowprimes.length; ++i)
      if(x[0] == lowprimes[i]) return true;
    return false;
  }
  if(x.isEven()) return false;
  i = 1;
  while(i < lowprimes.length) {
    var m = lowprimes[i], j = i+1;
    while(j < lowprimes.length && m < lplim) m *= lowprimes[j++];
    m = x.modInt(m);
    while(i < j) if(m%lowprimes[i++] == 0) return false;
  }
  return x.millerRabin(t);
}

// (protected) true if probably prime (HAC 4.24, Miller-Rabin)
function bnpMillerRabin(t) {
  var n1 = this.subtract(BigInteger.ONE);
  var k = n1.getLowestSetBit();
  if(k <= 0) return false;
  var r = n1.shiftRight(k);
  t = (t+1)>>1;
  if(t > lowprimes.length) t = lowprimes.length;
  var a = nbi();
  for(var i = 0; i < t; ++i) {
    //Pick bases at random, instead of starting at 2
    a.fromInt(lowprimes[Math.floor(Math.random()*lowprimes.length)]);
    var y = a.modPow(r,this);
    if(y.compareTo(BigInteger.ONE) != 0 && y.compareTo(n1) != 0) {
      var j = 1;
      while(j++ < k && y.compareTo(n1) != 0) {
        y = y.modPowInt(2,this);
        if(y.compareTo(BigInteger.ONE) == 0) return false;
      }
      if(y.compareTo(n1) != 0) return false;
    }
  }
  return true;
}

// protected
BigInteger.prototype.chunkSize = bnpChunkSize;
BigInteger.prototype.toRadix = bnpToRadix;
BigInteger.prototype.fromRadix = bnpFromRadix;
BigInteger.prototype.fromNumber = bnpFromNumber;
BigInteger.prototype.bitwiseTo = bnpBitwiseTo;
BigInteger.prototype.changeBit = bnpChangeBit;
BigInteger.prototype.addTo = bnpAddTo;
BigInteger.prototype.dMultiply = bnpDMultiply;
BigInteger.prototype.dAddOffset = bnpDAddOffset;
BigInteger.prototype.multiplyLowerTo = bnpMultiplyLowerTo;
BigInteger.prototype.multiplyUpperTo = bnpMultiplyUpperTo;
BigInteger.prototype.modInt = bnpModInt;
BigInteger.prototype.millerRabin = bnpMillerRabin;

// public
BigInteger.prototype.clone = bnClone;
BigInteger.prototype.intValue = bnIntValue;
BigInteger.prototype.byteValue = bnByteValue;
BigInteger.prototype.shortValue = bnShortValue;
BigInteger.prototype.signum = bnSigNum;
BigInteger.prototype.toByteArray = bnToByteArray;
BigInteger.prototype.equals = bnEquals;
BigInteger.prototype.min = bnMin;
BigInteger.prototype.max = bnMax;
BigInteger.prototype.and = bnAnd;
BigInteger.prototype.or = bnOr;
BigInteger.prototype.xor = bnXor;
BigInteger.prototype.andNot = bnAndNot;
BigInteger.prototype.not = bnNot;
BigInteger.prototype.shiftLeft = bnShiftLeft;
BigInteger.prototype.shiftRight = bnShiftRight;
BigInteger.prototype.getLowestSetBit = bnGetLowestSetBit;
BigInteger.prototype.bitCount = bnBitCount;
BigInteger.prototype.testBit = bnTestBit;
BigInteger.prototype.setBit = bnSetBit;
BigInteger.prototype.clearBit = bnClearBit;
BigInteger.prototype.flipBit = bnFlipBit;
BigInteger.prototype.add = bnAdd;
BigInteger.prototype.subtract = bnSubtract;
BigInteger.prototype.multiply = bnMultiply;
BigInteger.prototype.divide = bnDivide;
BigInteger.prototype.remainder = bnRemainder;
BigInteger.prototype.divideAndRemainder = bnDivideAndRemainder;
BigInteger.prototype.modPow = bnModPow;
BigInteger.prototype.modInverse = bnModInverse;
BigInteger.prototype.pow = bnPow;
BigInteger.prototype.gcd = bnGCD;
BigInteger.prototype.isProbablePrime = bnIsProbablePrime;

// JSBN-specific extension
BigInteger.prototype.square = bnSquare;

// BigInteger interfaces not implemented in jsbn:

// BigInteger(int signum, byte[] magnitude)
// double doubleValue()
// float floatValue()
// int hashCode()
// long longValue()
// static BigInteger valueOf(long val)

// Random number generator - requires a PRNG backend, e.g. prng4.js

// For best results, put code like
// <body onClick='rng_seed_time();' onKeyPress='rng_seed_time();'>
// in your main HTML document.

var rng_state;
var rng_pool;
var rng_pptr;

// Mix in a 32-bit integer into the pool
function rng_seed_int(x) {
  rng_pool[rng_pptr++] ^= x & 255;
  rng_pool[rng_pptr++] ^= (x >> 8) & 255;
  rng_pool[rng_pptr++] ^= (x >> 16) & 255;
  rng_pool[rng_pptr++] ^= (x >> 24) & 255;
  if(rng_pptr >= rng_psize) rng_pptr -= rng_psize;
}

// Mix in the current time (w/milliseconds) into the pool
function rng_seed_time() {
  rng_seed_int(new Date().getTime());
}

// Initialize the pool with junk if needed.
if(rng_pool == null) {
  rng_pool = new Array();
  rng_pptr = 0;
  var t;
  if(true) {
    // Use webcrypto if available
    var ua = new Uint8Array(32);
    //window.crypto.getRandomValues(ua);
    crypto.getRandomValues(ua);
    for(t = 0; t < 32; ++t)
      rng_pool[rng_pptr++] = ua[t];
  }
  if(navigator.appName == "Netscape" && navigator.appVersion < "5" && window.crypto) {
    // Extract entropy (256 bits) from NS4 RNG if available
    var z = window.crypto.random(32);
    for(t = 0; t < z.length; ++t)
      rng_pool[rng_pptr++] = z.charCodeAt(t) & 255;
  }  
  while(rng_pptr < rng_psize) {  // extract some randomness from Math.random()
    t = Math.floor(65536 * Math.random());
    rng_pool[rng_pptr++] = t >>> 8;
    rng_pool[rng_pptr++] = t & 255;
  }
  rng_pptr = 0;
  rng_seed_time();
  //rng_seed_int(window.screenX);
  //rng_seed_int(window.screenY);
}

function rng_get_byte() {
  if(rng_state == null) {
    rng_seed_time();
    rng_state = prng_newstate();
    rng_state.init(rng_pool);
    for(rng_pptr = 0; rng_pptr < rng_pool.length; ++rng_pptr)
      rng_pool[rng_pptr] = 0;
    rng_pptr = 0;
    //rng_pool = null;
  }
  // allow reseeding after first request
  return rng_state.next();
}

function rng_get_bytes(ba) {
  var i;
  for(i = 0; i < ba.length; ++i) ba[i] = rng_get_byte();
}

function SecureRandom() {}

SecureRandom.prototype.nextBytes = rng_get_bytes;

// prng4.js - uses Arcfour as a PRNG

function Arcfour() {
  this.i = 0;
  this.j = 0;
  this.S = new Array();
}

// Initialize arcfour context from key, an array of ints, each from [0..255]
function ARC4init(key) {
  var i, j, t;
  for(i = 0; i < 256; ++i)
    this.S[i] = i;
  j = 0;
  for(i = 0; i < 256; ++i) {
    j = (j + this.S[i] + key[i % key.length]) & 255;
    t = this.S[i];
    this.S[i] = this.S[j];
    this.S[j] = t;
  }
  this.i = 0;
  this.j = 0;
}

function ARC4next() {
  var t;
  this.i = (this.i + 1) & 255;
  this.j = (this.j + this.S[this.i]) & 255;
  t = this.S[this.i];
  this.S[this.i] = this.S[this.j];
  this.S[this.j] = t;
  return this.S[(t + this.S[this.i]) & 255];
}

Arcfour.prototype.init = ARC4init;
Arcfour.prototype.next = ARC4next;

// Plug in your RNG constructor here
function prng_newstate() {
  return new Arcfour();
}

// Pool size must be a multiple of 4 and greater than 32.
// An array of bytes the size of the pool will be passed to init()
var rng_psize = 256;

var CryptoJS=CryptoJS||function(u,m){var d={},l=d.lib={},s=l.Base=function(){function b(){}return{extend:function(r){b.prototype=this;var a=new b;r&&a.mixIn(r);a.hasOwnProperty("init")||(a.init=function(){a.$super.init.apply(this,arguments)});a.init.prototype=a;a.$super=this;return a},create:function(){var b=this.extend();b.init.apply(b,arguments);return b},init:function(){},mixIn:function(b){for(var a in b)b.hasOwnProperty(a)&&(this[a]=b[a]);b.hasOwnProperty("toString")&&(this.toString=b.toString)},
clone:function(){return this.init.prototype.extend(this)}}}(),t=l.WordArray=s.extend({init:function(b,a){b=this.words=b||[];this.sigBytes=a!=m?a:4*b.length},toString:function(b){return(b||p).stringify(this)},concat:function(b){var a=this.words,e=b.words,n=this.sigBytes;b=b.sigBytes;this.clamp();if(n%4)for(var q=0;q<b;q++)a[n+q>>>2]|=(e[q>>>2]>>>24-8*(q%4)&255)<<24-8*((n+q)%4);else if(65535<e.length)for(q=0;q<b;q+=4)a[n+q>>>2]=e[q>>>2];else a.push.apply(a,e);this.sigBytes+=b;return this},clamp:function(){var b=
this.words,a=this.sigBytes;b[a>>>2]&=4294967295<<32-8*(a%4);b.length=u.ceil(a/4)},clone:function(){var b=s.clone.call(this);b.words=this.words.slice(0);return b},random:function(b){for(var a=[],e=0;e<b;e+=4)a.push(4294967296*u.random()|0);return new t.init(a,b)}}),c=d.enc={},p=c.Hex={stringify:function(b){var a=b.words;b=b.sigBytes;for(var e=[],n=0;n<b;n++){var q=a[n>>>2]>>>24-8*(n%4)&255;e.push((q>>>4).toString(16));e.push((q&15).toString(16))}return e.join("")},parse:function(b){for(var a=b.length,
e=[],n=0;n<a;n+=2)e[n>>>3]|=parseInt(b.substr(n,2),16)<<24-4*(n%8);return new t.init(e,a/2)}},v=c.Latin1={stringify:function(b){var a=b.words;b=b.sigBytes;for(var e=[],n=0;n<b;n++)e.push(String.fromCharCode(a[n>>>2]>>>24-8*(n%4)&255));return e.join("")},parse:function(b){for(var a=b.length,e=[],n=0;n<a;n++)e[n>>>2]|=(b.charCodeAt(n)&255)<<24-8*(n%4);return new t.init(e,a)}},a=c.Utf8={stringify:function(b){try{return decodeURIComponent(escape(v.stringify(b)))}catch(a){throw Error("Malformed UTF-8 data");
}},parse:function(b){return v.parse(unescape(encodeURIComponent(b)))}},e=l.BufferedBlockAlgorithm=s.extend({reset:function(){this._data=new t.init;this._nDataBytes=0},_append:function(b){"string"==typeof b&&(b=a.parse(b));this._data.concat(b);this._nDataBytes+=b.sigBytes},_process:function(b){var a=this._data,e=a.words,n=a.sigBytes,q=this.blockSize,w=n/(4*q),w=b?u.ceil(w):u.max((w|0)-this._minBufferSize,0);b=w*q;n=u.min(4*b,n);if(b){for(var c=0;c<b;c+=q)this._doProcessBlock(e,c);c=e.splice(0,b);a.sigBytes-=
n}return new t.init(c,n)},clone:function(){var b=s.clone.call(this);b._data=this._data.clone();return b},_minBufferSize:0});l.Hasher=e.extend({cfg:s.extend(),init:function(b){this.cfg=this.cfg.extend(b);this.reset()},reset:function(){e.reset.call(this);this._doReset()},update:function(b){this._append(b);this._process();return this},finalize:function(b){b&&this._append(b);return this._doFinalize()},blockSize:16,_createHelper:function(b){return function(a,e){return(new b.init(e)).finalize(a)}},_createHmacHelper:function(a){return function(e,
c){return(new w.HMAC.init(a,c)).finalize(e)}}});var w=d.algo={};return d}(Math);(function(){var u=CryptoJS,m=u.lib.WordArray;u.enc.Base64={stringify:function(d){var l=d.words,m=d.sigBytes,t=this._map;d.clamp();d=[];for(var c=0;c<m;c+=3)for(var p=(l[c>>>2]>>>24-8*(c%4)&255)<<16|(l[c+1>>>2]>>>24-8*((c+1)%4)&255)<<8|l[c+2>>>2]>>>24-8*((c+2)%4)&255,v=0;4>v&&c+0.75*v<m;v++)d.push(t.charAt(p>>>6*(3-v)&63));if(l=t.charAt(64))for(;d.length%4;)d.push(l);return d.join("")},parse:function(d){var l=d.length,s=this._map,t=s.charAt(64);t&&(t=d.indexOf(t),-1!=t&&(l=t));for(var t=[],c=0,p=0;p<
l;p++)if(p%4){var v=s.indexOf(d.charAt(p-1))<<2*(p%4),a=s.indexOf(d.charAt(p))>>>6-2*(p%4);t[c>>>2]|=(v|a)<<24-8*(c%4);c++}return m.create(t,c)},_map:"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="}})();(function(u){function m(a,w,b,c,d,n,q){a=a+(w&b|~w&c)+d+q;return(a<<n|a>>>32-n)+w}function d(a,w,b,c,d,n,q){a=a+(w&c|b&~c)+d+q;return(a<<n|a>>>32-n)+w}function l(a,w,b,c,d,n,q){a=a+(w^b^c)+d+q;return(a<<n|a>>>32-n)+w}function s(a,c,b,d,m,n,q){a=a+(b^(c|~d))+m+q;return(a<<n|a>>>32-n)+c}var t=CryptoJS,c=t.lib,p=c.WordArray,v=c.Hasher,c=t.algo,a=[];(function(){for(var e=0;64>e;e++)a[e]=4294967296*u.abs(u.sin(e+1))|0})();c=c.MD5=v.extend({_doReset:function(){this._hash=new p.init([1732584193,4023233417,
2562383102,271733878])},_doProcessBlock:function(e,c){for(var b=0;16>b;b++){var r=c+b,p=e[r];e[r]=(p<<8|p>>>24)&16711935|(p<<24|p>>>8)&4278255360}var b=this._hash.words,r=e[c+0],p=e[c+1],n=e[c+2],q=e[c+3],x=e[c+4],y=e[c+5],t=e[c+6],v=e[c+7],u=e[c+8],z=e[c+9],A=e[c+10],B=e[c+11],C=e[c+12],D=e[c+13],E=e[c+14],F=e[c+15],f=b[0],g=b[1],h=b[2],k=b[3],f=m(f,g,h,k,r,7,a[0]),k=m(k,f,g,h,p,12,a[1]),h=m(h,k,f,g,n,17,a[2]),g=m(g,h,k,f,q,22,a[3]),f=m(f,g,h,k,x,7,a[4]),k=m(k,f,g,h,y,12,a[5]),h=m(h,k,f,g,t,17,a[6]),
g=m(g,h,k,f,v,22,a[7]),f=m(f,g,h,k,u,7,a[8]),k=m(k,f,g,h,z,12,a[9]),h=m(h,k,f,g,A,17,a[10]),g=m(g,h,k,f,B,22,a[11]),f=m(f,g,h,k,C,7,a[12]),k=m(k,f,g,h,D,12,a[13]),h=m(h,k,f,g,E,17,a[14]),g=m(g,h,k,f,F,22,a[15]),f=d(f,g,h,k,p,5,a[16]),k=d(k,f,g,h,t,9,a[17]),h=d(h,k,f,g,B,14,a[18]),g=d(g,h,k,f,r,20,a[19]),f=d(f,g,h,k,y,5,a[20]),k=d(k,f,g,h,A,9,a[21]),h=d(h,k,f,g,F,14,a[22]),g=d(g,h,k,f,x,20,a[23]),f=d(f,g,h,k,z,5,a[24]),k=d(k,f,g,h,E,9,a[25]),h=d(h,k,f,g,q,14,a[26]),g=d(g,h,k,f,u,20,a[27]),f=d(f,g,
h,k,D,5,a[28]),k=d(k,f,g,h,n,9,a[29]),h=d(h,k,f,g,v,14,a[30]),g=d(g,h,k,f,C,20,a[31]),f=l(f,g,h,k,y,4,a[32]),k=l(k,f,g,h,u,11,a[33]),h=l(h,k,f,g,B,16,a[34]),g=l(g,h,k,f,E,23,a[35]),f=l(f,g,h,k,p,4,a[36]),k=l(k,f,g,h,x,11,a[37]),h=l(h,k,f,g,v,16,a[38]),g=l(g,h,k,f,A,23,a[39]),f=l(f,g,h,k,D,4,a[40]),k=l(k,f,g,h,r,11,a[41]),h=l(h,k,f,g,q,16,a[42]),g=l(g,h,k,f,t,23,a[43]),f=l(f,g,h,k,z,4,a[44]),k=l(k,f,g,h,C,11,a[45]),h=l(h,k,f,g,F,16,a[46]),g=l(g,h,k,f,n,23,a[47]),f=s(f,g,h,k,r,6,a[48]),k=s(k,f,g,h,
v,10,a[49]),h=s(h,k,f,g,E,15,a[50]),g=s(g,h,k,f,y,21,a[51]),f=s(f,g,h,k,C,6,a[52]),k=s(k,f,g,h,q,10,a[53]),h=s(h,k,f,g,A,15,a[54]),g=s(g,h,k,f,p,21,a[55]),f=s(f,g,h,k,u,6,a[56]),k=s(k,f,g,h,F,10,a[57]),h=s(h,k,f,g,t,15,a[58]),g=s(g,h,k,f,D,21,a[59]),f=s(f,g,h,k,x,6,a[60]),k=s(k,f,g,h,B,10,a[61]),h=s(h,k,f,g,n,15,a[62]),g=s(g,h,k,f,z,21,a[63]);b[0]=b[0]+f|0;b[1]=b[1]+g|0;b[2]=b[2]+h|0;b[3]=b[3]+k|0},_doFinalize:function(){var a=this._data,c=a.words,b=8*this._nDataBytes,d=8*a.sigBytes;c[d>>>5]|=128<<
24-d%32;var p=u.floor(b/4294967296);c[(d+64>>>9<<4)+15]=(p<<8|p>>>24)&16711935|(p<<24|p>>>8)&4278255360;c[(d+64>>>9<<4)+14]=(b<<8|b>>>24)&16711935|(b<<24|b>>>8)&4278255360;a.sigBytes=4*(c.length+1);this._process();a=this._hash;c=a.words;for(b=0;4>b;b++)d=c[b],c[b]=(d<<8|d>>>24)&16711935|(d<<24|d>>>8)&4278255360;return a},clone:function(){var a=v.clone.call(this);a._hash=this._hash.clone();return a}});t.MD5=v._createHelper(c);t.HmacMD5=v._createHmacHelper(c)})(Math);(function(){var u=CryptoJS,m=u.lib,d=m.Base,l=m.WordArray,m=u.algo,s=m.EvpKDF=d.extend({cfg:d.extend({keySize:4,hasher:m.MD5,iterations:1}),init:function(d){this.cfg=this.cfg.extend(d)},compute:function(d,c){for(var p=this.cfg,m=p.hasher.create(),a=l.create(),e=a.words,w=p.keySize,p=p.iterations;e.length<w;){b&&m.update(b);var b=m.update(d).finalize(c);m.reset();for(var r=1;r<p;r++)b=m.finalize(b),m.reset();a.concat(b)}a.sigBytes=4*w;return a}});u.EvpKDF=function(d,c,p){return s.create(p).compute(d,
c)}})();CryptoJS.lib.Cipher||function(u){var m=CryptoJS,d=m.lib,l=d.Base,s=d.WordArray,t=d.BufferedBlockAlgorithm,c=m.enc.Base64,p=m.algo.EvpKDF,v=d.Cipher=t.extend({cfg:l.extend(),createEncryptor:function(a,b){return this.create(this._ENC_XFORM_MODE,a,b)},createDecryptor:function(a,b){return this.create(this._DEC_XFORM_MODE,a,b)},init:function(a,b,c){this.cfg=this.cfg.extend(c);this._xformMode=a;this._key=b;this.reset()},reset:function(){t.reset.call(this);this._doReset()},process:function(a){this._append(a);
return this._process()},finalize:function(a){a&&this._append(a);return this._doFinalize()},keySize:4,ivSize:4,_ENC_XFORM_MODE:1,_DEC_XFORM_MODE:2,_createHelper:function(){return function(a){return{encrypt:function(b,c,d){return("string"==typeof c?G:r).encrypt(a,b,c,d)},decrypt:function(b,c,d){return("string"==typeof c?G:r).decrypt(a,b,c,d)}}}}()});d.StreamCipher=v.extend({_doFinalize:function(){return this._process(!0)},blockSize:1});var a=m.mode={},e=d.BlockCipherMode=l.extend({createEncryptor:function(a,
b){return this.Encryptor.create(a,b)},createDecryptor:function(a,b){return this.Decryptor.create(a,b)},init:function(a,b){this._cipher=a;this._iv=b}}),a=a.CBC=function(){function a(b,n,c){var d=this._iv;d?this._iv=u:d=this._prevBlock;for(var q=0;q<c;q++)b[n+q]^=d[q]}var b=e.extend();b.Encryptor=b.extend({processBlock:function(b,c){var d=this._cipher,q=d.blockSize;a.call(this,b,c,q);d.encryptBlock(b,c);this._prevBlock=b.slice(c,c+q)}});b.Decryptor=b.extend({processBlock:function(b,c){var d=this._cipher,
q=d.blockSize,e=b.slice(c,c+q);d.decryptBlock(b,c);a.call(this,b,c,q);this._prevBlock=e}});return b}(),w=(m.pad={}).Pkcs7={pad:function(a,b){for(var c=4*b,c=c-a.sigBytes%c,d=c<<24|c<<16|c<<8|c,e=[],p=0;p<c;p+=4)e.push(d);c=s.create(e,c);a.concat(c)},unpad:function(a){a.sigBytes-=a.words[a.sigBytes-1>>>2]&255}};d.BlockCipher=v.extend({cfg:v.cfg.extend({mode:a,padding:w}),reset:function(){v.reset.call(this);var a=this.cfg,b=a.iv,a=a.mode;if(this._xformMode==this._ENC_XFORM_MODE)var c=a.createEncryptor;
else c=a.createDecryptor,this._minBufferSize=1;this._mode=c.call(a,this,b&&b.words)},_doProcessBlock:function(a,b){this._mode.processBlock(a,b)},_doFinalize:function(){var a=this.cfg.padding;if(this._xformMode==this._ENC_XFORM_MODE){a.pad(this._data,this.blockSize);var b=this._process(!0)}else b=this._process(!0),a.unpad(b);return b},blockSize:4});var b=d.CipherParams=l.extend({init:function(a){this.mixIn(a)},toString:function(a){return(a||this.formatter).stringify(this)}}),a=(m.format={}).OpenSSL=
{stringify:function(a){var b=a.ciphertext;a=a.salt;return(a?s.create([1398893684,1701076831]).concat(a).concat(b):b).toString(c)},parse:function(a){a=c.parse(a);var d=a.words;if(1398893684==d[0]&&1701076831==d[1]){var e=s.create(d.slice(2,4));d.splice(0,4);a.sigBytes-=16}return b.create({ciphertext:a,salt:e})}},r=d.SerializableCipher=l.extend({cfg:l.extend({format:a}),encrypt:function(a,c,d,e){e=this.cfg.extend(e);var p=a.createEncryptor(d,e);c=p.finalize(c);p=p.cfg;return b.create({ciphertext:c,
key:d,iv:p.iv,algorithm:a,mode:p.mode,padding:p.padding,blockSize:a.blockSize,formatter:e.format})},decrypt:function(a,b,c,d){d=this.cfg.extend(d);b=this._parse(b,d.format);return a.createDecryptor(c,d).finalize(b.ciphertext)},_parse:function(a,b){return"string"==typeof a?b.parse(a,this):a}}),m=(m.kdf={}).OpenSSL={execute:function(a,c,d,e){e||(e=s.random(8));a=p.create({keySize:c+d}).compute(a,e);d=s.create(a.words.slice(c),4*d);a.sigBytes=4*c;return b.create({key:a,iv:d,salt:e})}},G=d.PasswordBasedCipher=
r.extend({cfg:r.cfg.extend({kdf:m}),encrypt:function(a,b,c,d){d=this.cfg.extend(d);c=d.kdf.execute(c,a.keySize,a.ivSize);d.iv=c.iv;a=r.encrypt.call(this,a,b,c.key,d);a.mixIn(c);return a},decrypt:function(a,b,c,d){d=this.cfg.extend(d);b=this._parse(b,d.format);c=d.kdf.execute(c,a.keySize,a.ivSize,b.salt);d.iv=c.iv;return r.decrypt.call(this,a,b,c.key,d)}})}();(function(){function u(c){return l[3][c>>>24&255]^l[2][c>>>16&255]^l[1][c>>>8&255]^l[0][c&255]}var m=CryptoJS,d=m.lib.BlockCipher,l=[[696885672,92635524,382128852,331600848,340021332,487395612,747413676,621093156,491606364,54739776,403181592,504238620,289493328,1020063996,181060296,591618912,671621160,71581764,536879136,495817116,549511392,583197408,147374280,386339604,629514660,261063564,50529024,994800504,999011256,318968592,314757840,785310444,809529456,210534540,1057960764,680042664,839004720,
500027868,919007988,876900468,751624428,361075092,185271048,390550356,474763356,457921368,1032696252,16843008,604250148,470552604,860058480,411603096,268439568,214745292,851636976,432656856,738992172,667411428,843215472,58950528,462132120,297914832,109478532,164217288,541089888,272650320,595829664,734782440,218956044,914797236,512660124,256852812,931640244,441078360,113689284,944271480,646357668,302125584,797942700,365285844,557932896,63161280,881111220,21053760,306336336,1028485500,227377548,134742024,
521081628,428446104,0,420024600,67371012,323179344,935850996,566354400,1036907004,910586484,789521196,654779172,813740208,193692552,235799052,730571688,578986656,776888940,327390096,223166796,692674920,1011642492,151585032,168428040,1066382268,802153452,868479984,96846276,126321540,335810580,1053750012,608460900,516870876,772678188,189481800,436867608,101057028,553722144,726360936,642146916,33686016,902164980,310547088,176849544,202113036,864269232,1045328508,281071824,977957496,122110788,377918100,
633725412,637936164,8421504,764256684,533713884,562143648,805318704,923218740,781099692,906375732,352653588,570565152,940060728,885321972,663200676,88424772,206323788,25264512,701096424,75792516,394761108,889532724,197903304,248431308,1007431740,826372464,285282576,130532292,160006536,893743476,1003222008,449499864,952692984,344232084,424235352,42107520,80003268,1070593020,155795784,956903736,658989924,12632256,265274316,398971860,948482232,252642060,244220556,37896768,587408160,293704080,743202924,
466342872,612671652,872689716,834793968,138952776,46318272,793731948,1024274748,755835180,4210752,1049539260,1041117756,1015853244,29475264,713728680,982168248,240009804,356864340,990589752,483184860,675831912,1062171516,478974108,415813848,172638792,373707348,927429492,545300640,768467436,105267780,897954228,722150184,625303908,986379E3,600040416,965325240,830583216,529503132,508449372,969535992,650568420,847426224,822161712,717939432,760045932,525292380,616882404,817950960,231588300,143163528,369496596,
973746744,407392344,348442836,574775904,688464168,117900036,855847728,684253416,453710616,84214020,961114488,276861072,709517928,705307176,445289112],[943196208,3894986976,741149985,2753988258,3423588291,3693006546,2956166067,3090712752,2888798115,1612726368,1410680145,3288844227,1141130304,1815039843,1747667811,1478183763,3221472195,1612857954,808649523,3023406513,673777953,2686484640,3760374498,2754054051,3490956243,2417066385,269549841,67503618,471600144,3158084784,875955762,1208699715,3962556387,
2282260608,1814842464,2821228704,337053459,3288646848,336987666,4097098992,3221406402,1141196097,3760308705,3558262482,1010765619,1010634033,2349764226,2551744656,673712160,1276005954,4097230578,1010699826,2753922465,4164536817,202181889,3693072339,3625502928,673909539,1680229986,2017086066,606537507,741281571,4029792753,1882342002,1073889858,3558130896,1073824065,3221274816,1882407795,1680295779,2888600736,2282457987,4097296371,2888666529,2147516544,471797523,3356150466,741084192,2821360290,875824176,
3490890450,134941443,3962490594,3895052769,1545424209,2484372624,404228112,4164471024,1410811731,2888732322,134744064,3288712641,269681427,3423456705,2215020162,3090778545,4232040435,2084392305,3221340609,808517937,4097164785,2282392194,1747602018,2956034481,3490824657,538968096,3558328275,131586,539099682,67372032,1747470432,1882276209,67569411,3625700307,2619182481,2551810449,1612792161,3158216370,3827746530,1478052177,3692940753,1343308113,2417000592,3692874960,2551876242,2686682019,2821426083,
3490758864,2147582337,202313475,1141327683,404359698,3760440291,3962359008,2349698433,3158282163,2484504210,2017151859,1545358416,2686616226,2686550433,1612923747,539165475,1275940161,3356018880,2619248274,2619116688,943327794,202116096,741215778,3090844338,1814974050,2619314067,1478117970,4029858546,2417132178,4029924339,1208568129,2016954480,3423390912,336921873,4164668403,1882210416,1949648241,2084523891,875889969,269484048,197379,1680098400,1814908257,3288778434,1949582448,3558196689,3023340720,
3895118562,134809857,1949714034,404293905,4231974642,1073758272,269615634,3760242912,3158150577,67437825,4164602610,65793,4029726960,673843746,1545490002,2821294497,1410745938,1073955651,2214954369,336856080,2282326401,2551942035,2955968688,3827680737,1208502336,2017020273,2484570003,4231843056,471731730,2147648130,539033889,2349632640,404425491,1545555795,1949779827,1410614352,2956100274,471665937,606405921,1276071747,0,1141261890,3962424801,1477986384,1343373906,3895184355,2084458098,3625634514,
3356084673,4231908849,808452144,2484438417,1680164193,1010568240,3023472306,3827614944,3090910131,2084326512,202247682,1343242320,943262001,606471714,808583730,2214888576,1747536225,2417197971,876021555,3827812323,606340128,2753856672,3356216259,1343439699,134875650,2215085955,3625568721,1275874368,2147713923,2349830019,3423522498,943393587,1208633922,3023538099],[2712152457,2172913029,3537114822,3553629123,1347687492,287055117,2695638156,556016901,1364991309,1128268611,270014472,303832590,1364201793,
4043062476,3267889866,1667244867,539502600,1078199364,538976256,2442927501,3772784832,3806339778,3234334920,320083719,2711889285,2206994319,50332419,1937259339,3015195531,319820547,3536851650,3807129294,1886400576,2156661900,859586319,2695374984,842019330,3520863693,4076091078,1886663748,3773574348,2442401157,50858763,1398019911,1348213836,1398283083,2981903757,16777473,539239428,270277644,1936732995,2425886856,269488128,3234598092,4075827906,3520600521,539765772,3823380423,1919955522,2206204803,
2476219275,3520074177,2189690502,3251112393,1616912448,1347424320,2745181059,3823643595,17566989,2998154886,2459704974,1129058127,3014932359,1381505610,3267626694,1886926920,2728666758,303043074,2745970575,3520337349,1633689921,3284140995,2964599940,1094713665,1380979266,1903967565,2173439373,526344,320610063,2442664329,0,286791945,263172,1397756739,4092868551,3789562305,4059839949,1920218694,590098191,589571847,2964336768,2206731147,34344462,2745707403,2728403586,1651256910,2475692931,1095503181,
1634216265,1887190092,17303817,34081290,3015458703,3823906767,4092605379,3250849221,2206467975,269751300,4076617422,1617175620,3537641166,573320718,1128794955,303569418,33818118,555753729,1667771211,1650730566,33554946,4059313605,2458915458,2189953674,789516,3014669187,1920745038,3503296704,1920481866,1128531783,2459178630,3789825477,572794374,2155872384,2712415629,3554418639,2711626113,808464384,859059975,2729193102,842282502,286528773,572531202,808990728,4042536132,2745444231,1094976837,1078725708,
2172649857,3790088649,2156135556,2475956103,825505029,3284667339,3268153038,809253900,1903178049,286265601,3284404167,2173176201,1903441221,4093131723,3537377994,4042799304,2425623684,1364728137,2189427330,3234071748,4093394895,1095240009,825768201,1667508039,3233808576,3284930511,3553892295,2964863112,51121935,2190216846,1111491138,589308675,2442137985,1617701964,3554155467,2695111812,808727556,4059050433,1078462536,3267363522,1668034383,826031373,556543245,1077936192,2998681230,842808846,2965126284,
3250586049,2728929930,2998418058,1112280654,1364464965,859323147,3504086220,1617438792,1937522511,2426150028,3503823048,1112017482,1381242438,1936996167,2694848640,3790351821,1111754310,2981377413,589835019,1633953093,4076354250,3823117251,2981640585,2981114241,2476482447,1381768782,4059576777,3806602950,2997891714,825241857,3806866122,1634479437,1398546255,3773048004,4042272960,3251375565,2156398728,303306246,842545674,1347950664,3503559876,1650467394,556280073,50595591,858796803,3773311176,320346891,
17040645,1903704393,2425360512,1650993738,573057546,2459441802],[137377848,3370182696,220277805,2258805798,3485715471,3469925406,2209591347,2293282872,2409868335,1080057888,1162957845,3351495687,1145062404,1331915823,1264805931,1263753243,3284385795,1113743394,53686323,2243015733,153167913,2158010400,3269648418,2275648551,3285438483,2173800465,17895441,100795398,202382364,2360392764,103953462,1262700555,3487820847,2290124808,1281387564,2292230184,118690839,3300967428,101848086,3304125492,3267543042,
1161905157,3252805665,3335705622,255015999,221330493,2390920206,2291177496,136325160,1312967694,3337810998,238173246,2241963045,3388078137,218172429,3486768159,3369130008,186853419,1180853286,1249015866,119743527,253963311,3253858353,1114796082,1111638018,3302020116,1094795265,3233857536,1131638835,1197696039,2359340076,2340653067,3354653751,2376182829,2155905024,252910623,3401762826,203435052,2325915690,70267956,3268595730,184748043,3470978094,3387025449,1297177629,2224067604,135272472,3371235384,
1196643351,2393025582,134219784,3317810181,51580947,3452029965,2256700422,2310125625,3488873535,1299283005,3250700289,20000817,3320968245,2323810314,1247963178,2175905841,3251752977,2105376,3352548375,33685506,35790882,67109892,1214277672,1097953329,117638151,3419658267,2375130141,2308020249,1096900641,2394078270,3336758310,1230067737,3453082653,1095847953,2156957712,3436239900,2324863002,2208538659,2342758443,3234910224,2172747777,251857935,1195590663,168957978,3286491171,3437292588,2374077453,2410921023,
2257753110,1265858619,1280334876,2191695906,2174853153,1130586147,52633635,1296124941,3368077320,2391972894,2358287388,171063354,201329676,237120558,2326968378,1315073070,2408815647,1246910490,3270701106,2190643218,3287543859,1229015049,1215330360,3435187212,85005333,3421763643,1081110576,1165063221,1332968511,87110709,1052688,50528259,1147167780,1298230317,3334652934,1148220468,3318862869,2226172980,3403868202,151062537,1181905974,152115225,3472030782,1077952512,34738194,3235962912,2377235517,83952645,
3404920890,16842753,3237015600,170010666,1314020382,2309072937,1179800598,1128480771,2239857669,68162580,2306967561,2341705755,2159063088,3319915557,1212172296,1232173113,2274595863,3438345276,236067870,2189590530,18948129,2357234700,185800731,1330863135,1198748727,1146115092,2192748594,219225117,86058021,1329810447,0,1178747910,3454135341,1213224984,1112690706,3420710955,1316125758,3402815514,3384920073,3455188029,3158064,2240910357,1164010533,204487740,2259858486,3303072804,2343811131,1282440252,
235015182,1079005200,154220601,102900774,36843570,2223014916,1231120425,2207485971,120796215,3353601063,69215268,2225120292,3418605579,1129533459,167905290,2273543175,3385972761,1279282188,2206433283,2407762959,3468872718,187906107,1245857802,2276701239]],s=[2654435769,1013904243,2027808486,4055616972,3816266649,3337566003,2380164711,465362127,930724254,1861448508,3722897016,3150826737,2006686179,4013372358,3731777421,3168587547],t=m.algo.SEED=d.extend({_doReset:function(){for(var c=this._key,d=c.words[0],
m=c.words[1],a=c.words[2],c=c.words[3],e=[],l=0;16>l;l++)if(e[l]=[],e[l][0]=u(d+a-s[l]),e[l][1]=u(m-c+s[l]),0==l%2)var b=d,d=d>>>8|m<<24,m=m>>>8|b<<24;else b=a,a=a<<8|c>>>24,c=c<<8|b>>>24;this._roundKeys=e;this._invRoundKeys=e.slice().reverse()},encryptBlock:function(c,d){this._doCryptBlock(c,d,this._roundKeys)},decryptBlock:function(c,d){this._doCryptBlock(c,d,this._invRoundKeys)},_doCryptBlock:function(c,d,m){for(var a=c.slice(d,d+2),e=c.slice(d+2,d+4),l=[a,e],a=0;16>a;a++){var e=m[a],b=l[0],l=
l[1],r=[];r[0]=l[0]^e[0];r[1]=l[1]^e[1];r[1]^=r[0];r[1]=u(r[1]);r[0]+=r[1];r[0]=u(r[0]);r[1]+=r[0];r[1]=u(r[1]);r[0]+=r[1];b[0]^=r[0];b[1]^=r[1];l=[l,b]}l.reverse();c.splice(d,4,l[0][0],l[0][1],l[1][0],l[1][1])},keySize:4,ivSize:4,blockSize:4});m.SEED=d._createHelper(t)})();

/*
CryptoJS v3.1.2
code.google.com/p/crypto-js
(c) 2009-2013 by Jeff Mott. All rights reserved.
code.google.com/p/crypto-js/wiki/License
*/
CryptoJS.pad.AnsiX923={pad:function(a,d){var b=a.sigBytes,c=4*d,c=c-b%c,b=b+c-1;a.clamp();a.words[b>>>2]|=c<<24-8*(b%4);a.sigBytes+=c},unpad:function(a){a.sigBytes-=a.words[a.sigBytes-1>>>2]&255}};


async function login(jsessionid, login_key, id, password){
	await keyModule.init( '/sso/usr/postech/login/init', 'ko' , jsessionid);
	//await new Promise(r => setTimeout(r, 1000));
	await loginModule.auth('/sso/usr/postech/login/auth', 'ko', jsessionid, login_key, id, password);
}
//test(jsessionid,login_key);

module.exports = { login };
