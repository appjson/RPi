import requests
import rsa
from urllib import parse
import hashlib
import base64

appkey = "1d8b6e7d45233436"
appsecret = "560c52ccd288fed045859ed18bffd973"
build = 8230
mobi_app = "iphone"
platform = "ios"


def calc_sign(str):
    str += appsecret
    hash = hashlib.md5()
    hash.update(str.encode('utf-8'))
    sign = hash.hexdigest()
    return sign


def calc_name_passw(key, hash, username, password):
    pubkey = rsa.PublicKey.load_pkcs1_openssl_pem(key.encode())
    password = base64.b64encode(rsa.encrypt(
        (hash + password).encode('utf-8'), pubkey))
    password = parse.quote_plus(password)
    username = parse.quote_plus(username)
    return username, password


resp = requests.get("https://passport.bilibili.com/login?act=getkey&r=0.11975121303174707")
resp = resp.json()
hash = resp["hash"]
key = resp["key"]

username, password = calc_name_passw(key, hash, "17082882809", "654123Bili.")
url = "https://passport.snm0516.aisee.tv/api/tv/login"
temp_params = f"appkey={appkey}&build={build}&captcha=&channel=master&guid=XYEBAA3E54D502E17BD606F0589A356902FCF&mobi_app={mobi_app}&password={password}&platform={platform}&token=5598158bcd8511e1&ts=0&username={username}"
data = f"{temp_params}&sign={calc_sign(temp_params)}"
headers = {"Content-type": "application/x-www-form-urlencoded"}
response = requests.post(url, data=data, headers=headers)
print(response.json())
