from django.shortcuts import render

# Create your views here.
import os, json, base64
import requests
from Crypto import PublicKey
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5, AES
from django.http import JsonResponse

apiHost = 'https://api.tilko.net/'
apiKey  = 'd4cd43b9abe844909fe998677d50931a'


# AES 암호화 함수
def aesEncrypt(key, iv, plainText):
    def pad(text):
        text_length     = len(text)
        amount_to_pad   = AES.block_size - (text_length % AES.block_size)

        if amount_to_pad == 0:
            amount_to_pad = AES.block_size
            
        pad     = chr(amount_to_pad)

        result  = None
        try:
            result  = text + str(pad * amount_to_pad).encode('utf-8')
        except Exception as e:
            result  = text + str(pad * amount_to_pad)

        return result
    
    if type(plainText) == str:
        plainText = plainText.encode('utf-8')
    
    plainText   = pad(plainText)
    cipher      = AES.new(key, AES.MODE_CBC, iv)
    
    if(type(plainText) == bytes):
        return base64.b64encode(cipher.encrypt(plainText)).decode('utf-8')
    else:
        return base64.b64encode(cipher.encrypt(plainText.encode('utf-8'))).decode('utf-8')


# RSA 암호화 함수(RSA 공개키로 AES키 암호화)
def rsaEncrypt(publicKey, aesKey):
    rsa             = RSA.importKey(base64.b64decode(publicKey))
    cipher          = PKCS1_v1_5.new(rsa.publickey())
    aesCipherKey	= cipher.encrypt(aesKey)
    return aesCipherKey


# RSA 공개키(Public Key) 조회 함수
def getPublicKey(request):
    headers = {'Content-Type': 'application/json'}
    response = requests.get(apiHost + "/api/Auth/GetPublicKey?APIkey=" + apiKey, headers=headers)
    rsaPublicKey=response.json()['PublicKey']
    return rsaPublicKey

# RSA Public Key 조회
rsaPublicKey = getPublicKey(requests)
print(f"rsaPublicKey: {rsaPublicKey}")#f는 포맷임

# AES Secret Key 및 IV 생성
aesKey = os.urandom(16)
aesIv = ('\x00' * 16).encode('utf-8')


# AES Key를 RSA Public Key로 암호화
aesCipherKey = base64.b64encode(rsaEncrypt(rsaPublicKey, aesKey))
print(f"aesCipherKey: {aesCipherKey}")



#부동산 고유번호 api 호출
nourl=apiHost +"/api/v1.0/iros/risuconfirmsimplec"
options     = {
    "headers": {
        "Content-Type"          : "application/json",
        "API-KEY"               : apiKey,
        "ENC-KEY"               : aesCipherKey
    },
    
    "json": {
        "Address"                : "경상북도 포항시 남구 동해면 약전리 366-3",
        "Sangtae"              : "0",
        "KindClsFlag"             : "0",
        "Region"        : "0",
        "Page"            : "2",

    },
}
uniqueno_res = requests.post(nourl, headers=options['headers'], json=options['json'])
print(f"res: {uniqueno_res.json()}")

#str 형식 확인용 코드
# data = uniqueno_res.json()['ResultList'][0]['UniqueNo']
# print(type(data))
#UniqueNo = base64.b64decode(uniqueno_res.json()['ResultList'][0]['UniqueNo']).decode("utf-8") #부동산 고유번호
UniqueNo =uniqueno_res.json()['ResultList'][0]['UniqueNo']
print(f"UniqueNo: {UniqueNo}")

##UniqueNo=base64.b64decode(uniqueno_res.json()['ResultList'][0]['UniqueNo']).decode("utf-8")
# API URL 설정: https://tilko.net/Help/Api/POST-api-apiVersion-FssLifeplan-RegisterStep1)
url         = apiHost + "/api/v1.0/iros/risuretrieve"
iros_id = "ham1209"
iros_pw = "euna0825."
emoney_pwd="hameuna1209"

# API 요청 파라미터 설정
options     = {
    "headers": {
        "Content-Type"          : "application/json",
        "API-KEY"               : apiKey,
        "ENC-KEY"               : aesCipherKey
    },
    
    "json": {
        "IrosId"                : aesEncrypt(aesKey, aesIv, iros_id),
        "IrosPwd"              : aesEncrypt(aesKey, aesIv, iros_pw),
        "EmoneyNo1"             : aesEncrypt(aesKey, aesIv, "Y8381523"),
        "EmoneyNo2"        : aesEncrypt(aesKey, aesIv, "3913" ),
        "EmoneyPwd"            : aesEncrypt(aesKey, aesIv, emoney_pwd),
        "UniqueNo"           : UniqueNo,  
        "JoinYn"           : "N",
        "CostsYn"           :"N",
        "DataYn"        :"N",
        "ValidYn":          "N",
    },
}




# API 호출
res = requests.post(url, headers=options['headers'], json=options['json'])
print(f"res: {res.json()}")
t_Key=base64.b64decode(res.json()["TransactionKey"]).decode("utf-8") # 트랜잭션 키 획득
print(f"res: {res.json()}")
# 파일 저장
with open("D:\\result", "w") as f:
    f.write(base64.b64decode(res.json()["TransactionKey"]))