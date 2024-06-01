# api_app/views.py
import time
import json
# Create your views here.
import os, json, base64
import requests
from Crypto import PublicKey
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5, AES
from django.http import JsonResponse
import datetime
from django.http import HttpResponse
import xmltodict
import re
from django.shortcuts import render
from .models import Address

def success(request):
    full_address = request.GET.get('fullAddress')  # GET 매개변수에서 fullAddress 값을 가져옴
    if full_address:
        # full_address가 존재할 때 Address 모델에 저장
        address_instance = Address(full_address=full_address)
        address_instance.save()

    latest_address = getaddr()
    # 템플릿에 전달할 컨텍스트 사전
    context = {
        'full_address': full_address,
        'latest_address': latest_address
    }
        
    apiKey="f482cb3c75b844d3897381c08b84acbb"
    # RSA Public Key 조회
    apiHost="https://api.tilko.net/"
    rsaPublicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArSkp4g/y8Cjth38S9QafsyAwXQwgzCG+3oZDfM1IIYMoAetQ8ufbUCB8ai7pTlivYYDZXQvzbd7OHgKAkH9uuBlPA+ybg7eqoy8C2HPKWuaszlmVUvjR3QMe4F9DEXyN2zmrpenssHg4Pr9TARPW9ut1E+gSN8qhvmPmIVl59IdHfXy12R51GmNI8Jt3iDseduR6UElVfUg0B9p0/4FHseHkflVodxcf4TcYY5rnrSnHwwniuehf3lJM+LUKH3Dfr/vlW29iOQ9YVMeynga/F863+xCGENFl9W+jDjVxN1fR20EGshWiTqo0S633EBOAbtHYihaOZhD2g1u51xO01QIDAQAB"
    print(f"rsaPublicKey: {rsaPublicKey}")#f는 포맷임

    # AES Secret Key 및 IV 생성
    aesKey = os.urandom(16)
    aesIv = ('\x00' * 16).encode('utf-8')


    # AES Key를 RSA Public Key로 암호화
    aesCipherKey = base64.b64encode(rsaEncrypt(rsaPublicKey, aesKey))
    print(f"aesCipherKey: {aesCipherKey}")



    ############################################################################
    #부동산 고유번호 api 호출
    nourl=apiHost +"/api/v1.0/iros/risuconfirmsimplec"
    options     = {
        "headers": {
            "Content-Type"          : "application/json",
            "API-KEY"               : apiKey,
            "ENC-KEY"               : aesCipherKey
        },
        
        "json": {
            "Address"                : latest_address, #변수로 정보를 받아와야함
            "Sangtae"              : "0",
            "KindClsFlag"             : "0",
            "Region"        : "0",
            "Page"            : "1",

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
    emoney_pwd="euna0825"
    #전자민원캐시 비밀번호 : hameuna1209

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
    ############################################################################



    ############################################################################
    # xml API 호출
    res = requests.post(url, headers=options['headers'], json=options['json'])
    res_json = res.json()
    #print(f"res.json: {res_json}")
    res_xml=res.json()["Message"]
    t_Key = res.json()["TransactionKey"]
    print(f"t_Key: {t_Key}")
    #갑을구 주요정보
    info=apiHost +"/api/v2.0/IrosArchive/ParseXml"
    options     = {
        "headers": {
            "Content-Type"          : "application/json",
            "API-KEY"               : apiKey,
            "ENC-KEY"               : aesCipherKey
        },
        
        "json": {
            "TransactionKey"                :t_Key , 
            

        },
    }
    info_res = requests.post(info, headers=options['headers'], json=options['json'])
    #print(f"info res: {info_res.json()}")



    with open("C:/Users/hamea/OneDrive/바탕 화면/info.txt", "w", encoding="utf-8") as file:
        file.write(f"{info_res.json()}\n")
    return render(request, 'api_app/success.html', {'full_address': full_address})


def getaddr():
    try:
        # 데이터베이스에서 가장 최근에 저장된 주소 불러오기
        latest_address = Address.objects.latest('id')
        print(f"Latest Address: {latest_address.full_address}")
        return latest_address.full_address
    except Address.DoesNotExist:
        print("No addresses found in the database.")
        return None
    
    
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
