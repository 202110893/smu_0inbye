import time
from django.shortcuts import render
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
import xml.etree.ElementTree as ET
now = time.localtime()
print(f"{now.tm_year}/{now.tm_mon}/{now.tm_mday} {now.tm_hour}:{now.tm_min}:{now.tm_sec}")






    
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


# # RSA 공개키(Public Key) 조회 함수
# def getPublicKey(request):
#     headers = {'Content-Type': 'application/json'}
#     response = requests.get(apiHost + "/api/Auth/GetPublicKey?APIkey=" + apiKey, headers=headers)
#     rsaPublicKey=response.json()['PublicKey']
#     return rsaPublicKey


# #주소 획득 함수
# def getAddr(request):
#     Addr= pass
#     return Addr


apiKey="d4cd43b9abe844909fe998677d50931a"
# RSA Public Key 조회
apiHost="https://api.tilko.net/"
rsaPublicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAliB+NjGN7C4rohPd/8rHmIKT/Xbxsv+8IrjvySBalWrv15YYDVMfKpX7bRVmWL4XUM5cuNe65Zkbjcx2TdjZl0Ii+54ol7D/OaP+RDqJ3JPU34zIFOI6hNs0SZoPAn/zvCmvLcCm0e6XsV7Zhni7fBmyp/Pq0JaCJWNtm6ninsM4mLCREtnC5fsjrgXzHqq7In/q9MEFDRMqYLv/obUc3FQaG2/vq1UegnO+DmjGcaykStjdwEqFPjEKiE9tUduiDvTiMHw8mhoo7kl6DE30NwayrDvSnYj1ZEDHLOinIj2q/FXwMpuydvt88RQ5mJXdZipJPuP64xQcIZph5SjChQIDAQAB"
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
        "Address"                : "서울특별시 관악구 보라매로 62 보라매삼성아파트 102동 1505호", #변수로 정보를 받아와야함
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
print(f"res.json: {res_json}")
res_xml=res.json()["Message"]

# #xml 파일로 저장

# xml_file_path = r"C:/Users/hamea/smu_0inbye/res.xml"
# with open(xml_file_path, "w") as xml_file:
#     xml_file.write(res_xml)

# # XML 파일 string으로 바꾸기
# with open(xml_file_path, 'r', encoding='utf-8') as file:
#     xml_string = file.read()

## 태그 뒷 내용 지우기
xml_string = re.sub(r'<summary>.*', '', res_xml, flags=re.DOTALL)
print(xml_string)  # 문자열로 된 XML 내용 출력

root = ET.fromstring(xml_string)
xml_file_path = 'C:/Users/hamea/smu_0inbye/res.xml'
ET.ElementTree(root).write(xml_file_path, encoding='utf-8')

print(f"XML이 {xml_file_path} 경로에 저장되었습니다.")

#json으로 변환
with open('C:/Users/hamea/smu_0inbye/res.xml', encoding='utf-8') as f:
    doc = xmltodict.parse(f.read())
                          
json_data = json.loads(json.dumps(doc))

with open('C:/Users/hamea/smu_0inbye/res_result.json', 'w', encoding='utf-8') as json_file:
    json.dump(json_data, json_file, ensure_ascii=False, indent=4)

#트랜잭션 키 값
t_Key = res.json()["TransactionKey"]
print(f"t_Key: {t_Key}")



############################################################################

############################################################################
# # XML 파일 읽기
# tree = ET.parse('res_xml.xml')
# root = tree.getroot()

# # 제거할 태그 목록
# tags_to_remove = ['summary', 'term', '3ndHS']

# # 각 태그에 포함된 내용 제거
# for tag_name in tags_to_remove:
#     # 태그 찾기
#     tags = root.findall('.//' + tag_name)
#     # 찾은 태그들의 내용 제거
#     for tag in tags:
#         tag.text = ''

# # 수정된 XML 파일 저장
# tree.write('res_modified.xml')


 
# with open('res_xml.xml', encoding='utf-8') as f:
#     doc = xmltodict.parse(f.read())
                          
# json_data = json.loads(json.dumps(doc))

# with open('res_xml_to_json.json', 'w', encoding='utf-8') as json_file:
    # json.dump(json_data, json_file, ensure_ascii=False, indent=4)






############################################################################
#t_Key=base64.b64decode(res.json()["TransactionKey"]).decode("utf-8") # 트랜잭션 키 획득






############################################################################
#pdf 변환 api 호출
get_pdf=apiHost +"api/v1.0/iros/GetPdfFile"
options     = {
    "headers": {
        "Content-Type"          : "application/json",
        "API-KEY"               : apiKey,
        "ENC-KEY"               : aesCipherKey
    },
    
    "json": {
        "TransactionKey"                : t_Key,
        "IsSummary"              : "Y",
        
    },
}
getpdf_res = requests.post(get_pdf, headers=options['headers'], json=options['json'])
pdf_string = getpdf_res.json()["Message"]
#print(f"getpdf_res: {pdf_string}")


#pdf_string = getpdf_res.json()["Message"]

# Base64 디코딩하여 바이너리 데이터로 변환
pdf_binary_data = base64.b64decode(pdf_string)

# PDF 파일로 저장
with open("output.pdf", "wb") as pdf_file:
    pdf_file.write(pdf_binary_data)

# 파일 저장
with open("D:\\result", "w") as f:
    f.write(base64.b64decode(res.json()["TransactionKey"]))
############################################################################

############################################################################
# #갑을구 주요정보
# info=apiHost +"/api/v2.0/IrosArchive/ParseXml"
# options     = {
#     "headers": {
#         "Content-Type"          : "application/json",
#         "API-KEY"               : apiKey,
#         "ENC-KEY"               : aesCipherKey
#     },
    
#     "json": {
#         "TransactionKey"                :t_Key , 
        

#     },
# }
# info_res = requests.post(info, headers=options['headers'], json=options['json'])
# print(f"info res: {info_res.json()}")
############################################################################

now = time.localtime()
print(f"{now.tm_year}/{now.tm_mon}/{now.tm_mday} {now.tm_hour}:{now.tm_min}:{now.tm_sec}")