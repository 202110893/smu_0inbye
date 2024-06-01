from django.shortcuts import render, redirect
from django.http import HttpResponse, JsonResponse
import requests
import json
from django.template import loader


def index(request):
    return render(request,'kakaopay/index.html')


def kakaopay(request):
    if request.method == "POST":
        _admin_key = '08e7fe96815c0226bacfa3ad85bac563'
        _url = f'https://kapi.kakao.com/v1/payment/ready'
        _headers = {
            'Authorization': f'KakaoAK {_admin_key}',
            "Content-type": "application/x-www-form-urlencoded;charset=utf-8",
            }
        _data = {
            'cid': 'TC0ONETIME',
            'partner_order_id':'partner_order_id',
            'partner_user_id':'partner_user_id',
            'item_name':'등기부등본',
            'quantity':'1',
            'total_amount':'720',
            'vat_amount':'0',
            'tax_free_amount':'0',  
            'approval_url':'http://127.0.0.1:8000/kakaopay/paySuccess', 
            'fail_url':'http://127.0.0.1:8000/payFail',
            'cancel_url':'http://127.0.0.1:8000/payCancel'
            }

        _res = requests.post(_url, headers=_headers, data=_data)
        request.session['tid'] = _res.json()['tid']      # 결제 승인시 사용할 tid를 세션에 저장

        full_address = request.GET.get('fullAddress')
        request.session['full_address'] = full_address

        next_url = _res.json()['next_redirect_pc_url']   
        return redirect(next_url)

    return render(request, 'kakaopay/kakaopay.html')

def paySuccess(request):
    _admin_key = '08e7fe96815c0226bacfa3ad85bac563'
    _url = f'https://kapi.kakao.com/v1/payment/approve'
    _headers = {
        'Authorization': f'KakaoAK {_admin_key}',
        "Content-type": "application/x-www-form-urlencoded;charset=utf-8",
    }
    _data = {
        "cid": "TC0ONETIME",    # 테스트용 코드
        "tid": request.session['tid'],  
        'partner_order_id':'partner_order_id',
        'partner_user_id':'partner_user_id',    
        'pg_token': request.GET['pg_token'],     
    }
    _res = requests.post(_url, data=_data, headers=_headers)
    _result = _res.json()
    
    if _result.get('msg'):
        return redirect('kakaopay/PayFail.html')

    else:
        full_address = request.session.get('full_address')
        #print(full_address)
        return render(request, 'kakaopay/paySuccess.html', {'full_address': full_address})

def payFail(request):
    return render(request, 'kakaopay/payFail.html')  

def payCancel(request):
    return render(request, 'kakaopay/payCancel.html')