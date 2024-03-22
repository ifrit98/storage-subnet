import json
from django.http import HttpResponse
import requests
from django.shortcuts import render, redirect
from .forms import UploadFileForm
from io import BytesIO


def home(request):
    return render(request, 'index.html')

def logout_view(request):
    request.session.flush()
    return redirect('home')

def register_view(request):
    base_url = "http://127.0.0.1:8000"
    
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        if username and password:
            response = requests.post(f'{base_url}/register/', json={'username': username, 'password': password})
            if response.status_code == 200:
                data = response.json()
                request.session['username'] = username  # Set the session variable
                
                # get token
                token_response = requests.post(f'{base_url}/token', data={"username": username, "password": password})
                
                request.session['token'] = token_response.json()['access_token']
                
                return render(request, 'accounts/success.html', {'data': data, 'token_data': token_response.json()})

            elif response.status_code == 400:
                # get token
                token_response = requests.post(f'{base_url}/token', data={"username": username, "password": password})
            
                if token_response.status_code == 200:
                    data = token_response.json()
                    request.session['username'] = username
                    request.session['token'] = data['access_token']
                    
                    return render(request, 'accounts/success.html', {'data': data})
                else:
                    data = token_response.json()
                    request.session['username'] = None
                    request.session['token'] = None
                    
                    return render(request, 'accounts/success.html', {'data': data})
            else:
                data = response.json()
                return render(request, 'accounts/success.html', {'data': data})   
    return render(request, 'accounts/register.html')

def login_view(request):
    base_url = "http://127.0.0.1:8000"
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        if username and password:
            data = {"username": username, "password": password}
            
            response = requests.post(f'{base_url}/token', data=data)
            if response.status_code == 200:
                data = response.json()
                request.session['username'] = username  # Set the session variable
                request.session['token'] = data['access_token']
                
                return render(request, 'accounts/success.html', {'data': data})
            else:
                data = response.json()
                return render(request, 'accounts/success.html', {'data': data})   
    return render(request, 'accounts/login.html')

def upload_file_view(request):
    base_url = "http://127.0.0.1:8000"
    if request.method == 'POST':
        form = UploadFileForm(request.POST, request.FILES)
        if form.is_valid():
            file = request.FILES['file']
            token = request.session.get('token')
            response = upload_file(base_url, token, file)
            return render(request, 'accounts/success.html', {'data': response})
    else:
        form = UploadFileForm()
    return render(request, 'accounts/upload.html', {'form': form})

def upload_file(base_url, token: str, file):
    print(file)
    data = {'filename': file.name, 'msg': 'hello', 'type': 'multipart/form-data'}
    files = {"file": ("test.txt", "test")}
    headers = {'Authorization': f'Bearer {token}'}
    response = requests.post(f'{base_url}/uploadfiles/', json=data, files=files, headers=headers)
    
    try:
        return response.json()
    except json.decoder.JSONDecodeError:
        return {'error': 'The server returned an empty response'}
    
def retrieve_file_view(request):
    base_url = "http://127.0.0.1:8000"
    if request.method == 'POST':
        file_hash = request.POST.get('file_hash')
        headers = {"Authorization": f"Bearer {request.session.get('token')}"}
        response = requests.get(f"{base_url}/retrieve/{file_hash}", headers=headers)
        return response.json()

    return render(request, 'accounts/retrieve.html')
        