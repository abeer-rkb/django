from django.shortcuts import render

# Create your views here.

def index(request):
    return render(request,'index.html')  


def legitimate(request):
    return render(request, "legitimate.html")

def phishing(request):
    return render(request, "phishing.html")    

import warnings
warnings.filterwarnings("ignore")

from django.shortcuts import render, redirect
from .utils import preprocess_website, classify_website, classifier

def classify_view(request):
    if request.method == 'POST':
        url = request.POST.get('url')
        print('url:', url)
        is_phishing = classify_website(url)
        result = classifier(is_phishing)
        if result == 'Legitimate website':
            return redirect('legitimate')
        else:
            return redirect('phishing')
    else:
        return render(request, 'home.html')    