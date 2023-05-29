import pickle
import numpy as np
import ipaddress
import re
import urllib.request    
from bs4 import BeautifulSoup
import socket
import requests
from googlesearch import search
import whois
from datetime import date, datetime
import time
from dateutil.parser import parse as date_parse
from urllib.parse import urlparse
from dns import resolver



def having_IP_Address(url):
      parsedurl = urlparse(url)
      domain = parsedurl.netloc
      
      try:
            ipaddress.ip_address(domain)
            return 1
      except:
            return -1


def URL_Length(url):
        if len(url) < 54:
            return -1
        elif len(url) >= 54 and len(url) <= 75:
            return 0
        else:
            return 1


def Shortining_Service(url):
        shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
            r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
            r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
            r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
            r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
            r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
            r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
            r"tr\.im|link\.zip\.net"
        if re.search(shortening_services, url):
            return 1
        else:
            return -1


def having_At_Symbol(url):
        if '@' in url:
            return 1
        else:
            return -1


def double_slash_redirecting(url):
        if re.search(r'https?://[^\s]*//', url):
            return 1
        else:
            return -1


def Prefix_Suffix(url):
        parsedurl = urlparse(url)
        domain = parsedurl.netloc   
        if '-' in domain:
            return 1
        else:
            return -1


def having_Sub_Domain(url):
        parsedurl = urlparse(url)
        domain = parsedurl.netloc 
        count = domain.count('.')
        if count <= 2:
            return -1
        elif count > 2 and count <= 3:
            return 0
        else:
            return 1




def domain_registration_length(url):
    parsedurl = urlparse(url)
    domain = parsedurl.netloc
    try:
        whois_info = whois.whois(domain)
    except:
        whois_info = None

    if whois_info is None:
        return 1

    try:
        if type(whois_info['expiration_date']) is list:
            expiration_date = whois_info['expiration_date'][0]
        else:
            expiration_date = whois_info['expiration_date']

        registration_length = abs(
            (expiration_date - datetime.now()).days)
        if registration_length / 30 >= 6:
            return -1
        else:
            return 1
    except:
        return 1


def URL_Depth(url):
        parsedurl = urlparse(url)
        depth = 0
        subdirs = parsedurl.path.split('/')
        for subdir in subdirs:
            if subdir:
                depth += 1
        return depth


def Favicon(url):
    try:
         request = requests.get(url, timeout=5, headers={
                                        "User-Agent": "Mozilla/5.0 (X11; CrOS x86_64 12871.102.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.141 Safari/537.36"
                                        ,"Connection": "keep-alive"})
         soup = BeautifulSoup(request.content, 'html.parser')
    except:
         request = None
         soup = None
    try:
        if re.findall(r'favicon', soup.text) or \
                soup.find('link', rel='shortcut icon') or \
                soup.find('link', rel='icon'):
            return -1
        else:
            return 1
    except:
        return 1


def port(url):
        parsedurl = urlparse(url)   
        if parsedurl.port:
            return 1
        else:
            return -1


def HTTPS_token(url):
    parsedurl = urlparse(url)
    domain = parsedurl.netloc
    if 'https' in domain:
        return 1
    else:
        return -1

def Request_URL(url):
        try:
         request = requests.get(url, timeout=5, headers={
                                        "User-Agent": "Mozilla/5.0 (X11; CrOS x86_64 12871.102.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.141 Safari/537.36"})
        except:
         request = None
        try:
            if len(request.history) <= 1:
                return -1
            elif len(request.history) <= 3:
                return 0
            else:
                return 1
        except:
            return -1 #1



def URL_of_Anchor(url):
        try:
         request = requests.get(url, timeout=5, headers={
                                        "User-Agent": "Mozilla/5.0 (X11; CrOS x86_64 12871.102.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.141 Safari/537.36"})
         soup = BeautifulSoup(request.content, 'html.parser')
        except:
            request = None
            soup = None
        try:
            count = 0
            for i in soup.find_all('a'):
                if i.has_attr('href'):
                    count += 1
            if count == 0:
                return 1
            else:
                return -1
        except:
            return 1



def Links_in_tags(url):
        try:
         request = requests.get(url, timeout=5, headers={
                                        "User-Agent": "Mozilla/5.0 (X11; CrOS x86_64 12871.102.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.141 Safari/537.36"})
         soup = BeautifulSoup(request.content, 'html.parser')
        except:
            request = None
            soup = None
        try:
            count = 0
            for i in soup.find_all('link'):
                if i.has_attr('href'):
                    count += 1
            if count == 0:
                return 1
            else:
                return -1
        except:
            return 1


def SFH(url):
        try:
         request = requests.get(url, timeout=5, headers={
                                        "User-Agent": "Mozilla/5.0 (X11; CrOS x86_64 12871.102.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.141 Safari/537.36"})
         soup = BeautifulSoup(request.content, 'html.parser')
        except:
            request = None
            soup = None
        try:
            if soup.find('form'):
                return 1
            else:
                return -1
        except:
            return 0


def Submitting_to_email(url):
        try:
         request = requests.get(url, timeout=5, headers={
                                        "User-Agent": "Mozilla/5.0 (X11; CrOS x86_64 12871.102.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.141 Safari/537.36"})
         soup = BeautifulSoup(request.content, 'html.parser')
        except:
            request = None
            soup = None
        try:
            if soup.find('mailto:'):
                return 1
            else:
                return -1
        except:
            return 0



def Abnormal_URL(url):
        try:
         request = requests.get(url, timeout=5, headers={
                                        "User-Agent": "Mozilla/5.0 (X11; CrOS x86_64 12871.102.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.141 Safari/537.36"})
         soup = BeautifulSoup(request.content, 'html.parser')
        except:
            request = None
            soup = None
        try:
            if re.findall(r'script|javascript|alert|onmouseover|onload|onerror|onclick|onmouse', url):
                return 1
            else:
                return -1
        except:
            return -1 #1


def Redirect(url):
        try:
         request = requests.get(url, timeout=5, headers={
                                        "User-Agent": "Mozilla/5.0 (X11; CrOS x86_64 12871.102.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.141 Safari/537.36"})
         soup = BeautifulSoup(request.content, 'html.parser')
        except:
            request = None
            soup = None
        try:
            if soup.find('meta', attrs={'http-equiv': 'refresh'}):
                return 1
            else:
                return -1
        except:
            return -1 #1



def on_mouseover(url):
        try:
         request = requests.get(url, timeout=5, headers={
                                        "User-Agent": "Mozilla/5.0 (X11; CrOS x86_64 12871.102.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.141 Safari/537.36"})
         soup = BeautifulSoup(request.content, 'html.parser')
        except:
            request = None
            soup = None

        try:
            if re.findall(r"onmouseover", soup.text):
                return 1
            else:
                return -1
        except:
            return -1


def RightClick(url):
        try:
         request = requests.get(url, timeout=5, headers={
                                        "User-Agent": "Mozilla/5.0 (X11; CrOS x86_64 12871.102.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.141 Safari/537.36"})
         soup = BeautifulSoup(request.content, 'html.parser')
        except:
            request = None
            soup = None


        try:
            if re.findall(r"contextmenu|event.button ?== ?2", soup.text):
                return 1
            else:
                return -1
        except:
            return -1


def popUpWidnow(url):
        try:
         request = requests.get(url, timeout=5, headers={
                                        "User-Agent": "Mozilla/5.0 (X11; CrOS x86_64 12871.102.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.141 Safari/537.36"})
         soup = BeautifulSoup(request.content, 'html.parser')
        except:
            request = None
            soup = None
        try:
            if re.findall(r"alert\(|onMouseOver|window.open", soup.text):
                return 1
            else:
                return -1
        except:
            return -1


def Iframe(url):
        try:
         request = requests.get(url, timeout=5, headers={
                                        "User-Agent": "Mozilla/5.0 (X11; CrOS x86_64 12871.102.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.141 Safari/537.36"})
         soup = BeautifulSoup(request.content, 'html.parser')
        except:
            request = None
            soup = None
    
        try:
            if re.findall(r"[<iframe>|<frameBorder>]", soup.text):
                return 1
            else:
                return -1
        except:
            return -1 #1



def age_of_domain(url):

    parsedurl = urlparse(url)
    domain = parsedurl.netloc
    try:
        whois_info = whois.whois(domain)
    except:
        whois_info = None

    if whois_info is None:
        return 1

    try:
        if type(whois_info['creation_date']) is list:
            creation_date = whois_info['creation_date'][0]
        else:
            creation_date = whois_info['creation_date']

        ageofdomain = abs((datetime.now() - creation_date).days)
        if ageofdomain / 30 >12:
            return -1
        else:
            return 1
    except:
        return 1


def DNSRecord(url):
        parsedurl = urlparse(url)
        domain = parsedurl.netloc
        try:
            resolver.resolve(domain, 'A')
            return -1
        except:
            return 1



def getInput(url):
 
  input = []
  #print(domain)
  input.append(having_IP_Address(url))
  input.append(URL_Length(url))
  input.append(Shortining_Service(url))
  input.append(having_At_Symbol(url))
  input.append(double_slash_redirecting(url))
  input.append(Prefix_Suffix(url))
  input.append(having_Sub_Domain(url))
  input.append(URL_Depth(url))
  input.append(domain_registration_length(url))
  input.append(Favicon(url))
  input.append(port(url))
  input.append(HTTPS_token(url))
  input.append(Request_URL(url))
  input.append(URL_of_Anchor(url))
  input.append(Links_in_tags(url))
  input.append(SFH(url))
  input.append(Submitting_to_email(url))
  input.append(Abnormal_URL(url))
  input.append(Redirect(url))
  input.append(on_mouseover(url))
  input.append(RightClick(url))
  input.append(popUpWidnow(url))
  input.append(Iframe(url))
  input.append(age_of_domain(url))
  input.append(DNSRecord(url))

  return (input)

# load the model from disk

filename1 = 'app/randomForestModel.pickle'
model = pickle.load(open(filename1, 'rb'))


# Define a function to preprocess the website URL and create features for the model
def preprocess_website(url):
    input_vector = np.array(getInput(url))
    return input_vector



def classify_website(url):
    # Preprocess the website URL
  #try:
    input_vector = preprocess_website(url)

    # Use the saved  model to classify the website
    is_phishing  = model.predict(input_vector.reshape(1,-1))

  #url : https://gouvantai.info/app/ 
  
  #except requests.exceptions.RequestException as e:
        #print(f"An error occurred while accessing the URL: {e}")
        #is_phishing = 1  # Changed to 1 for phishing
  #except socket.gaierror as e:
        #print(f"DNS resolution error: {e}")
        #is_phishing = 1  # Changed to 1 for phishing  
    return is_phishing

def classifier(is_phishing):
    if is_phishing == 0:
        return 'Legitimate website'
    else:
        return 'Phishing website'















