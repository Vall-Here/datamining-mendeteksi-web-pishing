from flask import Flask, request, render_template, flash, redirect, url_for
import pickle
import requests
from bs4 import BeautifulSoup
import tldextract
import re
import whois
import datetime
import numpy as np

# Fungsi untuk memuat model
def load_model(model_path):
    return pickle.load(open(model_path, 'rb'))

# Fungsi untuk mengecek HTTPS
def check_https(url):
    return 1 if url.startswith("https://") else -1

# Fungsi untuk mengecek panjang URL
def check_url_length(url):
    return 1 if len(url) >= 54 else (-1 if len(url) <= 7 else 0)

# Fungsi untuk mengecek IP Address di URL
def check_ip_in_url(url):
    return 1 if re.match(r'http[s]?://(?:[0-9]{1,3}\.){3}[0-9]{1,3}', url) else 0

# Fungsi untuk mengecek age of domain
def check_age_of_domain(url):
    try:
        domain_info = whois.whois(url)
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        age = (datetime.datetime.now() - creation_date).days
        return 1 if age >= 180 else -1
    except:
        return -1

# Fungsi untuk memeriksa apakah form handler sesuai
def check_sfh(url, soup):
    forms = soup.find_all('form')
    for form in forms:
        action = form.get('action')
        if action:
            domain = tldextract.extract(url).domain
            action_domain = tldextract.extract(action).domain
            if action_domain and domain != action_domain:
                return -1
    return 1

# Fungsi untuk memeriksa adanya pop-up
def check_pop_up(soup):
    scripts = soup.find_all('script')
    for script in scripts:
        if "window.open" in script.text:
            return -1
    return 1

# Fungsi untuk memeriksa Request_URL
def check_request_url(url, soup):
    domain = tldextract.extract(url).domain
    requests = soup.find_all(['img', 'audio', 'embed', 'iframe'])
    for request in requests:
        src = request.get('src')
        if src:
            request_domain = tldextract.extract(src).domain
            if request_domain and request_domain != domain:
                return -1
    return 1

# Fungsi untuk memeriksa URL of Anchor
def check_url_of_anchor(url, soup):
    domain = tldextract.extract(url).domain
    anchors = soup.find_all('a', href=True)
    total = len(anchors)
    suspicious = 0
    for anchor in anchors:
        href = anchor['href']
        anchor_domain = tldextract.extract(href).domain
        if anchor_domain and anchor_domain != domain:
            suspicious += 1
    if total > 0:
        ratio = suspicious / total
        if ratio < 0.31:
            return 1
        elif ratio < 0.67:
            return 0
        else:
            return -1
    return 1

# Fungsi untuk memeriksa web traffic (data fiktif)
def check_web_traffic():
    # Implementasi dengan API eksternal seharusnya dilakukan di sini
    # Contoh data fiktif
    traffic = 50000
    return 1 if traffic > 100000 else (0 if traffic > 10000 else -1)

# Fungsi utama untuk mengekstrak fitur dari URL
def extract_features(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
    except requests.RequestException as e:
        flash(f"Error connecting to {url}: {e}", "error")
        return None, None
    
    soup = BeautifulSoup(response.content, 'html.parser')
    
    sfh_status = check_sfh(url, soup)
    pop_up_status = check_pop_up(soup)
    ssl_status = check_https(url)
    request_url_status = check_request_url(url, soup)
    url_of_anchor_status = check_url_of_anchor(url, soup)
    web_traffic_status = check_web_traffic()
    url_length = check_url_length(url)
    age_of_domain = check_age_of_domain(url)
    ip_in_url = check_ip_in_url(url)
    
    features = {
        "SFH": sfh_status,
        "Pop Up Window": pop_up_status,
        "SSL Final State": ssl_status,
        "Request URL": request_url_status,
        "URL of Anchor": url_of_anchor_status,
        "Web Traffic": web_traffic_status,
        "URL Length": url_length,
        "Age of Domain": age_of_domain,
        "Having IP Address": ip_in_url
    }
    
    feature_array = np.array([sfh_status, pop_up_status, ssl_status, request_url_status, url_of_anchor_status, web_traffic_status, url_length, age_of_domain, ip_in_url]).reshape(1, -1)
    
    return feature_array, features

# Mengonversi nilai fitur menjadi deskripsi teks
def feature_description(features):
    descriptions = {}
    descriptions["SFH"] = "Phishing atau mencurigakan" if features["SFH"] in [-1, 0] else "Sah"
    descriptions["Pop Up Window"] = "Tidak ada pop-up yang mencurigakan" if features["Pop Up Window"] == 1 else ("Pop-up netral" if features["Pop Up Window"] == 0 else "Ada pop-up yang mencurigakan")
    descriptions["SSL Final State"] = "SSL sertifikat valid (HTTPS)" if features["SSL Final State"] == 1 else ("SSL sertifikat netral atau tidak dapat ditentukan" if features["SSL Final State"] == 0 else "SSL sertifikat tidak valid atau tidak ada (HTTP)")
    descriptions["Request URL"] = "URL meminta sumber daya dari domain yang sah" if features["Request URL"] == 1 else ("URL netral" if features["Request URL"] == 0 else "URL meminta sumber daya dari domain yang mencurigakan")
    descriptions["URL of Anchor"] = "Semua anchor URL menuju domain yang sah" if features["URL of Anchor"] == 1 else ("Sebagian anchor URL netral atau tidak dapat ditentukan" if features["URL of Anchor"] == 0 else "Banyak anchor URL menuju domain yang mencurigakan")
    descriptions["Web Traffic"] = "Lalu lintas web tinggi (banyak pengunjung, mengindikasikan situs yang populer)" if features["Web Traffic"] == 1 else ("Lalu lintas web sedang" if features["Web Traffic"] == 0 else "Lalu lintas web rendah (sedikit pengunjung, mengindikasikan situs tidak populer atau baru)")
    descriptions["URL Length"] = "URL panjang" if features["URL Length"] == 1 else ("URL dengan panjang sedang" if features["URL Length"] == 0 else "URL pendek")
    descriptions["Age of Domain"] = "Domain telah ada untuk waktu yang lama (lebih dari 6 bulan)" if features["Age of Domain"] == 1 else "Domain baru (kurang dari 6 bulan)"
    descriptions["Having IP Address"] = "URL memiliki alamat IP (biasanya mengindikasikan situs tidak sah atau phishing)" if features["Having IP Address"] == 1 else "URL tidak memiliki alamat IP (menggunakan nama domain)"
    return descriptions

# Memuat model yang telah disimpan
model_path = 'models/rf_model.sav'
rf_model = load_model(model_path)

app = Flask(__name__)
app.secret_key = 'supersecretkey'

@app.route("/", methods=["GET", "POST"])
def index():
    prediction = None
    features = None
    feature_descriptions = None
    if request.method == "POST":
        url = request.form.get("url")
        if not url:
            flash("URL tidak boleh kosong", "error")
        else:
            feature_array, features = extract_features(url)
            if feature_array is not None and features is not None:
                feature_descriptions = feature_description(features)
                prediction = rf_model.predict(feature_array)[0]
                return render_template('index.html', prediction=prediction, features=feature_descriptions)
    return render_template('index.html', prediction=prediction, features=feature_descriptions)

if __name__ == "__main__":
    app.run(debug=True)
