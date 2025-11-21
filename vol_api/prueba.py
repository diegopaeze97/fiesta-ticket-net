import requests, os, logging
logging.basicConfig(level=logging.INFO)
TARGET = "https://200.135.106.250/rs/verifyP2C"   # reemplaza por la URL que imprime tu app
print("HTTP_PROXY:", os.getenv("HTTP_PROXY"), "HTTPS_PROXY:", os.getenv("HTTPS_PROXY"))
try:
    s = requests.Session()
    # Evita que requests use variables de entorno de proxy si sospechas interferencia:
    # s.trust_env = False
    r = s.post(TARGET, json={"ping":"test"}, timeout=(5,30))
    print("status", r.status_code)
    print("body:", r.text[:1000])
except requests.exceptions.ConnectTimeout:
    print("ConnectTimeout")
except requests.exceptions.ReadTimeout:
    print("ReadTimeout")
except Exception as e:
    print("Otro error:", type(e), e)