import feedparser
import requests

RSS_FEED = "https://cert.europa.eu/publications/threat-intelligence-rss"
HEADERS = {"User-Agent": "Mozilla/5.0"}

def extrair_urls_json():
    feed = feedparser.parse(RSS_FEED)
    urls = []

    for item in feed.entries:
        base_url = item.link.rstrip("/")
        json_url = base_url + "/json"
        urls.append(json_url)

    return urls

def nome_ficheiro(url):
    return url.rstrip("/").split("/")[-2] + ".json"

def descarregar_jsons(urls):
    for url in urls:
        nome = nome_ficheiro(url)
        try:
            r = requests.get(url, headers=HEADERS)
            r.raise_for_status()
            with open(nome, "w", encoding="utf-8") as f:
                f.write(r.text)
            print(f"Guardado: {nome}")
        except Exception as e:
            print(f"Erro em {url}: {e}")

if __name__ == "__main__":
    print("A extrair URLs do RSS...")
    lista_urls = extrair_urls_json()
    print(f"{len(lista_urls)} URLs encontrados.")
    descarregar_jsons(lista_urls)
