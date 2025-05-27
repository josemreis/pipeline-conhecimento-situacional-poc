import requests
import nvdlib
import time
import json
from tqdm import tqdm
import os
import signal

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class CVEProcessor:
    def __init__(self, arquivo_saida="vulnerabilidades.json"):
        self.arquivo_saida = arquivo_saida
        self.dados = self.carregar_existente()
        signal.signal(signal.SIGINT, self.handle_interrupt)

    def handle_interrupt(self, signum, frame):
        print("\nInterrupção detectada. Salvando dados antes de sair...")
        self.salvar_em_arquivo()
        exit(0)

    def carregar_existente(self):
        if os.path.exists(self.arquivo_saida):
            try:
                with open(self.arquivo_saida, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                return []
        return []

    def salvar_em_arquivo(self):
        try:
            with open(self.arquivo_saida, "w", encoding="utf-8") as f:
                json.dump(self.dados, f, ensure_ascii=False, indent=4)
        except Exception as e:
            print(f"Erro ao salvar arquivo: {e}")

    def ja_processado(self, cve_id):
        return any(item.get("CVE") == cve_id for item in self.dados)

    def fetch_cvss_from_data(self, cve_data):
        try:
            metrics = getattr(cve_data, "metrics", None)
            if not metrics:
                return "CVSS não disponível"

            for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                data = getattr(metrics, version, None)
                if data and isinstance(data, list) and len(data) > 0:
                    score = data[0].cvssData.baseScore
                    severity = (
                        data[0].cvssData.baseSeverity
                        if version != "cvssMetricV2"
                        else data[0].baseSeverity
                    )
                    return (
                        f"CVSS {version[-4:].replace('V', 'v')}: {score} ({severity})"
                    )

            return "CVSS não disponível"
        except Exception as e:
            return f"Erro ao obter CVSS: {e}"

    def fetch_cpes_for_cve(self, cve_id):
        try:
            results = nvdlib.searchCPEmatch(cveId=cve_id)
            cpes = set()

            for match in results:
                if hasattr(match, "criteria"):
                    cpes.add(match.criteria)
                if hasattr(match, "matches"):
                    for m in match.matches:
                        if isinstance(m, dict) and "cpeName" in m:
                            cpes.add(m["cpeName"])

            return list(cpes) if cpes else []
        except Exception as e:
            return [f"CPE não disponível ({e})"]

    def extract_cve_details(self, cve_data):
        try:
            cve_id = cve_data.id
            description = next(
                (desc.value for desc in getattr(cve_data, "descriptions", []) if desc),
                "Descrição não disponível",
            )
            published = str(getattr(cve_data, "published", "Data não disponível"))
            cvss = self.fetch_cvss_from_data(cve_data)
            cpes = self.fetch_cpes_for_cve(cve_id)

            raw_cwe = getattr(cve_data, "cwe", [])
            if isinstance(raw_cwe, list) and raw_cwe:
                cwe = [item.value for item in raw_cwe if hasattr(item, "value")]
            else:
                cwe = ["CWE não disponível"]

            return {
                "CVE": cve_id,
                "Descrição": description,
                "Data Publicação": published,
                "CPE": cpes,
                "CWE": cwe,
                "CVSS": cvss,
            }
        except Exception as e:
            return {"CVE": getattr(cve_data, "id", "Desconhecido"), "Erro": str(e)}

    def fetch_and_process_kev(self):
        try:
            response = requests.get(KEV_URL)
            response.raise_for_status()
            kev_data = response.json()
            vulnerabilities = kev_data.get("vulnerabilities", [])

            for vuln in tqdm(vulnerabilities, desc="Processando CVEs"):
                cve_id = vuln.get("cveID")
                if not cve_id or self.ja_processado(cve_id):
                    continue

                try:
                    cve_list = nvdlib.searchCVE(cveId=cve_id)
                    if cve_list:
                        cve_data = cve_list[0]
                        detalhes = self.extract_cve_details(cve_data)
                        self.dados.append(detalhes)
                        self.salvar_em_arquivo()
                    else:
                        self.dados.append(
                            {"CVE": cve_id, "Erro": "CVE não encontrado na NVD"}
                        )
                except Exception as e:
                    self.dados.append({"CVE": cve_id, "Erro": str(e)})

                time.sleep(0.7)
        except Exception as e:
            print(f"Erro ao obter feed KEV: {e}")

    def executar(self):
        self.fetch_and_process_kev()


# if __name__ == "__main__":
#     processor = CVEProcessor()
#     processor.executar()
