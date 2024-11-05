# Fontes de dados

Este documento compila fontes de dados a utilizar na pipeline. Estrutura das entradas:

* **Nome da fonte**
  * **Formato dos dados (e.g. csv, json, pdf, html)**: ...
  * **Método de extração recomendado (e.g. leitura de ficheiro, web scraping, pdf parsing)**: ...
  * **URL (final ou exemplo)**: ...
  * **Notas**: ...


------------------------------------------------------------------------

## Media

* **GDELT**
  * **Formato dos dados**: CSV, Google BigQuery
  * **Método de extração recomendado**: leitura de ficheiros CSV, SQL
  * **URL**: https://www.gdeltproject.org/#downloading
  * **Notas**: Cliente API? https://pypi.org/project/gdeltdoc/ 

------------------------------------------------------------------------

* **European Media Monitor**
  * **Formato dos dados**: RSS 
  * **Método de extração recomendado**: RSS Parsing
  * **URL**: https://emm.newsbrief.eu/rss/rss?type=category&id=ECnews&language=all&duplicates=false 
  * **Notas**: Os parâmetros URL podem ser manipulados para filtrar eventos e  geografias relevantes


------------------------------------------------------------------------

## Relatórios de CTI

* **CERT-EU Cyber Brief**
  * **Formato dos dados**: JSON
  * **Método de extração recomendado**: JSON Parsing
  * **URL**: https://cert.europa.eu/publications/threat-intelligence/cb24-08/json 
  * **Notas**: 


------------------------------------------------------------------------

## Vulnerabilidades

* **...**
  * **Formato dos dados**: ...
  * **Método de extração recomendado**: ...
  * **URL**: ...
  * **Notas**: ...