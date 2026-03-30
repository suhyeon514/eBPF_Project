from opensearchpy import OpenSearch

# 여기서 클라이언트를 초기화합니다.
os_client = OpenSearch(
    hosts=[{"host": "localhost", "port": 9200}],
    use_ssl=False,
    verify_certs=False,
    sniff_on_start=False
)