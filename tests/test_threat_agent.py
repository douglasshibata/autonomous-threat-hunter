import os
import sys
import json
import pytest
from unittest.mock import MagicMock, patch

# Adiciona o diretório principal ao path do Python para encontrar os módulos corretos
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from security_tools import (
    buscar_assinaturas_ameaca_qdrant,
    consultar_logs_opensearch,
    solicitar_aprovacao_humana,
    isolar_container_comprometido_docker,
    bloquear_ip_revogar_sessao,
    PENDING_APPROVALS
)
from threat_agent import threat_agent

# ---------------------------------------------------------------------------
# TESTES UNITÁRIOS DE FERRAMENTAS (TOOLS)
# ---------------------------------------------------------------------------

def test_consultar_logs_opensearch_sucesso():
    # Testa consulta ao índice 'network' por termo de IP conhecido
    resultado = consultar_logs_opensearch.invoke({"index_name": "network", "query": "198.51.100.42"})
    dados = json.loads(resultado)

    assert dados["status"] == "success"
    assert dados["index"] == "network"
    assert dados["total_found"] > 0
    assert "198.51.100.42" in dados["results"][0]["ip_destino"]

def test_consultar_logs_opensearch_indice_invalido():
    resultado = consultar_logs_opensearch.invoke({"index_name": "indice_fake", "query": "198.51.100.42"})
    dados = json.loads(resultado)

    assert dados["status"] == "error"
    assert "Índice 'indice_fake' não encontrado" in dados["message"]

def test_buscar_assinaturas_ameaca_qdrant_sucesso():
    resultado = buscar_assinaturas_ameaca_qdrant.invoke({"query_pattern": "high_data_volume"})
    dados = json.loads(resultado)

    assert dados["status"] == "success"
    assert len(dados["results"]) > 0
    assert dados["results"][0]["threat_actor"] == "APT-29 / Cozy Bear"
    assert dados["results"][0]["severity"] == "CRITICAL"

def test_buscar_assinaturas_ameaca_qdrant_comportamento_generico():
    resultado = buscar_assinaturas_ameaca_qdrant.invoke({"query_pattern": "unusual_pattern_xyz"})
    dados = json.loads(resultado)

    assert dados["status"] == "success"
    assert dados["results"][0]["id"] == "sig-generic"
    assert dados["results"][0]["severity"] == "MEDIUM"

def test_bloquear_ip_revogar_sessao():
    resultado = bloquear_ip_revogar_sessao.invoke({"ip_atacante": "198.51.100.42", "usuario_afetado": "admin"})
    dados = json.loads(resultado)

    assert dados["status"] == "success"
    assert dados["firewall_action"]["blocked_ip"] == "198.51.100.42"
    assert dados["iam_action"]["revoked_user"] == "admin"

def test_fluxo_aprovacao_humana_e_isolamento_docker():
    # 1. Solicita aprovação humana
    resultado_aprov = solicitar_aprovacao_humana.invoke({
        "acao_critica": "Isolar container 'prod-api-pod-9x' via Docker API",
        "justificativa": "Teste unitário de segurança"
    })
    dados_aprov = json.loads(resultado_aprov)

    assert dados_aprov["status"] == "pending_approval_granted"
    token = dados_aprov["token_aprovacao"]
    assert token.startswith("SEC-TOKEN-")

    # Verifica que o token foi guardado no estado pendente
    assert token in PENDING_APPROVALS

    # 2. Isola contêiner usando o token válido
    resultado_isol = isolar_container_comprometido_docker.invoke({
        "container_id": "prod-api-pod-9x",
        "token_aprovacao": token
    })
    dados_isol = json.loads(resultado_isol)

    assert dados_isol["status"] == "success"
    assert dados_isol["action"] == "container_isolated"
    assert dados_isol["container_id"] == "prod-api-pod-9x"
    assert dados_isol["approved_by_token"] == token

    # Garante que o token foi devidamente consumido (evitando replay)
    assert token not in PENDING_APPROVALS

def test_isolamento_docker_token_invalido():
    resultado = isolar_container_comprometido_docker.invoke({
        "container_id": "prod-api-pod-9x",
        "token_aprovacao": "SEC-TOKEN-INVALIDO"
    })
    dados = json.loads(resultado)

    assert dados["status"] == "denied"
    assert "Token de aprovação inválido" in dados["message"]

# ---------------------------------------------------------------------------
# TESTES DE FLUXO DO AGENTE (LANGGRAPH INTEGRATION)
# ---------------------------------------------------------------------------

def test_agente_execucao_fluxo_completo():
    prompt = "Analisar atividades anômalas e executar mitigação para o IP '198.51.100.42'."
    inputs = {"messages": [("user", prompt)]}

    events = list(threat_agent.stream(inputs, stream_mode="values"))
    assert len(events) > 0

    # Pega a última mensagem do fluxo do agente e garante que terminou com o relatório de sucesso
    ultima_msg = events[-1]["messages"][-1]
    assert ultima_msg.type == "ai"
    assert "Incidente mitigado com sucesso" in ultima_msg.content
    assert "bloqueado no firewall" in ultima_msg.content
