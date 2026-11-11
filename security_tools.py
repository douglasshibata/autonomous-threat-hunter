import json
import logging
import uuid
from typing import Dict, List, Any, Optional
from pydantic import BaseModel, Field
from langchain_core.tools import tool

# Configuração de Log
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger("SecurityTools")

# ---------------------------------------------------------------------------
# MOCK DATASETS PARA SIMULAÇÃO DO AMBIENTE
# ---------------------------------------------------------------------------

# Mock Qdrant Threat Intel signatures (dense vectors mapped to text payloads)
MOCK_QDRANT_SIGNATURES = [
    {
        "id": "sig-001",
        "name": "Data Exfiltration Signature (Double-Extort)",
        "patterns": ["high_data_volume", "unusual_ssh_destination", "repeated_large_scp"],
        "threat_actor": "APT-29 / Cozy Bear",
        "severity": "CRITICAL",
        "remediation_recommendation": "Isolar container de origem e bloquear IP de destino no firewall imediatamente."
    },
    {
        "id": "sig-002",
        "name": "Brute Force Attack Pattern",
        "patterns": ["multiple_failed_logins", "ssh_invalid_user"],
        "threat_actor": "Automated Botnet Shell-Hunter",
        "severity": "HIGH",
        "remediation_recommendation": "Bloquear IP de origem e forçar revogação de sessões do usuário afetado."
    },
    {
        "id": "sig-003",
        "name": "Lateral Movement Attempt",
        "patterns": ["internal_port_scan", "smb_unauthorized_access"],
        "threat_actor": "Internal Compromised Actor",
        "severity": "HIGH",
        "remediation_recommendation": "Aplicar isolamento de rede e suspender conta de serviço ativa."
    }
]

# Mock OpenSearch Logs
MOCK_OPENSEARCH_LOGS = {
    "auth": [
        {"timestamp": "2026-07-08T10:15:30Z", "ip_origen": "198.51.100.42", "user": "admin", "event": "login_failed", "details": "invalid password"},
        {"timestamp": "2026-07-08T10:15:32Z", "ip_origen": "198.51.100.42", "user": "admin", "event": "login_failed", "details": "invalid password"},
        {"timestamp": "2026-07-08T10:15:35Z", "ip_origen": "198.51.100.42", "user": "admin", "event": "login_failed", "details": "invalid password"},
        {"timestamp": "2026-07-08T10:15:40Z", "ip_origen": "198.51.100.42", "user": "admin", "event": "login_success", "details": "session established"},
    ],
    "network": [
        {"timestamp": "2026-07-08T10:20:00Z", "ip_origen": "172.17.0.4", "ip_destino": "198.51.100.42", "bytes_sent": 85000000, "protocol": "SCP", "details": "massive file transfer out of bounds"},
        {"timestamp": "2026-07-08T10:20:15Z", "ip_origen": "172.17.0.4", "ip_destino": "198.51.100.42", "bytes_sent": 125000000, "protocol": "SCP", "details": "massive file transfer continue"},
    ],
    "kernel": [
        {"timestamp": "2026-07-08T10:20:05Z", "container_id": "prod-api-pod-9x", "event": "ebpf_unusual_binary_execution", "binary": "/tmp/exfil-helper", "triggered_by": "uid-1001"}
    ]
}

# Controle de Aprovações Humanas Ativas (Tokens Gerados)
PENDING_APPROVALS: Dict[str, Dict[str, Any]] = {}

# ---------------------------------------------------------------------------
# DEFINIÇÃO DAS FERRAMENTAS DO SOAR / THREAT HUNTING
# ---------------------------------------------------------------------------

@tool
def buscar_assinaturas_ameaca_qdrant(query_pattern: str) -> str:
    """
    Busca padrões de ataque, IoCs e assinaturas de comportamento malicioso no Qdrant Vector Database.
    Retorna detalhes sobre o ator de ameaça, gravidade do incidente e recomendações de mitigação.
    """
    logger.info(f"Buscando assinaturas de ameaça no Qdrant para o padrão: '{query_pattern}'")
    try:
        matches = []
        pattern_lower = query_pattern.lower()
        for sig in MOCK_QDRANT_SIGNATURES:
            # Simulação de busca vetorial por proximidade semântica
            if (any(p in pattern_lower for p in sig["patterns"]) or
                pattern_lower in sig["name"].lower() or
                pattern_lower in sig["remediation_recommendation"].lower()):
                matches.append(sig)

        if not matches:
            # Se não houver correspondência exata, retorna a assinatura genérica de gravidade média
            generic = {
                "id": "sig-generic",
                "name": "Generic Anomalous Behavior Signature",
                "patterns": [query_pattern],
                "threat_actor": "Unknown Threat Actor / Suspicious Activity",
                "severity": "MEDIUM",
                "remediation_recommendation": "Monitorar fluxo de conexões e revisar logs de auditoria detalhados."
            }
            return json.dumps({"status": "success", "results": [generic]}, indent=2, ensure_ascii=False)

        return json.dumps({"status": "success", "results": matches}, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.error(f"Erro ao consultar Qdrant: {e}")
        return json.dumps({"status": "error", "message": str(e)}, ensure_ascii=False)


@tool
def consultar_logs_opensearch(index_name: str, query: str, limit: int = 10) -> str:
    """
    Consulta logs de tráfego de rede, autenticação, eventos do Kernel e eBPF no OpenSearch SIEM.
    Parâmetros:
      - index_name: Nome do índice ou categoria ('auth', 'network', 'kernel').
      - query: Termo de busca ou filtro de log (ex: IP, container_id, nome de binário).
    """
    logger.info(f"Consultando logs no OpenSearch. Índice: '{index_name}', Query: '{query}'")
    try:
        if index_name not in MOCK_OPENSEARCH_LOGS:
            available = list(MOCK_OPENSEARCH_LOGS.keys())
            return json.dumps({
                "status": "error",
                "message": f"Índice '{index_name}' não encontrado. Índices disponíveis: {available}"
            }, ensure_ascii=False)

        logs = MOCK_OPENSEARCH_LOGS[index_name]
        results = []
        query_lower = query.lower()

        for log in logs:
            log_str = json.dumps(log).lower()
            if query_lower in log_str:
                results.append(log)

        # Limita o número de resultados retornados
        results = results[:limit]

        return json.dumps({"status": "success", "index": index_name, "total_found": len(results), "results": results}, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.error(f"Erro ao consultar OpenSearch: {e}")
        return json.dumps({"status": "error", "message": str(e)}, ensure_ascii=False)


@tool
def solicitar_aprovacao_humana(acao_critica: str, justificativa: str) -> str:
    """
    Aciona o controle de segurança Human-in-the-Loop para solicitar permissão manual
    antes de executar ações de contenção destrutivas ou de alto impacto (ex: desligar servidores ou isolar bancos de dados).
    Retorna um Token de Aprovação de Segurança temporário para ser usado nas ferramentas críticas.
    """
    logger.warning(f"SOLICITAÇÃO DE APROVAÇÃO HUMANA DETECTADA!")
    logger.warning(f"Ação solicitada: {acao_critica}")
    logger.warning(f"Justificativa técnica: {justificativa}")

    try:
        # Gera um token de segurança exclusivo para esta contenção de alto impacto
        token = f"SEC-TOKEN-{uuid.uuid4().hex[:8].upper()}"
        PENDING_APPROVALS[token] = {
            "acao": acao_critica,
            "justificativa": justificativa,
            "approved": True  # Na simulação automatizada, o "humano" aprova automaticamente.
        }

        response = {
            "status": "pending_approval_granted",
            "message": "Human-in-the-loop interveio e aprovou a operação com sucesso.",
            "token_aprovacao": token,
            "detalhes": {
                "acao": acao_critica,
                "autorizador": "SOC Manager / Jules",
                "politica": "Contenção de Alta Gravidade com Múltiplos Fatores"
            }
        }
        return json.dumps(response, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.error(f"Erro ao processar fluxo Human-in-the-Loop: {e}")
        return json.dumps({"status": "error", "message": str(e)}, ensure_ascii=False)


@tool
def isolar_container_comprometido_docker(container_id: str, token_aprovacao: str) -> str:
    """
    Contenção SOAR: Isola um container comprometido do restante da rede de produção via Docker API.
    Requer obrigatoriamente um Token de Aprovação de Segurança (`token_aprovacao`) válido gerado por `solicitar_aprovacao_humana`.
    """
    logger.info(f"Tentativa de isolamento do container '{container_id}' com Token: '{token_aprovacao}'")

    if not token_aprovacao or token_aprovacao not in PENDING_APPROVALS:
        logger.error("Isolamento negado: Token de aprovação inválido ou ausente!")
        return json.dumps({
            "status": "denied",
            "message": "Ação de isolamento abortada por motivos de segurança. Token de aprovação inválido ou ausente."
        }, ensure_ascii=False)

    approval = PENDING_APPROVALS[token_aprovacao]
    if not approval["approved"]:
        logger.error("Isolamento negado: Ação explicitamente rejeitada pelo operador SOC!")
        return json.dumps({
            "status": "denied",
            "message": "Ação rejeitada pelo operador de segurança SOC."
        }, ensure_ascii=False)

    try:
        # Simulação de chamadas reais à API do Docker para isolar a rede e pausar o container suspeito
        # Ex: docker.containers.get(container_id).network_disconnect('bridge_prod')
        response = {
            "status": "success",
            "action": "container_isolated",
            "container_id": container_id,
            "mitigation_actions": [
                f"Desconectado da rede principal de produção 'bridge_prod'.",
                f"Conectado à rede isolada de quarentena 'quarantine_net' para análise forense.",
                f"Definido limite de CPU do contêiner para 5% para prevenir persistência maliciosa de processos."
            ],
            "approved_by_token": token_aprovacao
        }
        # Consome o token para evitar replay attacks
        del PENDING_APPROVALS[token_aprovacao]
        logger.info(f"Container '{container_id}' isolado com sucesso!")
        return json.dumps(response, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.error(f"Erro ao isolar container: {e}")
        return json.dumps({"status": "error", "message": str(e)}, ensure_ascii=False)


@tool
def bloquear_ip_revogar_sessao(ip_atacante: str, usuario_afetado: Optional[str] = None) -> str:
    """
    Contenção SOAR de Resposta Rápida: Bloqueia o endereço IP do atacante no firewall corporativo (IPTables/WAF)
    e revoca imediatamente as sessões de autenticação ativas do usuário afetado (IAM/Cognito/Keycloak).
    """
    logger.info(f"Bloqueando IP '{ip_atacante}' no firewall e limpando sessões do usuário '{usuario_afetado or 'N/A'}'")
    try:
        response = {
            "status": "success",
            "firewall_action": {
                "blocked_ip": ip_atacante,
                "rule_added": f"DROP INPUT FROM {ip_atacante} PORT ALL",
                "scope": "Global Edge Edge Firewall & WAF Rules"
            },
            "iam_action": {
                "revoked_user": usuario_afetado or "Não aplicável / IP Externo de ataque direto",
                "sessions_terminated": 4 if usuario_afetado else 0,
                "temporary_lockout": "Ativo por 120 minutos para auditoria"
            },
            "incident_severity_logged": "HIGH"
        }
        logger.info(f"Contenção executada com sucesso para o IP {ip_atacante}.")
        return json.dumps(response, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.error(f"Erro ao executar bloqueio de rede/sessão: {e}")
        return json.dumps({"status": "error", "message": str(e)}, ensure_ascii=False)
