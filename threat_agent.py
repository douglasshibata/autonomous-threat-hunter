import os
import sys
from typing import List, Optional, Any, Dict
from langchain_openai import ChatOpenAI
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import BaseMessage, AIMessage, ToolCall
from langchain_core.outputs import ChatResult, ChatGeneration
from langgraph.prebuilt import create_react_agent

# Garante que o diretório atual está no path para importar security_tools corretamente
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from security_tools import (
    buscar_assinaturas_ameaca_qdrant,
    consultar_logs_opensearch,
    solicitar_aprovacao_humana,
    isolar_container_comprometido_docker,
    bloquear_ip_revogar_sessao
)

# ---------------------------------------------------------------------------
# FALLBACK MOCK LLM (Para execução offline / sem chave de API ativa)
# ---------------------------------------------------------------------------
class MockThreatHunterLLM(BaseChatModel):
    """Mock LLM para testes e execuções offline do agente de caça a ameaças."""

    def _generate(
        self,
        messages: List[BaseMessage],
        stop: Optional[List[str]] = None,
        run_manager: Optional[Any] = None,
        **kwargs: Any
    ) -> ChatResult:
        last_message = messages[-1]
        content_lower = last_message.content.lower() if last_message.content else ""

        # Passo 1: Início da simulação. O usuário pede para analisar atividades anômalas no SIEM.
        if "analisar atividades" in content_lower or "detectar ameaças" in content_lower or "exfiltração" in content_lower:
            # Chama consultar_logs_opensearch para o índice de rede
            tool_call = ToolCall(
                name="consultar_logs_opensearch",
                args={"index_name": "network", "query": "198.51.100.42"},
                id="call_os_1"
            )
            message = AIMessage(
                content="Vou iniciar a investigação consultando logs de rede no OpenSearch referentes ao IP suspeito '198.51.100.42'.",
                tool_calls=[tool_call]
            )
            return ChatResult(generations=[ChatGeneration(message=message)])

        # Passo 2: OpenSearch retornou logs. O agente percebe exfiltração SCP massiva.
        elif "massive file transfer" in content_lower or last_message.name == "consultar_logs_opensearch":
            # Agora consulta assinaturas de ameaça no Qdrant
            tool_call = ToolCall(
                name="buscar_assinaturas_ameaca_qdrant",
                args={"query_pattern": "high_data_volume"},
                id="call_qd_1"
            )
            message = AIMessage(
                content="Identifiquei transferências massivas via SCP no OpenSearch. Vou consultar assinaturas correspondentes no Qdrant para confirmar se trata-se de um vetor conhecido.",
                tool_calls=[tool_call]
            )
            return ChatResult(generations=[ChatGeneration(message=message)])

        # Passo 3: Qdrant retornou assinatura APT-29 / Cozy Bear de gravidade CRÍTICA.
        elif "apt-29" in content_lower or "cozy bear" in content_lower or last_message.name == "buscar_assinaturas_ameaca_qdrant":
            # Primeiro: Executa bloqueio de IP de resposta rápida (baixa fricção, alto impacto defensivo)
            tool_call = ToolCall(
                name="bloquear_ip_revogar_sessao",
                args={"ip_atacante": "198.51.100.42", "usuario_afetado": "admin"},
                id="call_block_1"
            )
            message = AIMessage(
                content="Confirmado! Trata-se de uma assinatura de exfiltração de dados vinculada ao APT-29 (Cozy Bear). "
                        "Vou bloquear imediatamente o IP atacante '198.51.100.42' no firewall e revogar sessões do usuário comprometido 'admin'.",
                tool_calls=[tool_call]
            )
            return ChatResult(generations=[ChatGeneration(message=message)])

        # Passo 4: Bloqueio de IP concluído. O agente precisa isolar o container suspeito "prod-api-pod-9x", mas como é crítico, solicita aprovação humana.
        elif "firewall_action" in content_lower or last_message.name == "bloquear_ip_revogar_sessao":
            tool_call = ToolCall(
                name="solicitar_aprovacao_humana",
                args={
                    "acao_critica": "Isolar container 'prod-api-pod-9x' via Docker API",
                    "justificativa": "O container está sendo usado como origem em um ataque de exfiltração ativa do APT-29."
                },
                id="call_approve_1"
            )
            message = AIMessage(
                content="IP bloqueado. Para conter a ameaça na raiz, preciso isolar o contêiner 'prod-api-pod-9x'. "
                        "Por ser uma ação crítica que afeta a infraestrutura de produção, vou acionar o controle Human-in-the-Loop para obter aprovação.",
                tool_calls=[tool_call]
            )
            return ChatResult(generations=[ChatGeneration(message=message)])

        # Passo 5: Aprovado! Agora isola o container passando o Token recebido.
        elif "pending_approval_granted" in content_lower or last_message.name == "solicitar_aprovacao_humana":
            # Extrai o token simulado
            token = "SEC-TOKEN-SIMULATED"
            # Se a mensagem real tiver o token, tente usá-lo
            if last_message.content and "token_aprovacao" in last_message.content:
                try:
                    import json
                    data = json.loads(last_message.content)
                    token = data.get("token_aprovacao", token)
                except Exception:
                    pass

            tool_call = ToolCall(
                name="isolar_container_comprometido_docker",
                args={"container_id": "prod-api-pod-9x", "token_aprovacao": token},
                id="call_isolate_1"
            )
            message = AIMessage(
                content=f"Aprovação concedida com o token '{token}'. Executando isolamento de rede do contêiner 'prod-api-pod-9x' via Docker API.",
                tool_calls=[tool_call]
            )
            return ChatResult(generations=[ChatGeneration(message=message)])

        # Finalização: Tudo mitigado com sucesso.
        else:
            message = AIMessage(
                content="[FIM DA SIMULAÇÃO] Incidente mitigado com sucesso!\n"
                        "- IP atacante 198.51.100.42 bloqueado no firewall de borda.\n"
                        "- Sessões ativas do usuário 'admin' suspensas para segurança.\n"
                        "- Contêiner 'prod-api-pod-9x' totalmente isolado em rede de quarentena.\n"
                        "Todos os playbooks de contenção e auditoria forense foram executados."
            )
            return ChatResult(generations=[ChatGeneration(message=message)])

    @property
    def _llm_type(self) -> str:
        return "mock_threat_hunter"

    def bind_tools(self, tools: List[Any], **kwargs: Any) -> Any:
        # Permite que o create_react_agent faça o bind das ferramentas ao MockLLM
        return self

# ---------------------------------------------------------------------------
# CONFIGURAÇÃO DO AGENTE REACT E TRATAMENTO DE ASSINATURA
# ---------------------------------------------------------------------------

# 1. Escolha do LLM (Fallback seguro para desenvolvimento local)
AI_API_KEY = os.getenv("OPENAI_API_KEY", "sua-chave-aqui")

if AI_API_KEY == "sua-chave-aqui" or AI_API_KEY.startswith("sk-dummy"):
    llm = MockThreatHunterLLM()
else:
    llm = ChatOpenAI(
        model="gpt-4o",
        temperature=0.0
    )

# 2. System Prompt do Arquiteto de Cibersegurança Sênior
SYSTEM_PROMPT = """Você é o Agente Autônomo de Caça e Mitigação de Ameaças (Autonomous Cyber Threat Hunting & Remediation Agent).
Sua missão é atuar como operador de SOC de nível 3 para detectar anomalias, IoCs e ataques em andamento, executando contenções automáticas com máximo rigor e segurança.

Orientações de Segurança e Execução de Playbooks:
1. **Fase de Análise**: Busque logs do OpenSearch (`consultar_logs_opensearch`) de rede ('network'), autenticação ('auth') e kernel/eBPF ('kernel') para traçar a linha do tempo do incidente.
2. **Fase de Correlação**: Compare os comportamentos suspeitos encontrados com a base de Threat Intelligence no Qdrant (`buscar_assinaturas_ameaca_qdrant`).
3. **Fase de Contenção Defensiva (Baixa Fricção)**: Se identificar ameaças confirmadas de alta gravidade, bloqueie imediatamente os IPs de origem e revogue credenciais suspeitas utilizando `bloquear_ip_revogar_sessao`.
4. **Fase de Contenção de Alto Impacto (Human-in-the-Loop)**: Ações que afetem serviços produtivos (como isolar nós de banco de dados ou contêineres vitais) EXIGEM a solicitação de autorização humana via `solicitar_aprovacao_humana`. Nunca execute `isolar_container_comprometido_docker` sem um token válido e justificado.
5. **Relatório Técnico**: Ao finalizar, descreva os ataques mitigados, atores de ameaça (ex: APT-29) e as contenções aplicadas.
"""

tools = [
    buscar_assinaturas_ameaca_qdrant,
    consultar_logs_opensearch,
    solicitar_aprovacao_humana,
    isolar_container_comprometido_docker,
    bloquear_ip_revogar_sessao
]

# 3. Criação do Agente com suporte a dual-signature (compatibilidade estrita com LangGraph)
try:
    threat_agent = create_react_agent(
        model=llm,
        tools=tools,
        prompt=SYSTEM_PROMPT
    )
except TypeError:
    threat_agent = create_react_agent(
        model=llm,
        tools=tools,
        state_modifier=SYSTEM_PROMPT
    )
