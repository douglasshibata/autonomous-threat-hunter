# Autonomous Cyber Threat Hunting & Remediation Agent

## 1. Cabeçalho
Este módulo contém o **Autonomous Cyber Threat Hunting & Remediation Agent**, um ecossistema autônomo de orquestração SOAR (Security Orchestration, Automation, and Response) e caça a ameaças cibernéticas. Ele analisa logs de telemetria em tempo real a partir de bases SIEM simuladas e atua diretamente na contenção de incidentes de segurança crítica, integrando controle humano estrito (Human-in-the-Loop) para operações de alto impacto na infraestrutura de produção.

---

## 2. Arquitetura
O agente foi construído sob uma arquitetura resiliente baseada no **Agent Starter Kit (LangGraph/LangChain)** utilizando o padrão de agente ReAct.

### Fluxo de Execução Técnica (Diagrama ASCII):

```
       [ Telemetria de Redes / Autenticação / Kernel eBPF ]
                               │
                               ▼
                [ SIEM Database (OpenSearch) ]
                               │
                               ▼ (Pesquisa de Logs de Eventos)
     ┌──────────────────────────────────────────────────┐
     │  Threat Hunting Agent (Orquestrador LangGraph)   │◄────► [ Threat Intel (Qdrant) ]
     └─────────────────────────┬────────────────────────┘     (Análise de Assinatura/Atores)
                               │
         ┌─────────────────────┴─────────────────────┐
         ▼ (Baixo Impacto / Resposta Rápida)        ▼ (Alto Impacto / Destrutivo)
  [ Contenção Autônoma Direta ]                [ Human-in-the-Loop Gate ]
   - Bloqueio de IP no Firewall Rules           - Solicitação de permissão manual
   - Revogação de Tokens de Usuário IAM         - Geração de Token de Segurança (OTP)
                                                             │
                                                             ▼ (Aprovação de Operador SOC)
                                               [ Docker Container Isolation API ]
                                                - Isola container afetado na quarentena
```

---

## 3. Instalação
Siga as instruções abaixo para preparar o ambiente e instalar as dependências necessárias para a execução offline e desenvolvimento:

```bash
# Navegue até o diretório do agente
cd autonomous-threat-hunter/

# Recomenda-se criar um ambiente virtual (venv)
python3 -m venv .venv
source .venv/bin/activate

# Instale todas as dependências requeridas pelo ecossistema
pip install -r requirements.txt
```

---

## 4. Configuração
Para configurar as chaves de API necessárias para integração com o modelo da OpenAI ou utilizar o mock offline nativo:

Edite ou crie o arquivo `.env` no diretório raiz do projeto:
```env
# Chave da API OpenAI (Se deixada como padrão ou vazia, o agente acionará o MockThreatHunterLLM automaticamente)
OPENAI_API_KEY=sua-chave-aqui
```

---

## 5. Execução & Uso
Para executar a simulação completa de resposta a incidentes de exfiltração de dados (APT-29 / Cozy Bear):

```bash
# Certifique-se de estar com as dependências instaladas
python3 autonomous-threat-hunter/run_simulation.py
```

Durante a execução, o agente passará por todas as etapas de resposta automática ao incidente:
1. Pesquisa nos logs do OpenSearch pelo IP suspeito.
2. Identificação de volume excessivo de transferências SCP.
3. Cruzamento no Qdrant confirmando assinatura APT-29.
4. Aplicação do bloqueio de IP de resposta rápida.
5. Solicitação de aprovação humana para isolar o container produtivo.
6. Recebimento do token e isolamento de rede do container comprometido via Docker API.

---

## 6. Testes
Os testes automatizados cobrem de forma exaustiva as ferramentas individuais (Tools), a lógica de fluxo de trabalho do LangGraph e o fallback do LLM.

Para executar o conjunto completo de testes via pytest:
```bash
python3 -m pytest autonomous-threat-hunter/tests/
```

---

## 7. Segurança
Para manter a conformidade com as melhores práticas de cibersegurança do SOC e DevSecOps:
1. **Human-in-the-Loop Obrigatório**: Qualquer ação potencialmente destrutiva ou de alto impacto na infraestrutura de produção (como `isolar_container_comprometido_docker`) requer de forma obrigatória um Token de Segurança gerado pela ferramenta `solicitar_aprovacao_humana`.
2. **Prevenção de Replay Attacks**: Os Tokens de Segurança são válidos para uma única execução de contenção e são limpos da memória após o uso de quarentena.
3. **Mínimo Privilégio**: As chaves de acesso ao OpenSearch, Docker daemon e Qdrant devem ser segregadas com permissões de leitura/escrita restritas exclusivamente ao escopo de atuação do agente.

---

## 8. Troubleshooting
- **Problema: Erro `ModuleNotFoundError: No module named 'langchain_core'`**
  - *Solução*: Certifique-se de que instalou o arquivo `requirements.txt` utilizando o pip de forma correta e ativou o ambiente virtual.
- **Problema: O agente não responde ou falha sem OpenAI API Key**
  - *Solução*: O agente possui um mecanismo de fallback automático que ativa o `MockThreatHunterLLM` se a variável `OPENAI_API_KEY` for igual ao valor padrão ou iniciar com `sk-dummy`. Verifique suas variáveis de ambiente.
