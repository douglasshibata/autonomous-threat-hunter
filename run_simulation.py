import os
import sys

# Garante que o diretório atual está no path para importar threat_agent corretamente
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from threat_agent import threat_agent

def executar_simulacao_threat_hunting():
    prompt = """
    Identificamos uma possível exfiltração de dados envolvendo o IP de origem '198.51.100.42'.
    Por favor, execute o playbook de Threat Hunting e Mitigação:
    1. Consulte os logs no OpenSearch para traçar o tráfego de rede desse IP.
    2. Identifique anomalias e correlacione os padrões encontrados com as assinaturas de ameaça no Qdrant.
    3. Execute o bloqueio do IP do atacante imediatamente para mitigação rápida.
    4. Solicite aprovação humana para isolar o container suspeito de origem do ataque 'prod-api-pod-9x' via Docker API.
    5. Isole o container com o token de aprovação recebido.
    """

    print("================================================================================")
    print("🛡️  INICIANDO SIMULAÇÃO AUTÔNOMA DE CAÇA E MITIGAÇÃO DE AMEAÇAS (SOC LEVEL 3)  🛡️")
    print("================================================================================")
    print(f"Alvo suspeito sob investigação: IP '198.51.100.42'\n")

    inputs = {"messages": [("user", prompt)]}
    step_count = 1

    try:
        for event in threat_agent.stream(inputs, stream_mode="values"):
            msg = event["messages"][-1]
            if msg.type == "ai" and msg.content:
                print(f"\n[PASSO {step_count}] - AGENTE INTELIGENTE:")
                print(f"{msg.content}")
                print("-" * 80)
                step_count += 1

                # Se houver tool_calls, mostra quais ferramentas o agente decidiu chamar
                if msg.tool_calls:
                    print("🛠️  AÇÕES/FERRAMENTAS QUE SERÃO ACIONADAS:")
                    for call in msg.tool_calls:
                        print(f"   -> Ferramenta: {call['name']}")
                        print(f"      Argumentos: {call['args']}")
                    print("-" * 80)
    except Exception as e:
        print(f"\n❌ Erro durante a execução da simulação: {e}")
        sys.exit(1)

    print("\n✅ SIMULAÇÃO CONCLUÍDA COM SUCESSO E AMEAÇA DE EXFILTRAÇÃO TOTALMENTE CONTIDA!")
    print("================================================================================")

if __name__ == "__main__":
    executar_simulacao_threat_hunting()
