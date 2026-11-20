# Relatório de incidente — 198.51.100.30

- **Gerado em:** 2026-11-20T22:50:03+00:00
- **Severidade máxima:** CRITICAL
- **Origem:** privado/reservado
- **Primeira atividade:** 2026-11-20T15:00:00+00:00
- **Última atividade:** 2026-11-20T15:01:00+00:00

## Resumo da atividade

| Fonte | Evento | Quantidade |
|---|---|---|
| honeypot | ssh_login_failed | 6 |
| nids | port_scan | 1 |

## Linha do tempo dos alertas

| Horário | Severidade | Regra | Técnicas |
|---|---|---|---|
| 2026-11-20T15:00:00+00:00 | LOW | R001 - Falha de login SSH | T1110 |
| 2026-11-20T15:00:05+00:00 | LOW | R001 - Falha de login SSH | T1110 |
| 2026-11-20T15:00:10+00:00 | LOW | R001 - Falha de login SSH | T1110 |
| 2026-11-20T15:00:15+00:00 | LOW | R001 - Falha de login SSH | T1110 |
| 2026-11-20T15:00:20+00:00 | LOW | R001 - Falha de login SSH | T1110 |
| 2026-11-20T15:00:20+00:00 | HIGH | R003 - Força bruta SSH | T1110 |
| 2026-11-20T15:00:25+00:00 | LOW | R001 - Falha de login SSH | T1110 |
| 2026-11-20T15:01:00+00:00 | MEDIUM | R002 - Port scan detectado | T1046 |
| 2026-11-20T15:01:00+00:00 | CRITICAL | R004 - Ataque coordenado (força bruta + port scan) | T1110, T1046 |

## Técnicas MITRE ATT&CK observadas

- **T1046** Network Service Discovery (Discovery)
- **T1110** Brute Force (Credential Access)

## Resposta automática

- 2026-11-20T22:50:03+00:00 — modo dry-run: simulado: iptables -I INPUT -s 198.51.100.30 -j DROP
