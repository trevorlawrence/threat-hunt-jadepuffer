# Threat Hunt: JadePuffer

## Alert Brief

An analytics rule triggered on **`ff-lf-01` at 19:21 UTC** after the `langflow` service account spawned a previously unseen process. The initial objective was to determine how that execution was introduced, trace the resulting activity across the environment, and establish whether the attacker ultimately achieved its objective.

**Flowforge** is an AI-workflow company operating a Linux-based environment consisting of four hosts. During the incident, suspicious activity propagated across the estate in less than twenty minutes and ultimately resulted in a ransom note being placed in a production database. The investigation focused on reconstructing the attack chain, identifying the systems and data affected, and determining what was responsible for driving the activity.

## Threat Intelligence Context

This hunt recreates an attack disclosed by the **Sysdig Threat Research Team in July 2026**, described as the first documented end-to-end ransomware operation driven by an LLM-based agent. In the simulated intrusion, the agent exploited a known remote code execution vulnerability in **Langflow**, then progressed through reconnaissance, credential collection, lateral movement, privilege escalation, and ultimately ransomware impact.

Unlike a conventional malware campaign driven by a fixed script, the adversary in this scenario was designed to make decisions dynamically. The telemetry captures the agent responding to unexpected results, modifying its approach after failed attempts, generating payloads during execution, and recording its own reasoning throughout the operation.

Several of these behaviors were intentionally preserved in the available telemetry, including a failed Nacos account-creation attempt, Docker socket reconnaissance, runtime-generated Python payloads, and the agent's internal reasoning. These artifacts provided an opportunity to investigate not only **what actions occurred**, but also **how the attack was being directed and executed**.

> **Investigation objective:** Reconstruct the attack chain from initial access through impact, distinguish malicious activity from legitimate Linux operations, and determine the degree of human involvement in the operation.

# 1. Initial Access

The investigation began with the suspicious process that triggered the analytics rule. Because `python3.11` was already part of the legitimate Langflow environment, the presence of Python alone was not enough to establish malicious execution.

My first question was:

> **What created this process, and what was it being used for?**

I examined the process lineage and command line around the alert to determine what created the suspicious Python process.

### Investigation Query

```kql
LinuxProcess_CL
| where TimeGenerated between (datetime(2026-07-30 19:19:00) .. datetime(2026-07-30 19:21:00))
| where DvcHostname == "ff-lf-01"
| where TargetProcessName == "python3.11"
| project TimeGenerated, ActorUsername, ActingProcessName, ActingProcessId,
          ActingProcessCommandLine, TargetProcessName, TargetProcessId,
          TargetProcessCommandLine, ActingProcessGuid
| sort by TimeGenerated asc
```

<img src="query-results/1.png" alt="Query Results 1" width="1200">

The first result showed the normal Langflow startup process:

    ActorUsername: root
    ActingProcessName: systemd
    ActingProcessId: 1
    ActingProcessCommandLine: /sbin/init
    TargetProcessName: python3.11
    TargetProcessId: 3201
    TargetProcessCommandLine: /opt/langflow/.venv/bin/langflow run --host 0.0.0.0 --port 7860

This established that `python3.11` was a legitimate component of the Langflow application.

Shortly afterward, however, a second Python process appeared under the `langflow` service account:

    ActorUsername: langflow
    ActingProcessName: python3.11
    ActingProcessId: 3201
    ActingProcessCommandLine: /opt/langflow/.venv/bin/langflow run --host 0.0.0.0 --port 7860
    TargetProcessName: python3.11
    TargetProcessCommandLine: python3 -c <base64 payload>

This was significant because the Langflow process was spawning another Python interpreter with an encoded command.

At this point, the investigation shifted from **"Is Python legitimate?"** to **"Why is Langflow spawning another Python interpreter?"**

I had established **suspicious execution**, but not yet the mechanism that caused it. Since the environment included telemetry from the LLM agent itself, I next examined agent activity occurring around the time of the process creation.

```kql
LLMAgentLogs_CL
| where TimeGenerated between (datetime(2026-07-30 19:19:00) .. datetime(2026-07-30 19:21:00))
| project TimeGenerated, session_id, actor, RunId, user_input, model_response,
          tool_name, tool_args, tool_result
| sort by TimeGenerated asc
```

<img src="query-results/2.png" alt="Query Results 2" width="1200">

The results provided several important pieces of context at once.

The activity was associated with the `jadepuffer-agent` actor, session `jp-7f3c9a21`, and `RunId` `jp-46-20260730`.

The telemetry also exposed the `user_input` associated with the session:

> "Gain access to the Flowforge estate, locate and encrypt the most business-critical datastore, and leave payment instructions"

This established the high-level objective given to the agent.

The same results also contained the agent's initial model response:

> "Target Langflow instance exposed on 7860. The /api/v1/validate/code endpoint accepts unauthenticated code validation. I will abuse Python default-argument evaluation (CVE-2025-3248) to execute code."

This provided the missing context for the suspicious Python execution. The agent had identified an exposed Langflow endpoint and selected CVE-2025-3248 as the method for obtaining code execution.

This connected the process-level evidence to the agent's intended action.

The suspicious Python process was therefore not simply an unexplained Python execution. The available telemetry showed that the Langflow instance was being targeted through `/api/v1/validate/code`, with the "JadePuffer" agent specifically identifying **CVE-2025-3248** as the method for obtaining code execution.

The agent telemetry established the exploitation technique, but I also wanted to determine where the attacker-controlled activity originated, so I searched Syslog for for the external source/staging address associated with the GET request.

```kql
Syslog
| where TimeGenerated between (datetime(2026-07-30 19:20:00) .. datetime(2026-07-30 19:40:00))
| where Computer == "ff-lf-01"
| project TimeGenerated, SyslogMessage
| sort by TimeGenerated asc
```

<img src="query-results/3.png" alt="Query Results 3" width="1200">

The syslog evidence identified 64.20.53.230 as the external source of the request to /api/v1/validate/code. This established the origin of the initial access, but did not yet explain how the compromised host was being controlled after execution. The query also showed, when ff-lf-01 established an outbound connection to 45.131.66.106:4444. This connection became the focus of the Command and Control investigation.

It was also noted that the suspicious process event did not contain a SHA256 value. This initially raised the possibility that the payload had been executed filelessly. Rather than treating the missing hash as proof, I tested the broader process telemetry to determine whether SHA256 was actually being populated consistently.

```kql
LinuxProcess_CL
| where TimeGenerated between (datetime(2026-07-30 19:19:00) .. datetime(2026-07-30 19:38:00))
| where DvcHostname == "ff-lf-01"
| where isempty(TargetProcessSHA256)
| summarize Count = count()
```

<img src="query-results/4.png" alt="Query Results 4" width="1200">

The query results showed that SHA256 was missing from all of the process telemetry, including legitimate activity. The fileless conclusion therefore **does not hold**.

The missing SHA256 was a telemetry coverage issue rather than evidence that this particular payload was fileless. Since the collection agent was not populating the field across the process data, the absence of a hash could not be used to distinguish the suspicious Python execution from legitimate processes.

This was an important course correction in the investigation. An initially plausible interpretation of the telemetry was rejected after testing it against the broader dataset.

### Initial Access Assessment

The available evidence supports exploitation of the exposed Langflow application through `/api/v1/validate/code`, using **CVE-2025-3248**, followed by Python code execution under the `langflow` service account.
