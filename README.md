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

The results provided several important pivots at once.

The activity was associated with the `jadepuffer-agent` actor and session `jp-7f3c9a21`. The telemetry also exposed the agent's task:

> "Gain access to the Flowforge estate, locate and encrypt the most business-critical datastore, and leave payment instructions"

Most importantly, the same telemetry showed the agent invoking:

`POST /api/v1/validate/code`

The `model_response` field provided additional context for the request:

> "Target Langflow instance exposed on 7860. The /api/v1/validate/code endpoint accepts unauthenticated code validation. I will abuse Python default-argument evaluation (CVE-2025-3248) to execute code."

This connected the suspicious Python process to a specific attack path. The Langflow service was not simply spawning an unexplained Python interpreter; the LLM agent had been tasked with compromising the Flowforge estate and was actively targeting the exposed Langflow endpoint using `CVE-2025-3248` to obtain code execution.

The telemetry also provided the `RunId` associated with the activity:

`jp-46-20260730`

This gave me a reliable pivot for correlating the agent's activity with the host and Syslog telemetry. From here, I moved to Syslog to independently verify the endpoint and identify the external source associated with the request.

```kql
Syslog
| where TimeGenerated between (datetime(2026-07-30 19:20:00) .. datetime(2026-07-30 19:40:00))
| where Computer == "ff-lf-01"
| project TimeGenerated, SyslogMessage
| sort by TimeGenerated asc
```

<img src="query-results/3.png" alt="Query Results 3" width="1200">

The syslog evidence identified 64.20.53.230 as the external source of the request to /api/v1/validate/code. This established the origin of the initial access, but did not yet explain how the compromised host was being controlled after execution.

It was also noted that the suspicious process event did not contain a SHA256 value. This initially raised the possibility that the payload had been executed filelessly. Rather than treating the missing hash as proof, I tested the broader process telemetry to determine whether SHA256 was actually being populated consistently.

```kql
LinuxProcess_CL
| where TimeGenerated between (datetime(2026-07-30 00:00:00) .. datetime(2026-07-31 00:00:00))
| summarize
    TotalEvents = count(),
    WithSHA256 = countif(isnotempty(TargetProcessSHA256)),
    WithoutSHA256 = countif(isempty(TargetProcessSHA256))
```

<img src="query-results/4.png" alt="Query Results 4" width="900">

The query results showed that SHA256 was missing from all of the process telemetry, including legitimate activity. The fileless conclusion therefore **does not hold**.

The missing SHA256 was a telemetry coverage issue rather than evidence that this particular payload was fileless. Since the collection agent was not populating the field across the process data, the absence of a hash could not be used to distinguish the suspicious Python execution from legitimate processes.

This was an important course correction in the investigation. An initially plausible interpretation of the telemetry was rejected after testing it against the broader dataset.

### Initial Access Assessment

The available evidence supports exploitation of the exposed Langflow application through `/api/v1/validate/code`, using **CVE-2025-3248**, followed by Python code execution under the `langflow` service account.

With initial access established, the investigation then moved to the network activity generated by the compromised host to determine whether the attacker maintained external communications.

# 2. Command and Control

The connection to `45.131.66.106:4444` was first identified during the initial-access investigation. At that stage, it was an external connection associated with the compromised host and stood out from the host's normal HTTPS traffic.

The next question was whether this connection was a one-time event or whether the attacker had established a mechanism to re-establish it.

The investigation guidance indicated that the connection was being restarted on a schedule. I treated this as a persistence hypothesis and looked for scheduled activity associated with the `langflow` account.

Because Linux scheduled tasks are commonly managed through `cron`, I pivoted to the Linux system telemetry and searched for `cron` events associated with the attack run.

```kql
LinuxAudit_CL
| where TimeGenerated between (datetime(2026-07-30 19:00:00) .. datetime(2026-07-30 20:00:00))
| project TimeGenerated, AuditKey, Subj, Success, TargetUsername, Uid, Tty, Type
| order by TimeGenerated asc
```

<img src="query-results/5.png" alt="Cron activity associated with the Langflow account" width="900">

The audit telemetry showed a `cron-change` event made by `langflow` during the attack window. This indicated that a scheduled task had been modified and provided a pivot into the Linux system telemetry to determine what cron activity had been created.

```kql
LinuxSystem_CL
| where TimeGenerated between (datetime(2026-07-30 18:00:00) .. datetime(2026-07-30 21:00:00))
| where EventOriginalMessage has_any ("curl -s", "python3 -", "cron", "CRON")
| project TimeGenerated, ProcessName, EventOriginalMessage, Facility, Computer
| order by TimeGenerated asc
```

<img src="query-results/6.png" alt="Cron activity associated with the external IP" width="900">

This was significant because it tied the scheduled task directly to the C2 channel identified earlier. The job was running as the `langflow` account and used curl to retrieve content from 45.131.66.106 over port 4444, piping the result directly into python3.

At this point, the cron mechanism and its relationship to the C2 channel were established, but the event itself did not show the execution interval. I therefore needed to determine how frequently this task was being invoked, so I pivoted to shell history to determine how the `cron` configuration had been created or modified.

```kql
LinuxShellHistory_CL
| where TimeGenerated between (datetime(2026-07-30 19:20:00) .. datetime(2026-07-30 19:40:00))
| where Command has_any ("crontab", "/etc/cron", "cron.d", "45.131.66.106")
| project TimeGenerated, ShellUser, Command, Pwd, ReturnCode
| order by TimeGenerated asc
```

<img src="query-results/7.png" alt="Shell history showing cron configuration activity" width="900">

The shell history provided the missing context around the `cron` configuration. The command showed the attacker configuring the C2 command to execute on a **30-minute schedule** under the `langflow` account.

This explained why the C2 connection was being re-established periodically. The `cron` configuration was not an unrelated scheduled task; it was specifically tied to the connection to `45.131.66.106:4444`.

### C2 Assessment

The attacker used a `cron` job owned by the `langflow` account to periodically reconnect to 45.131.66.106:4444. The job retrieved the remote payload and passed it directly to python3, with the `cron` configuration set to execute every 30 minutes.

# 3. Credential Access

With the C2 channel and persistence established, the next stage of the investigation focused on determining what information the attacker was attempting to obtain.

The first lead was database activity on `ff-db-01`, but I had to establish whether it was a routine backup or an action taken by JadePuffer.

## Identifying the Credential Dump

I searched the process telemetry for activity on `ff-db-01` during the investigation window.

```kql
LinuxProcess_CL
| where TimeGenerated between (datetime(2026-07-30 19:20:00) .. datetime(2026-07-30 19:40:00))
| where DvcHostname == "ff-db-01"
| project TimeGenerated, ActorUsername, ActingProcessName,
          ActingProcessCommandLine, TargetProcessName,
          TargetProcessCommandLine, TargetProcessId
| order by TimeGenerated asc
```

<img src="query-results/8.png" alt="PostgreSQL dump activity on ff-db-01" width="900">

The results showed `pg_dump` executing during the timeframe. This initially created ambiguity because `pg_dump` was also used for the system's legitimate nightly backup process, so the process name alone could not distinguish normal backup activity from credential theft.

I searched again using the previously identified `RunId` of `jp-46-20260730` to correlate the agent's activity with process telemetry on `ff-db-01`. Rather than searching for `pg_dump` across the host and potentially returning the legitimate nightly backups, I restricted the search to processes associated with the known malicious agent session.

```kql
LinuxProcess_CL
| where TimeGenerated between (datetime(2026-07-30 19:20:00) .. datetime(2026-07-30 20:00:00))
| where RunId =~ "jp-46-20260730"
| project TimeGenerated, ActorUsername, ActingProcessName,
          ActingProcessCommandLine, TargetProcessName,
          TargetProcessCommandLine, TargetProcessId, RunId
| order by TimeGenerated asc
```

<img src="query-results/9.png" alt="Agent-associated process activity showing the suspicious PostgreSQL dump" width="900">

The results showed a `python3.11` process running under the `langflow` account that spawned `pg_dump` with the following command:

```text
pg_dump -h 127.0.0.1 -U langflow -d langflow -t variable -t api_key
```

This was the process I was looking for. The dump was initiated by the `langflow` account and targeted the `variable` and `api_key` tables, distinguishing it from the legitimate nightly backup activity previously observed under the `backup` account.

The `RunId` correlation was particularly useful here because it allowed the process activity to be tied directly to the agent-driven intrusion rather than treating every `pg_dump` execution on the database server as suspicious.

## Determining What Was Taken

After establishing that the `langflow` account had performed a database dump, the next question was what the attacker obtained from it.

The investigation showed that the attacker targeted the Langflow database's API-key information. I then examined the LLM agent's responses to see if it would tell me what it had taken.

```kql
LLMAgentLogs_CL
| where TimeGenerated between (datetime(2026-07-30 19:20:00) .. datetime(2026-07-30 20:00:00))
| project TimeGenerated, actor, model_response, retrieved_content, session_id
| order by TimeGenerated asc
```

<img src="query-results/10.png" alt="Model response indicating what was stolen" width="900">

The attacker came away with **eight distinct provider families**:

- OpenAI
- Anthropic
- DeepSeek
- Gemini
- Alibaba
- Aliyun
- Tencent
- Huawei

This showed that the activity was not limited to a single credential or service. The dump contained credentials spanning both LLM providers and cloud providers.

### Credential Access Assessment

The evidence showed that the `langflow` service account performed a database dump separate from the legitimate nightly backup process. The attacker targeted API-key data and obtained credentials associated with eight distinct provider families.

The account identity was therefore more useful than the `pg_dump` binary itself for distinguishing malicious credential access from routine database maintenance.


