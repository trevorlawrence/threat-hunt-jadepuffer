<img src="query-results/JadePuffer-Hero-Image.png" alt="Hero Image" width="1200">

## Alert Brief

An analytics rule triggered on **`ff-lf-01` at 19:21 UTC** after the `langflow` service account spawned a previously unseen process. The initial objective was to determine how that execution was introduced, trace the resulting activity across the environment, and establish whether the attacker ultimately achieved its objective.

**Flowforge** is an AI-workflow company operating a Linux-based environment consisting of four hosts. During the incident, suspicious activity propagated across the estate in less than twenty minutes and ultimately resulted in a ransom note being placed in a production database. The investigation focused on reconstructing the attack chain, identifying the systems and data affected, and determining what was responsible for driving the activity.

## Threat Intelligence Context

This hunt recreates an attack disclosed by the **Sysdig Threat Research Team in July 2026**, described as the first documented end-to-end ransomware operation driven by an LLM-based agent. In the simulated intrusion, the agent exploited a known remote code execution vulnerability in **Langflow**, then progressed through reconnaissance, credential collection, lateral movement, privilege escalation, and ultimately ransomware impact.

Unlike a conventional malware campaign driven by a fixed script, the adversary in this scenario was designed to make decisions dynamically. The telemetry captures the agent responding to unexpected results, modifying its approach after failed attempts, generating payloads during execution, and recording its own reasoning throughout the operation.

Several of these behaviors were intentionally preserved in the available telemetry, including a failed Nacos account-creation attempt, Docker socket reconnaissance, runtime-generated Python payloads, and the agent's internal reasoning. These artifacts provided an opportunity to investigate not only **what actions occurred**, but also **how the attack was being directed and executed**.

> **Investigation objective:** Reconstruct the attack chain from initial access through impact, distinguish malicious activity from legitimate Linux operations, and determine the degree of human involvement in the operation.

## Langflow's Environment Topology

| Host | IP Address | Primary Service |
|---|---|---|
| `ff-lf-01` | `10.4.0.10` | **Langflow** (AI workflow framework), entry point |
| `ff-minio-01` | `10.4.0.20` | **MinIO** (S3-compatible object storage) |
| `ff-db-01` | `10.4.0.30` | **MySQL database server** |
| `ff-nacos-01` | `10.4.0.40` | **Nacos** (platform for managing application services and configurations) |

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

The next question was whether this connection was a one-time event or whether the attacker had established a mechanism to re-establish it. I treated this as a persistence hypothesis and looked for scheduled activity associated with the `langflow` account.

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

# 4. Discovery & Lateral Movement

The credential-access activity showed that the agent was able to execute commands on systems beyond the initial Langflow process. I next returned to the process telemetry for `ff-lf-01` to determine what other execution occurred during the same agent run.

Rather than looking only for a specific command, I examined the Python processes associated with the previously identified `RunId`. This would allow me to determine whether the agent spawned additional interpreters and, if so, what activity was associated with them.

```kql
LinuxProcess_CL
| where TimeGenerated between (datetime(2026-07-30 19:20:00) .. datetime(2026-07-30 20:00:00))
| where RunId =~ "jp-46-20260730"
| where DvcHostname =~ "ff-lf-01" and TargetProcessName =~ "python3.11"
| project TimeGenerated, TargetProcessId, ActingProcessCommandLine
```

<img src="query-results/11.png" alt="Second Python interpreter identified on ff-lf-01" width="1200">

The results showed another `python3.11` process associated with the agent run. This process had PID `4491`.

This gave me a new process-level pivot. I could now follow the network activity generated specifically by PID `4491` to determine what the agent was doing with the second interpreter.

## Scoping the Internal Sweep

With PID `4491` identified, I next examined the network connections associated with that specific process. The goal was to determine whether the second interpreter was communicating with other systems inside the Flowforge environment.

```kql
LinuxNetwork_CL
| where TimeGenerated between (datetime(2026-07-30 19:20:00) .. datetime(2026-07-30 20:00:00))
| where RunId =~ "jp-46-20260730"
| where ActingProcessId == 4491
| project TimeGenerated, DstIpAddr, DstPortNumber
| sort by TimeGenerated asc
```

<img src="query-results/12.png" alt="Internal network connections from Python process 4491" width="1200">

The network telemetry showed three internal destinations reached by the process:

- `10.4.0.20:9000`
- `10.4.0.30:3306`
- `10.4.0.40:8848`

The three connections occurred within a **very** short period of time and targeted different services on the internal network.

This changed the focus of the investigation. The second Python interpreter was not simply continuing the original execution on `ff-lf-01`, but actively probing other systems in the environment.

The three destinations represented different internal services:

- `10.4.0.20:9000` — MinIO
- `10.4.0.30:3306` — MySQL
- `10.4.0.40:8848` — Nacos

The MinIO service was the next logical pivot because it provided object storage that could potentially contain configuration files, credentials, or other infrastructure data.

## Identifying If the Attacker Accessed MinIO

The network sweep identified MinIO at `10.4.0.20:9000`. I next examined the agent telemetry for evidence of access to the service.

```kql
LLMAgentLogs_CL
| where TimeGenerated between (datetime(2026-07-30 19:20:00) .. datetime(2026-07-30 20:00:00))
| where RunId =~ "jp-46-20260730"
| where model_response has "minioadmin" or model_response has "MinIO"
| project TimeGenerated, model_response
```

<img src="query-results/13.png" alt="Agent telemetry showing MinIO access using default credentials" width="800">

The agent telemetry showed that MinIO accepted the factory-default credential pair:

```text
minioadmin:minioadmin
```

No exploit was required to access the service. The attacker was able to authenticate using the default account credentials that had apparently never been changed.

## Determining What Was Retrieved

After establishing access to MinIO, I needed to determine what the attacker retrieved from the object store.

I pivoted to the MinIO host's Syslog telemetry and searched for object retrieval activity associated with the same agent run.

```kql
Syslog
| where TimeGenerated between (datetime(2026-07-30 19:20:00) .. datetime(2026-07-30 20:00:00))
| where RunId_CF =~ "jp-46-20260730"
| where Computer =~ "ff-minio-01" and SyslogMessage has "GetObject"
| project TimeGenerated, SyslogMessage
```

<img src="query-results/14.png" alt="MinIO object retrieval activity" width="1200">

The object retrieval activity showed that the attacker accessed:

```text
terraform-state
credentials.json
```

These files were significant because they represented infrastructure and credential material rather than ordinary application data.

The `terraform-state` object could contain information about deployed infrastructure and associated configuration, while `credentials.json` represented another potential source of authentication material.

At this point, the investigation had established a progression from internal service discovery to authenticated access to MinIO and retrieval of potentially sensitive infrastructure data.

## The Unexpected Response and Correction

The MinIO investigation also revealed an important piece of behavioral evidence. JadePuffer did not receive the response it expected from the object-storage request. The agent expected the response to contain JSON data, but instead received XML.

Rather than abandoning the request, the agent recognized the mismatch and adjusted its parsing logic. It then retried the object retrieval using the corrected approach.

This was significant because the failure itself became evidence of how the intrusion was being conducted. The activity was not simply a fixed sequence of commands executing exactly as written. The agent encountered an unexpected result, interpreted the failure, modified its approach, and continued the operation.

The failed request and subsequent correction will be revisited later in the report when examining the autonomous behavior of the intrusion.

# 5. Privilege Escalation

The discovery activity showed that the attacker had moved beyond the initial Langflow host and was interacting with internal services. The next phase focused on whether those interactions resulted in elevated privileges or additional persistence.

The Nacos service identified during the internal sweep became particularly significant. I examined its telemetry for authentication activity and account-management events associated with the same agent run.

## The Rejected Attempt

I first looked for failed authentication or account-management activity on the Nacos host. A failed request would be useful for establishing whether the attacker was attempting to obtain additional privileges and whether the attempt succeeded.

```kql
Syslog
| where TimeGenerated between (datetime(2026-07-30 19:20:00) .. datetime(2026-07-30 19:40:00))
| where RunId_CF =~ "jp-46-20260730"
| where Computer =~ "ff-nacos-01"
| project TimeGenerated, SyslogMessage
| order by TimeGenerated asc
```

<img src="query-results/15.png" alt="Nacos authentication requests" width="900">

The results showed a rejected request at `19:34:36` UTC. Nacos returned HTTP `403`, with the authentication rejected because the password hash was blank.

This showed that the attacker was attempting to use the Nacos authentication mechanism to create or obtain an administrative account, but the first attempt failed because the supplied password hash did not satisfy the server's requirements. There was also a new user account called `svc-maint` created 31 seconds after the failed attempt, so I hypothesized that JadePuffer was trying to gain access another way.

## Proving the Corrective Attempt

To confirm my suspicion, I moved from the Syslog telemetry to the host's audit telemetry and searched for user-creation events associated with JadePuffer's `RunId`.

```kql
LinuxAudit_CL
| where TimeGenerated between (datetime(2026-07-30 19:30:00) .. datetime(2026-07-30 19:40:00))
| where RunId =~ "jp-46-20260730"
| where Computer =~ "ff-nacos-01"
| where AuditType =~ "ADD_USER"
| project TimeGenerated, EventOriginalMessage
| order by TimeGenerated asc
```

<img src="query-results/16.png" alt="Nacos host audit telemetry showing successful account creation" width="900">

The host audit telemetry showed a successful account-creation event at `19:35:07` UTC for the same username seen previously: `svc_maint`.

The event also provided two identifiers that were not present in the Syslog evidence:

- PID: `8801`
- UID: `997`

The PID and UID are particularly useful because they come straight from the host's audit telemetry, providing host-level evidence tying the successful account creation to a specific process and user identity.

At this point, the investigation had established a sequence of failed authentication followed by successful account creation.

## The Container Runtime Probe

The next question was whether the attacker had attempted to interact with the container environment on `ff-lf-01`. I searched the container telemetry associated with the JadePuffer's run to determine whether any activity could be established. 

```kql
LinuxContainer_CL
| where TimeGenerated between (datetime(2026-07-30 19:20:00) .. datetime(2026-07-30 20:00:00))
| where RunId =~ "jp-46-20260730"
| project TimeGenerated, Operation, RunId, ContainerId, ImageName, ImageRef
| order by TimeGenerated asc
```

<img src="query-results/17.png" alt="Container runtime telemetry" width="900">

The telemetry showed a request to the Docker API for the container list:

```text
GET /containers/json
```

However, the available telemetry did not contain the response to that request. The `LinuxContainer_CL` data also did not provide `ContainerId`, `ImageName`, or `ImageRef` values that could be used to establish which containers were returned.

I therefore could not determine which containers, if any, were visible to the attacker from the available evidence.

Rather than inferring the container list from the request itself, I recorded the finding as a telemetry limitation: the request was observed, but the response required to establish the result was not collected.

# 6. Impact

With the attacker having established access to the database, the next question was what effect the activity had on the data itself. I examined the database host telemetry for activity associated with the same agent `RunId`.

```kql
Syslog
| where TimeGenerated between (datetime(2026-07-30 19:20:00) .. datetime(2026-07-30 20:00:00))
| where RunId_CF =~ "jp-46-20260730"
| where Computer =~ "ff-db-01"
| project TimeGenerated, SyslogMessage
| order by TimeGenerated asc
```

<img src="query-results/18.png" alt="Database encryption and destruction activity" width="1200">

The results showed `AES_ENCRYPT` being used against the database, followed by the destruction of two tables:

> config_info
>
> history

The encryption operation affected 1,342 rows, indicating that the database was actively modified as part of the attack, with data encrypted and tables subsequently dropped.

The database activity also showed the creation of a ransom note in the newly-created README_RANSOM table. The note instructed the victim to make payment to the following Bitcoin address:

> 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy

The attacker had encrypted database records, destroyed database tables, and left payment instructions for the victim. The payment address is also significant for the later analysis of the attacker's autonomous behavior and will be examined in the next section.

# 7. Autonomy

The earlier investigation established that the intrusion was associated with the `jadepuffer-agent` and that its `user_input` contained a human-provided objective to gain access to the Flowforge estate, encrypt the most business-critical datastore, and leave payment instructions.

That established **human involvement at the beginning of the operation**. The remaining question was whether the subsequent activity was manually directed or whether the agent independently carried out the operation after receiving its objective.

## Determining the Degree of Autonomy

I examined the agent's subsequent `model_response` records to determine whether the technical decisions were being supplied by a human or generated by the agent itself. The earlier telemetry had already shown that the agent independently described its plan to exploit the Langflow instance using `CVE-2025-3248`. The subsequent investigation provided additional evidence of the same behavior.

```kql
LLMAgentLogs_CL
| where TimeGenerated between (datetime(2026-07-30 19:19:00) .. datetime(2026-07-30 19:40:00))
| where actor == 'jadepuffer-agent'
| project TimeGenerated, actor, user_input, model_response
| sort by TimeGenerated asc
| distinct TimeGenerated, actor, user_input, model_response
```

<img src="query-results/19.png" alt="JadePuffer model responses" width="1200">

The agent generated its own technical decisions as the operation progressed, including:

- identifying and exploiting the Langflow `/api/v1/validate/code` endpoint;
- establishing and maintaining the C2 connection;
- discovering internal services;
- identifying MinIO as an accessible target;
- adapting when the MinIO response did not match the expected format;
- accessing additional credentials and infrastructure data;
- attempting privilege escalation through Nacos;
- and ultimately encrypting and destroying database data.

The XML response encountered during the MinIO operation was particularly significant. The agent initially expected JSON, received XML instead, recognized the mismatch, adjusted its parsing approach, and retried the object request. This was not simply execution of a fixed command sequence. The agent responded to an unexpected result and modified its approach. The evidence therefore supports the conclusion that the operation was **human-tasked but autonomous in execution**.

A human supplied the objective at the beginning of the session and gave the initiating command. After receiving that objective, however, the available telemetry shows the agent independently generated the technical steps used to pursue it and adapted those steps when the environment produced an unexpected result or a roadblock.

The distinction is important: the evidence does not show a human manually directing each action. Instead, it shows a human establishing the objective and an LLM agent carrying out the intrusion through its own decisions.

# 8. Real or Noise?

After establishing the attack chain, I needed to determine whether the activity could reasonably be explained as normal behavior in the environment. The host generated legitimate Python activity, legitimate external network connections, and routine scheduled processes, so individual indicators could not always be treated as malicious in isolation.

I therefore compared the characteristics of the attacker activity against the benign activity observed on the same host.

## Distinguishing the Python Spawns

Several `python3.11` processes were present on `ff-lf-01` during the investigation window. Because the executable itself was not unique to the attack, I examined the parent-child relationships to determine what distinguished the suspicious interpreters from the normal Langflow process.

```kql
LinuxProcess_CL
| where TimeGenerated between (datetime(2026-07-30 19:19:00) .. datetime(2026-07-30 20:00:00))
| where DvcHostname == "ff-lf-01"
| where TargetProcessName == "python3.11"
| project TimeGenerated, ActorUsername, ActingProcessName,
          ActingProcessCommandLine, TargetProcessName,
          TargetProcessCommandLine, TargetProcessId, RunId
| order by TimeGenerated asc
```

<img src="query-results/20.png" alt="Python process lineage on ff-lf-01" width="1200">

The results showed the normal Langflow process starting at 19:19:00 under `systemd`:

    ActingProcessName: systemd
    ActingProcessCommandLine: /sbin/init
    TargetProcessName: python3.11
    TargetProcessCommandLine: /opt/langflow/.venv/bin/langflow run --host 0.0.0.0 --port 7860
    TargetProcessId: 3201

At 19:20:04, the Langflow process spawned another `python3.11` process, PID `4471`, which executed the encoded payload:

    ActingProcessName: python3.11
    ActingProcessCommandLine: /opt/langflow/.venv/bin/langflow run --host 0.0.0.0 --port 7860
    TargetProcessName: python3.11
    TargetProcessCommandLine: python3 -c <base64 payload>
    TargetProcessId: 4471

At 19:27:28, PID `4471` then spawned another `python3.11` process, PID `4491`, which executed the encoded subnet sweep:

    ActingProcessName: python3.11
    ActingProcessCommandLine: python3 -c <base64 payload>
    TargetProcessName: python3.11
    TargetProcessCommandLine: python3 -c <base64 subnet sweep 10.4.0.0/24>
    TargetProcessId: 4491

The distinguishing field was therefore `ActingProcessName`. The normal Langflow startup was launched by `systemd`, while the two suspicious interpreters were part of a chained `python3.11`-to-`python3.11` process relationship.

This demonstrated that the executable name alone was insufficient to identify the attack. The process lineage provided the additional behavioral context needed to distinguish the suspicious Python execution from the normal Langflow process.

## Distinguishing the External Connections

I next applied the same approach to the external network activity. `ff-lf-01` communicated with several legitimate external services during the investigation window, so the destination IP address alone was not enough to classify an external connection as malicious.

I examined the destination ports associated with external connections to determine whether the C2 traffic had a distinguishing characteristic.

```kql
LinuxNetwork_CL
| where TimeGenerated between (datetime(2026-07-30 19:00:00) .. datetime(2026-07-30 20:00:00))
| where DvcHostname == "ff-lf-01"
| where DstIpAddr !startswith "10."
| project TimeGenerated, ActingProcessId, DstIpAddr, DstPortNumber, RunId
| order by TimeGenerated asc
```

<img src="query-results/21.png" alt="External network connections from ff-lf-01" width="900">

The results showed several external connections during the investigation window. These included connections to `104.18.30.77` over port `8443`, connections to `104.16.132.229` over port `8080`, and a connection to `45.131.66.106` over port `4444`.

The connection to `45.131.66.106:4444` was significant because it was made by process ID `4471`.

PID `4471` had already been identified earlier in the investigation as the Python interpreter spawned by the Langflow process during the initial exploitation. The process subsequently established the connection to `45.131.66.106` at approximately `19:22:04` UTC. This process correlation provided the evidence needed to distinguish the connection from the other external traffic. The significance of `4444` was not simply that it was a non-standard port; the connection was made by the same suspicious Python process already associated with the exploitation activity.

The external connection to `45.131.66.106` on destination port `4444` was therefore confirmed as the command-and-control connection associated with the attack.

## Distinguishing the Timing

Finally, I examined the timing of the activity. Individual process and network events could resemble legitimate activity when viewed in isolation, so I needed to determine whether the attacker's actions formed a recognizable temporal pattern.

The activity associated with the intrusion was concentrated into a single period rather than being distributed throughout the working day like the benign Python activity.

The full sequence, from the initial exploitation through the subsequent discovery, credential access, privilege escalation, and impact activity, occurred over approximately 17 minutes.

This concentration provided another distinction between the intrusion and the normal activity on the host. Rather than isolated Python processes and network connections appearing at ordinary intervals, the attack produced a dense sequence of related activity across the environment.

Taken together, the process lineage, network destination port, and temporal concentration provided multiple characteristics that separated the intrusion from otherwise legitimate Python and network activity.

Ultimately, we see a continuous attack compressed into approximately 17 minutes with no pauses.

## 9. MITRE ATT&CK Mapping

The activity mapped across multiple MITRE ATT&CK tactics, progressing from exploitation and execution through persistence, credential access, discovery, privilege escalation, and ultimately impact. The telemetry demonstrated that these techniques were not isolated events; they formed a connected attack sequence across the Flowforge estate.

The following techniques were identified from the evidence collected during the investigation:

| Tactic | Technique | Evidence / Activity | Section |
|---|---|---|---:|
| Initial Access | **T1190 · Exploit Public-Facing Application** | Langflow exposed on port `7860`; attacker identified and exploited CVE-2025-3248 through `/api/v1/validate/code` | 1 |
| Execution | **T1059.006 · Python** | Python interpreters used to execute the attacker-controlled payloads | 1, 4 |
| Command and Control | **T1571 · Non-Standard Port** | PID `4471` established a connection to `45.131.66.106:4444` | 2, 8 |
| Persistence | **T1053.003 · Cron** | `langflow` cron job retrieved and executed the payload on a recurring interval | 2 |
| Credential Access | **T1555 · Credentials from Password Stores** | Attacker accessed credentials stored by the Langflow application and extracted API keys for eight provider families | 3 |
| Credential Access | **T1552 · Unsecured Credentials** | Credentials were stored in an application repository accessible from the compromised Langflow environment | 3 |
| Discovery | **T1046 · Network Service Discovery** | PID `4491` scanned `10.4.0.0/24` and identified MinIO, MySQL, and Nacos services | 4 |
| Credential Access | **T1078.001 · Default Accounts** | MinIO accessed using `minioadmin:minioadmin` | 4 |
| Credential Access | **T1552.001 · Credentials In Files** | `terraform-state` and `credentials.json` retrieved from MinIO object storage | 4 |
| Collection | **T1005 · Data from Local System** | Agent retrieved data from the local environment and adapted after receiving XML instead of the expected JSON | 4 |
| Privilege Escalation | **T1068 · Exploitation for Privilege Escalation** | Nacos authentication-bypass attempt followed by successful account creation | 5 |
| Persistence | **T1136.001 · Create Account: Local Account** | `svc_maint` account created on `ff-nacos-01` | 5 |
| Privilege Escalation | **T1611 · Escape to Host** | Agent queried the Docker socket with `GET /containers/json`, probing the container runtime for a potential escape path; successful escape was not established | 5 |
| Impact | **T1486 · Data Encrypted for Impact** | `AES_ENCRYPT` was used to encrypt 1,342 rows in the database | 6 |
| Impact | **T1485 · Data Destruction** | `config_info` and `history` tables were dropped after the encryption activity | 6 |

### Analysis

The activity mapped across multiple MITRE ATT&CK tactics, progressing from exploitation and execution through persistence, credential access, discovery, privilege escalation, and ultimately impact. The telemetry demonstrated that these techniques were not isolated events; they formed a connected attack sequence across the Flowforge estate.

The strongest mappings were supported by host and network telemetry rather than inference from the public disclosure alone. Process lineage, network connections, audit events, and application logs provided independent evidence for the techniques observed during the investigation.

## 10. Conclusion

The investigation established a complete attack chain beginning with the exploitation of a publicly exposed Langflow instance. The attacker identified a vulnerable `/api/v1/validate/code` endpoint and used [CVE-2025-3248](https://www.cve.org/CVERecord?id=CVE-2025-3248]) to obtain Python code execution. From there, the activity progressed through command and control, persistence, credential access, internal discovery, privilege escalation, and ultimately database encryption and destruction.

The investigation also demonstrated that the activity was not limited to a single compromised host. The attacker moved through the Flowforge estate, discovered internal services, accessed MinIO using default credentials, retrieved infrastructure credentials, targeted the Nacos service, created the `svc_maint` account, and ultimately reached the database containing business-critical information.

A defining characteristic of the incident was the degree of automation demonstrated throughout the attack. The agent received a high-level objective and independently selected exploitation techniques, executed commands, adapted when its expected JSON response was returned as XML, and continued through discovery, credential access, privilege escalation, and impact without evidence of human intervention during the execution chain. The investigation therefore supports the conclusion that this was a human-tasked but autonomously executed attack.

The investigation also demonstrated the value of correlating multiple telemetry sources rather than relying on individual alerts or indicators. Process lineage, network connections, agent telemetry, Syslog, audit events, and database activity each provided pieces of the attack chain. Together, they transformed isolated indicators of compromise into a coherent picture of an automated intrusion and provided sufficient evidence to map the observed behavior to multiple MITRE ATT&CK techniques.

## 11. Security Considerations

The investigation identified several security weaknesses that contributed to the success and progression of the attack.

- **Publicly exposed Langflow:** The Langflow application was accessible on port `7860` and contained a vulnerability that allowed unauthenticated code execution. Public-facing applications should be minimized, appropriately restricted, and kept current with security updates.

- **Default credentials:** The attacker accessed MinIO using `minioadmin:minioadmin`. Default credentials should be removed or changed before systems are placed into service.

- **Sensitive credentials stored in application data:** The attacker was able to retrieve API keys and other provider credentials from the Langflow database. Sensitive credentials should be securely stored, access-controlled, and rotated when exposure is suspected.

- **Exposed container management interface:** The attacker was able to query the Docker socket from the compromised environment. Container management interfaces should not be unnecessarily exposed to compromised applications or containers.

- **Insufficient separation of privileges:** The attack was able to progress from an application compromise to credential access, internal discovery, privilege escalation, and database impact. Strong isolation and least-privilege controls can limit the ability of a compromised application to affect other systems.

- **Detection and telemetry:** The investigation relied on correlating process, network, application, audit, and agent telemetry. Maintaining visibility across these sources is important for detecting automated attacks that can move rapidly between stages.

These considerations demonstrate that preventing a single vulnerability is not sufficient by itself. Defense in depth is necessary to prevent an initial application compromise from becoming a broader compromise of the environment.
