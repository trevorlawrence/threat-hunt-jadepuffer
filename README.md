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

LinuxProcess_CL
| where TimeGenerated between (datetime(2026-07-30 19:19:00) .. datetime(2026-07-30 19:21:00))
| where DvcHostname == "ff-lf-01"
| where TargetProcessName == "python3.11"
| project TimeGenerated, ActorUsername, ActingProcessName, ActingProcessId,
          ActingProcessCommandLine, TargetProcessName, TargetProcessId,
          TargetProcessCommandLine, ActingProcessGuid
| sort by TimeGenerated asc

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

Further investigation of the agent telemetry identified the initial exploitation path:

    /api/v1/validate/code

The vulnerability was identified as:

**CVE-2025-3248 — Langflow Remote Code Execution**

The source/staging address associated with the activity was:

    64.20.53.230

The agent's own reasoning provided additional context:

> "Target Langflow instance exposed on 7860. The /api/v1/validate/code endpoint accepts unauthenticated code validation. I will abuse Python default-argument evaluation (CVE-2025-3248) to execute code."

### Assessment

The evidence supports an initial compromise through the exposed Langflow application, followed by Python code execution under the `langflow` service account.

The important distinction was that **Python itself was not the indicator of compromise**. The process lineage and encoded command provided the necessary context to determine that the legitimate Langflow process had been abused to execute attacker-controlled code.

**MITRE ATT&CK:** `T1190 – Exploit Public-Facing Application`  
**MITRE ATT&CK:** `T1059.006 – Python`
