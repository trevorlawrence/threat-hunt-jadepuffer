# Threat Hunt: JadePuffer

## Alert Brief

An analytics rule triggered on **`ff-lf-01` at 19:21 UTC** after the `langflow` service account spawned a previously unseen process. The initial objective was to determine how that execution was introduced, trace the resulting activity across the environment, and establish whether the attacker ultimately achieved its objective.

**Flowforge** is an AI-workflow company operating a Linux-based environment consisting of four hosts. During the incident, suspicious activity propagated across the estate in less than twenty minutes and ultimately resulted in a ransom note being placed in a production database. The investigation focused on reconstructing the attack chain, identifying the systems and data affected, and determining what was responsible for driving the activity.

## Threat Intelligence Context

This hunt recreates an attack disclosed by the **Sysdig Threat Research Team in July 2026**, described as the first documented end-to-end ransomware operation driven by an LLM-based agent. In the simulated intrusion, the agent exploited a known remote code execution vulnerability in **Langflow**, then progressed through reconnaissance, credential collection, lateral movement, privilege escalation, and ultimately ransomware impact.

Unlike a conventional malware campaign driven by a fixed script, the adversary in this scenario was designed to make decisions dynamically. The telemetry captures the agent responding to unexpected results, modifying its approach after failed attempts, generating payloads during execution, and recording its own reasoning throughout the operation.

Several of these behaviors were intentionally preserved in the available telemetry, including a failed Nacos account-creation attempt, Docker socket reconnaissance, runtime-generated Python payloads, and the agent's internal reasoning. These artifacts provided an opportunity to investigate not only **what actions occurred**, but also **how the attack was being directed and executed**.

> **Investigation objective:** Reconstruct the attack chain from initial access through impact, distinguish malicious activity from legitimate Linux operations, and determine the degree of human involvement in the operation.

