# SSH Brute-Force Detection with Splunk

An isolated lab following SSH password guessing from reconnaissance to log analysis. I used Kali to generate the activity and Splunk to investigate the authentication events on Ubuntu.

The useful part was seeing the difference between a noisy failure count and a source that also had a successful login. The queries are included so the detection logic can be reviewed.

## Lab setup

| Role | Tools |
| --- | --- |
| Attacker VM | Kali Linux, Nmap, Metasploit |
| Target VM | Ubuntu Server 24.04, OpenSSH |
| Detection | Splunk Enterprise, index `ssh_lab` |
| Network | VirtualBox host-only lab |

## Workflow

First, I confirmed that SSH events were reaching `/var/log/auth.log` by making a manual failed login and watching the file:

```bash
sudo tail -f /var/log/auth.log
```

Then I checked the service from Kali:

```bash
nmap -p22 -sV <target-ip>
nmap --script ssh-auth-methods --script-args ssh.user=root <target-ip>
```

For the controlled password test, I used Metasploit’s SSH login module against my target VM:

```text
use auxiliary/scanner/ssh/ssh_login
set RHOSTS <target-ip>
set USERNAME <lab-user>
set PASS_FILE <lab-wordlist-path>
set STOP_ON_SUCCESS true
set THREADS 4
run
```

The lab account’s password was included in the test wordlist, producing failures followed by an accepted login. I ingested `auth.log` into Splunk and searched the resulting events.

## Detection logic

### Failed-login burst

[`failed-logins-by-ip.spl`](spl-queries/failed-logins-by-ip.spl) extracts the source IP, groups events into one-minute buckets, and returns sources with **more than five** failures:

```spl
index=ssh_lab "Failed password"
| rex field=_raw "Failed password for (invalid user )?(?<user>\S+) from (?<src_ip>\S+)"
| bucket _time span=1m
| stats count by src_ip, _time
| where count > 5
```

Fixed buckets are simple to explain, but a burst split across a minute boundary can stay below the threshold in each bucket.

### Failures and successful access

[`failed-to-success-detection.spl`](spl-queries/failed-to-success-detection.spl) groups failures and accepted logins by source IP and username. It returns groups with more than five failures and at least one success in the selected search range.

**Important limitation:** the current query counts both event types; it does not enforce their order or a maximum gap. Its filename describes the investigation goal. The query alone does not prove that the successful login came after the failures, or that an account was compromised. Verify the timeline and account context.

The other [SPL queries](spl-queries/) show targeted usernames and failed-login activity over time. Set the Splunk time picker deliberately before comparing results.

## What got in the way

My lab notes recorded SSH-side throttling during repeated attempts. `MaxAuthTries` limits attempts within a connection; newer OpenSSH builds can also apply source penalties. I used an exemption for the lab attacker rather than disabling the control globally.

Availability depends on the installed OpenSSH build. [PerSourcePenalties was introduced in OpenSSH 9.8](https://www.openssh.org/txt/release-9.8); the Ubuntu version label alone does not establish which SSH features are available. Check the installed server and effective configuration before reproducing this step.

## What I would improve

- Enforce event order and a bounded failure-to-success interval.
- Tune thresholds against normal login activity and shared source IPs.
- Correlate reconnaissance and authentication events.
- Add reproducible event samples alongside the queries.

This repository contains the lab writeup and SPL queries. The original VM experiment is documented here; it was not rerun during the documentation refresh.
