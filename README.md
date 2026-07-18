# SSH Brute-Force Detection with Splunk

## What this actually is
This is a lab project where I set up a full SSH brute-force attack chain from scratch — recon with Nmap, brute-forcing with Metasploit — then caught it using Splunk. The whole point wasn't just "run some tools," it was to actually understand what a brute-force attack looks like from the log side, and build real threshold-based detection for it instead of just reading about it.

Everything here happened in an isolated lab (two VMs, host-only network, no internet-facing anything). This is purely for learning — not something run against a real target.

## The Setup
- **Attacker VM**: Kali Linux — running Nmap + Metasploit
- **Target VM**: Ubuntu Server 24.04 — plain OpenSSH install
- **SIEM**: Splunk Enterprise, installed directly on the target VM
- **Network**: VirtualBox host-only adapter so the two VMs can only talk to each other, nothing external

## Steps I actually followed

1. **Built both VMs** — Kali as attacker, Ubuntu Server as target. Set up a host-only network so they could reach each other without touching my real network.

2. **Confirmed SSH was actually logging** — before touching anything else, I verified `sshd` was running and writing to `/var/log/auth.log` by triggering one manual failed login and watching it show up live with `tail -f`. No point building detection on a data source that doesn't even work.

3. **Recon from Kali**:
   ```
   nmap -p22 -sV <target-ip>
   nmap --script ssh-auth-methods --script-args ssh.user=root <target-ip>
   ```
   Confirmed SSH was open, grabbed the OpenSSH version, and confirmed password authentication was actually allowed (no point brute-forcing if it's key-only).

4. **Brute force with Metasploit**:
   ```
   use auxiliary/scanner/ssh/ssh_login
   set RHOSTS <target-ip>
   set USERNAME <username>
   set PASS_FILE ssh_common_passwords.txt
   set STOP_ON_SUCCESS true
   set THREADS 4
   run
   ```
   Set a real password on the target user partway through my wordlist so the attack had to genuinely grind through a bunch of failures before hitting success — that's what gives you the realistic "failed, failed, failed... success" pattern in the logs instead of one clean hit.

5. **Installed Splunk on the target VM**, ingested `auth.log` as a monitored source, and wrote SPL queries to detect the attack pattern (below).

## Notes on getting blocked —

Trying to actually run the brute force, make sure you take those into notice

- **MaxAuthTries** — limits how many attempts are allowed per single connection before SSH drops it. I bumped this up in `sshd_config`, but it turned out this wasn't even the real blocker in my case.
- **PerSourcePenalties** — this is the actual thing that got me. It's a newer OpenSSH feature (default on 9.8+, which ships with Ubuntu 24.04) that tracks failed attempts *per source IP* and starts penalizing/dropping connections from that IP once it decides there's been too many failures too fast. Way more aggressive than MaxAuthTries and not something I'd used before.

**The fix**: instead of straight up disabling it, I used `PerSourcePenaltyExemptList <kali-ip>` to whitelist my attacker VM specifically. Felt like the more "correct" way to do it — same as how you'd whitelist your own red team infra on a real engagement instead of nuking a security control just to make your test work.

## Detection Logic (SPL)
Full queries live in [`spl-queries/`](spl-queries/) — here's the two that matter most.

**Failed logins by source IP — basic threshold alert** ([`failed-logins-by-ip.spl`](spl-queries/failed-logins-by-ip.spl))
```spl
index=ssh_lab "Failed password"
| rex field=_raw "Failed password for (invalid user )?(?<user>\S+) from (?<src_ip>\S+)"
| bucket _time span=1m
| stats count by src_ip, _time
| where count > 5
```
`rex` pulls `user` and `src_ip` straight out of the raw log line using named regex groups, so you get them as real, filterable fields instead of just text. Then it buckets everything into 1-minute windows and flags any source IP with more than 5 failures in that window.

**Failed-to-success detection — the real "it's compromised" signal** ([`failed-to-success-detection.spl`](spl-queries/failed-to-success-detection.spl))
```spl
index=ssh_lab ("Failed password" OR "Accepted password")
| rex field=_raw "(Failed|Accepted) password for (invalid user )?(?<user>\S+) from (?<src_ip>\S+)"
| eval result=if(match(_raw, "Accepted"), "success", "failure")
| stats count(eval(result="failure")) as failures, count(eval(result="success")) as successes by src_ip, user
| where failures > 5 AND successes > 0
```
This is the query I actually care about most. Raw failed-login counts are noisy — this one specifically flags a source IP that racked up failures *and then got in*. That's the difference between "someone's probing" and "someone's in."

Also included: [`top-targeted-usernames.spl`](spl-queries/top-targeted-usernames.spl) 
```
index=ssh_lab "Failed password"
| rex field=_raw "Failed password for (invalid user )?(?<user>\S+) from (?<src_ip>\S+)"
| top limit=10 user
```
and [`failed-logins-timeline.spl`](spl-queries/failed-logins-timeline.spl) — used for the dashboard's bar chart and timeline panels.
```
index=ssh_lab "Failed password"
| timechart span=1m count by src_ip

```
## Security Tips & Procedures — how to actually stop this attack
1. **SSH key-based authentication, password auth disabled entirely** — the single biggest win, full stop. If there's no password to guess, brute force is dead on arrival regardless of wordlist size or how long an attacker's willing to grind.

2. **Fail2ban** — watches auth logs and auto-bans an IP after N failures, for a set amount of time. Basically automates what my SPL queries do, except it actually blocks instead of just alerting. Easy to set up, big payoff.

3. **UFW (Uncomplicated Firewall) rate-limiting** — Ubuntu's built-in firewall has a one-liner made for exactly this:
   ```bash
   sudo ufw limit ssh
   ```
   This automatically denies an IP if it tries more than 6 connections within 30 seconds. Way less setup than fail2ban and already on the box by default on Ubuntu — good baseline even before you get to fail2ban.

4. **OpenSSH's own PerSourcePenalties / MaxAuthTries** — these are already doing real work out of the box on modern OpenSSH, as I found out the hard way trying to fight past them. Worth knowing they exist and understanding what they actually do — free protection you get by just not disabling it, but it's not something you configure "for" security, it's already there.

5. **iptables custom rate-limiting rules** — same general idea as UFW, but hand-rolled instead of using UFW's shortcut. More control if you need something specific, but UFW/fail2ban cover the same ground with way less effort for most setups.

6. **Change the default SSH port** — cuts out the huge mountain of dumb automated bots that only ever scan port 22, but does basically nothing against an actual targeted attacker — a real Nmap scan finds the real port in seconds regardless. Fine as a small extra layer, not something to rely on by itself.

Realistically: key-based auth + fail2ban (or even just UFW rate-limiting as a quick baseline) covers almost all real-world SSH brute-force risk. Everything below that is just extra layers on top.

**Beyond this lab (OS-agnostic, worth knowing regardless of distro/platform):**
- `PermitRootLogin no` — disable root login outright, universal on any OpenSSH box
- MFA/2FA on SSH (e.g. PAM + Google Authenticator, or Duo) — password brute-force alone isn't enough to get in
- VPN or bastion host in front of SSH — don't expose it directly to the internet at all
- Cloud security groups (AWS SGs, Azure NSGs, GCP firewall rules) — same idea as UFW/iptables, enforced at the network edge on cloud infra
- Commands above are Ubuntu-specific — same principles apply elsewhere with different tooling (`firewalld` on RHEL/CentOS, etc.)

## What I'd improve next
- Real-time alerting instead of a scheduled check
- Correlate the Nmap recon burst and the brute force as one single incident, not two separate signals
- GeoIP mapping on source IPs for the dashboard
