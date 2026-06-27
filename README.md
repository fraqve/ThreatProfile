# ThreatProfile

A command-line tool I'm building in Python to analyze network traffic from `.pcap` files and flag suspicious behavior. Built entirely with Scapy — no Wireshark, no pre-made analysis libraries. I wanted to actually understand packets at the byte level instead of clicking through a GUI.

---

## Why I'm Building This

This is my follow-up project to Aegis-Scan. Aegis-Scan was about orchestrating existing tools (nmap, gobuster, nikto). ThreatProfile is about going one level deeper — actually reading and interpreting raw network traffic myself, instead of relying on other tools to do it for me.

I'm working toward a SOC analyst role, and network traffic analysis was a gap I knew I needed to close.

---

## How It's Organized

Instead of organizing data by protocol, I organize it by IP address. Every IP that shows up in the capture gets its own profile that builds up evidence as different protocols get analyzed.

I picked this approach because I realized tracking separate lists per protocol gets messy fast — having one "file" per IP made way more sense once I thought about how I'd actually use this data later.

The plan for the full tool is three stages:

1. **Gather data** — parse the pcap and pull out structured info per IP across multiple protocols
2. **Judge the data** — decide which IPs actually look suspicious, and why, using user-configurable thresholds
3. **Enrich it** — check suspicious IPs against VirusTotal and AbuseIPDB for real context

---

## What's Actually Working Right Now

### Data Gathering (`analyzer.py`) — done and tested against real pcap files

- **IP-level tracking** — every IP gets a profile: how many packets it sent, how many unique hosts it talked to. This function also creates the IP's profile the first time it shows up, so every other protocol function can assume the profile already exists.
- **ICMP** — tracks ping sweep behavior (one IP pinging a bunch of different hosts), ICMP redirects (possible man-in-the-middle), and destination unreachable floods (possible scanning).
- **TCP** — tracks unique well-known ports an IP sends SYN packets to. Dynamic ports get filtered out before they ever reach this list, since those get opened and closed for one connection and aren't a real scanning signal — they're just noise. I set the cutoff at 32768 since that's where Linux and Android start handing out ephemeral ports.
- **UDP** — same idea as TCP but without flags, since UDP doesn't have a handshake to look for. Same port filtering applies.
- **DNS tunneling** — flags DNS queries that are abnormally long, since that's a common way to sneak data out through a protocol that's almost never blocked by firewalls.

A few things changed under the hood since the last update, neither of which show up as a new "feature" but matter:

- **Switched from `rdpcap` to `PcapReader`.** `rdpcap` loads the entire pcap into memory before you can touch a single packet, which is fine for small test files and a disaster for anything big. `PcapReader` streams packets one at a time, so memory use stays flat no matter how large the capture is.
- **Every protocol function now defends itself** with `setdefault()` on the keys it needs, instead of assuming the IP-tracking function already ran and built the profile. That way the script doesn't fall over if a packet shows up without an IP layer, or in some order I didn't plan for.

Every protocol function follows the same pattern: take the shared data dictionary in, update it, return it. Made it way easier to build each new one once I had the pattern down — ICMP took me an entire afternoon to figure out, TCP took like 20 minutes.

### Judgment Logic (`assess.py`) — fully built now, and all of it is tested

- **ICMP, TCP, UDP, and DNS assessment** all follow the same logic: normal activity is free up to a tolerance, and anything past that scales up in points the further it goes. A detected ICMP redirect skips all that math and instantly pushes the score past the flagging threshold on its own, since that's an active attack, not just reconnaissance.
- **TCP and UDP turned out to need the exact same scoring logic**, just pointed at different data — so instead of writing it twice I built one shared function and pass in which protocol I'm scoring.
- **Each result returns** the score, a flagged/not-flagged verdict per protocol, and a list of which specific behaviors contributed, so the result can actually explain itself instead of just spitting out a number.
- **I had to rework how "flagged" gets stored too** — it started as one true/false value, but that meant whichever protocol ran last could silently overwrite another protocol's verdict. Now it's a dict keyed by protocol, so ICMP, TCP, UDP, and DNS each get their own flag and none of them step on each other.
- **One small inconsistency I haven't cleaned up yet:** `analyze_pcap_IP` still builds a new IP's profile through the shared `init_data` function, while every other protocol function defaults its own keys directly with `setdefault()`. Not a bug, just a leftover from before I made that pattern consistent — small TODO, not a blocker.

---

## Config System

Risk thresholds and scoring multipliers used to be hardcoded numbers buried inside the assessment functions. I pulled all of that out into a config file instead, so the tool's sensitivity becomes something a user can tune for their own network instead of me guessing one "correct" set of numbers that's supposed to work for everyone.

I ended up going with `config.json` instead of `config.ini` — ini files turn every value into a string, and I'm already passing this config around as a dict everywhere else in the code, so json saved me a conversion step.

Each protocol gets:

- Its own **tolerance** — how much normal activity is allowed before points start piling up
- Its own **risk factor** — points added per unit past that tolerance
- Its own **flagging threshold** — how many points it takes for that protocol alone to flag the IP

---

## What's Not Built Yet

- `main.py` — wiring `analyzer.py` and `assess.py` together into one pipeline
- Turning the raw data and verdicts into an actual readable report
- VirusTotal enrichment for flagged IPs
- AbuseIPDB enrichment for flagged IPs

---

## Known Limitations
*(stuff I can't do yet because it is above my skill level)*

- **No stateful tracking.** Detecting a "real" SYN scan means checking if a SYN ever actually got a SYN-ACK back, which means tracking conversations across multiple packets over time. That's above where my Python is at right now, so instead I detect scans by volume — if one IP hits a ton of unique well-known ports, that's the signal I use.
- **No time-based analysis yet.** Everything in v1 is volume-based. A slow, low-and-slow scan spread out over hours would look like normal traffic to this tool right now. Time-based detection is a v2 target.
- **DNS tunneling detection is basic.** I only catch single DNS queries that are abnormally long on their own. A smarter attacker could split their data across a bunch of smaller queries to stay under my length threshold, and I wouldn't catch that. Catching that pattern means tracking query frequency over time, which is the same stateful problem as above.
- **Fragmented packets aren't handled.** Some fragmented packets lose their protocol headers when Scapy parses them, so I can't always tell what protocol they originally belonged to. I scoped this out instead of trying to reassemble fragment streams.

---

## Tech Stack

- Python 3
- Scapy

---

## Where I'm At

Both `analyzer.py` and `assess.py` are fully done and tested now — every protocol's data gathering and scoring logic works, and I've verified the outputs match what I'd expect by hand.

Next up is the enrichment script with absueipdb and virustotal.
