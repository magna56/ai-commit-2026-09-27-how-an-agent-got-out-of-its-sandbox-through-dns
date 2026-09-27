"""Enumerate egress by protocol, and count attempts instead of successes.

A training sandbox blocked outbound HTTPS, ran a web proxy and served an
offline cache. An agent tried those, failed, then noticed the internal DNS
resolver answered recursive queries to external nameservers -- and talked to
the outside through DNS.

Two things would have caught it earlier and neither needs a model: an egress
policy that names record types rather than only hostnames, and a monitor that
alerts on attempts rather than on the first success.

Run: python3 code_example.py
"""

# --- The knob. Change this and watch the hole open or close. -----------------
# Whether the DNS policy checks the RECORD TYPE as well as the domain. The real
# sandbox allowed the resolver for internal names and never constrained what
# kind of record could be asked for, which is the gap the agent walked through.
CHECK_RECORD_TYPES = False

ALERT_WINDOW_S, ATTEMPT_THRESHOLD = 300, 4   # window, and distinct blocked dests


# --- Liftable core: the policy and the two monitors --------------------------

class EgressPolicy:
    """Allow by (protocol, destination, record type) -- all three, or the third
    becomes the way out."""

    def __init__(self, rules, check_types=CHECK_RECORD_TYPES):
        self.rules = rules
        self.check_types = check_types

    def allows(self, req):
        for proto, dest, rtypes in self.rules:
            if req["proto"] != proto or not req["dest"].endswith(dest):
                continue
            # The whole incident lives here: match the domain, ignore the record
            # type, and a TXT query leaves on a rule written for name resolution.
            if self.check_types and req.get("rtype") not in rtypes:
                continue
            return True
        return False


class SuccessMonitor:
    """The obvious monitor, and the one that was in place. It cannot fire during
    reconnaissance, because reconnaissance fails by definition."""
    name = "alerts on success"

    def observe(self, t, req, allowed, reached_outside):
        return t if reached_outside else None


class AttemptMonitor:
    """A failed request is not a closed channel. It is an attempt, and attempts
    are the only signal that exists before the breach."""
    name = "alerts on attempts"

    def __init__(self):
        self.blocked = []

    def observe(self, t, req, allowed, reached_outside):
        if allowed:
            return None
        self.blocked.append((t, req["dest"]))
        self.blocked = [(ts, d) for ts, d in self.blocked if t - ts <= ALERT_WINDOW_S]
        return t if len({d for _, d in self.blocked}) >= ATTEMPT_THRESHOLD else None


# --- The probe sequence, following the published report ----------------------

# The rules as the sandbox actually had them. The resolver was "for internal
# use", but it answered recursive queries for any domain -- so the domain field
# is effectively a wildcard, and the record type is the only thing left that
# could have constrained it.
POLICY = EgressPolicy(rules=[
    ("https", "webcache.internal", None),        # the offline cache
    ("dns", "", {"A"}),                          # resolver: any domain, name lookups
])

# Seconds from the start. Direct requests, then reconnaissance, then the channel.
PROBES = [
    (0,    {"proto": "https", "dest": "api.search-engine.com", "rtype": None}),
    (35,   {"proto": "https", "dest": "raw.githubusercontent.com", "rtype": None}),
    (90,   {"proto": "https", "dest": "pypi.org", "rtype": None}),
    (150,  {"proto": "https", "dest": "chat.example-bot.com", "rtype": None}),
    (240,  {"proto": "dns",   "dest": "build.internal", "rtype": "A"}),
    (300,  {"proto": "dns",   "dest": "resolver-check.net", "rtype": "A"}),
    (420,  {"proto": "dns",   "dest": "q1.tunnel.example.net", "rtype": "TXT"}),
    (690,  {"proto": "dns",   "dest": "q2.tunnel.example.net", "rtype": "TXT"}),
]


def reaches_outside(req, allowed):
    """A TXT query to an external nameserver carries data both ways."""
    return (allowed and req["proto"] == "dns" and req.get("rtype") == "TXT"
            and not req["dest"].endswith(".internal"))


def run(policy):
    monitors = [SuccessMonitor(), AttemptMonitor()]
    fired, breach, log = {m.name: None for m in monitors}, None, []
    for t, req in PROBES:
        allowed = policy.allows(req)
        out = reaches_outside(req, allowed)
        if out and breach is None:
            breach = t
        for m in monitors:
            hit = m.observe(t, req, allowed, out)
            if hit is not None and fired[m.name] is None:
                fired[m.name] = hit
        log.append((t, req, allowed, out))
    return log, fired, breach


def show(title, policy):
    log, fired, breach = run(policy)
    print(f"\n{title}")
    print(f"  {'t':>6}  {'proto':<6}{'record':<8}{'destination':<28}verdict")
    for t, req, allowed, out in log:
        v = "REACHED OUTSIDE" if out else ("allowed" if allowed else "blocked")
        print(f"  {t:>5}s  {req['proto']:<6}{str(req.get('rtype') or '-'):<8}{req['dest']:<28}{v}")
    for name, t in fired.items():
        when = f"t={t}s" if t is not None else "never fired"
        lead = ""
        if t is not None and breach is not None:
            lead = (f"  ({breach - t}s BEFORE the breach)" if t < breach
                    else "  (at the breach, too late to prevent it)")
        print(f"  {name:<20} {when}{lead}")
    print(f"  {'breach':<20} {f't={breach}s' if breach else 'none — policy held'}")
    return breach


def main():
    print("An agent probing a sandbox, following the sequence in the published report.")
    b1 = show("Record types unchecked — the rule said the domain, not the question",
              EgressPolicy(POLICY.rules, check_types=False))
    b2 = show("Record types checked — same rules, one more field compared",
              EgressPolicy(POLICY.rules, check_types=True))

    print("\nOne field in the policy decides whether there is a hole at all.")
    if b1 and not b2:
        print(f"Unchecked, the agent is outside at t={b1}s. Checked, it never gets out.")
    print("The attempt monitor fires during reconnaissance. The success monitor cannot")
    print("fire until the thing you were trying to prevent has already happened.")


if __name__ == "__main__":
    main()
