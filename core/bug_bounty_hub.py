"""
SWA AI Bug Bounty Directory & VDP Hub
Comprehensive directory of top crowdsourced bug bounty programs,
Vulnerability Disclosure Programs (VDP), scopes, and reward tiers.
"""

from typing import List, Dict, Any

BUG_BOUNTY_PLATFORMS = [
    {
        "name": "HackerOne",
        "url": "https://hackerone.com/directory/programs",
        "type": "Commercial Bug Bounty Platform",
        "programs_count": "1,000+",
        "features": "Managed triage, private programs, bounties via PayPal/Wire/Crypto"
    },
    {
        "name": "Bugcrowd",
        "url": "https://bugcrowd.com/programs",
        "type": "Crowdsourced Cybersecurity",
        "programs_count": "600+",
        "features": "CrowdStream leaderboards, vulnerability rating taxonomy (VRT)"
    },
    {
        "name": "Intigriti",
        "url": "https://app.intigriti.com/programs",
        "type": "European Ethical Hacking Platform",
        "programs_count": "350+",
        "features": "Strict European compliance, dynamic challenge bonuses"
    },
    {
        "name": "YesWeHack",
        "url": "https://yeswehack.com/programs",
        "type": "Global Bug Bounty Platform",
        "programs_count": "400+",
        "features": "Real-time vulnerability triage, multi-currency payouts"
    }
]

BUG_BOUNTY_PROGRAMS = [
    {
        "program": "Google VRP",
        "platform": "Google Bughunter",
        "domain": "google.com",
        "scope": "*.google.com, *.youtube.com, *.android.com",
        "reward_tier": "$100 - $31,337+",
        "policy_url": "https://bughunters.google.com/",
        "safe_harbor": True
    },
    {
        "program": "Microsoft Bug Bounty",
        "platform": "MSRC",
        "domain": "microsoft.com",
        "scope": "*.microsoft.com, *.azure.com, *.office.com",
        "reward_tier": "$500 - $250,000",
        "policy_url": "https://www.microsoft.com/en-us/msrc/bounty",
        "safe_harbor": True
    },
    {
        "program": "Meta Bug Bounty",
        "platform": "Meta Whitehat",
        "domain": "meta.com",
        "scope": "*.facebook.com, *.instagram.com, *.whatsapp.com",
        "reward_tier": "$500 - Unlimited",
        "policy_url": "https://www.facebook.com/whitehat",
        "safe_harbor": True
    },
    {
        "program": "Apple Security Bounty",
        "platform": "Apple Security",
        "domain": "apple.com",
        "scope": "*.apple.com, *.icloud.com",
        "reward_tier": "$1,000 - $1,000,000",
        "policy_url": "https://security.apple.com/bounty/",
        "safe_harbor": True
    },
    {
        "program": "GitHub Bug Bounty",
        "platform": "HackerOne",
        "domain": "github.com",
        "scope": "*.github.com, *.githubassets.com, *.githubapp.com",
        "reward_tier": "$617 - $30,000+",
        "policy_url": "https://bounty.github.com/",
        "safe_harbor": True
    },
    {
        "program": "Shopify Bug Bounty",
        "platform": "HackerOne",
        "domain": "shopify.com",
        "scope": "*.shopify.com, *.myshopify.com",
        "reward_tier": "$500 - $50,000",
        "policy_url": "https://hackerone.com/shopify",
        "safe_harbor": True
    },
    {
        "program": "Uber Bug Bounty",
        "platform": "HackerOne",
        "domain": "uber.com",
        "scope": "*.uber.com, *.ubereats.com",
        "reward_tier": "$500 - $15,000",
        "policy_url": "https://hackerone.com/uber",
        "safe_harbor": True
    },
    {
        "program": "US Dept of Defense (DoD)",
        "platform": "HackerOne (VDP)",
        "domain": "defense.gov",
        "scope": "*.mil, *.defense.gov",
        "reward_tier": "Public VDP / Points & Swag",
        "policy_url": "https://hackerone.com/deptofdefense",
        "safe_harbor": True
    },
    {
        "program": "GitLab Bug Bounty",
        "platform": "HackerOne",
        "domain": "gitlab.com",
        "scope": "*.gitlab.com",
        "reward_tier": "$650 - $35,000",
        "policy_url": "https://hackerone.com/gitlab",
        "safe_harbor": True
    },
    {
        "program": "Yahoo / Verizon Media",
        "platform": "HackerOne",
        "domain": "yahoo.com",
        "scope": "*.yahoo.com, *.aol.com",
        "reward_tier": "$100 - $15,000",
        "policy_url": "https://hackerone.com/yahoo",
        "safe_harbor": True
    },
    {
        "program": "Coinbase Bug Bounty",
        "platform": "HackerOne",
        "domain": "coinbase.com",
        "scope": "*.coinbase.com, *.pro.coinbase.com",
        "reward_tier": "$200 - $50,000",
        "policy_url": "https://hackerone.com/coinbase",
        "safe_harbor": True
    },
    {
        "program": "Netflix Bug Bounty",
        "platform": "Bugcrowd",
        "domain": "netflix.com",
        "scope": "*.netflix.com, *.nflxso.net",
        "reward_tier": "$200 - $20,000",
        "policy_url": "https://bugcrowd.com/netflix",
        "safe_harbor": True
    },
    {
        "program": "Tesla Bug Bounty",
        "platform": "Bugcrowd",
        "domain": "tesla.com",
        "scope": "*.tesla.com, *.teslamotors.com",
        "reward_tier": "$100 - $15,000",
        "policy_url": "https://bugcrowd.com/tesla",
        "safe_harbor": True
    },
    {
        "program": "Atlassian",
        "platform": "Bugcrowd",
        "domain": "atlassian.com",
        "scope": "*.atlassian.com, *.jira.com, *.trello.com",
        "reward_tier": "$250 - $10,000",
        "policy_url": "https://bugcrowd.com/atlassian",
        "safe_harbor": True
    },
    {
        "program": "Intel Bug Bounty",
        "platform": "Intigriti",
        "domain": "intel.com",
        "scope": "*.intel.com",
        "reward_tier": "$500 - $100,000",
        "policy_url": "https://app.intigriti.com/programs/intel",
        "safe_harbor": True
    }
]

class BugBountyHub:
    @staticmethod
    def list_programs(query: str = "") -> List[Dict[str, Any]]:
        if not query:
            return BUG_BOUNTY_PROGRAMS
        q = query.lower()
        return [
            p for p in BUG_BOUNTY_PROGRAMS
            if q in p["program"].lower() or q in p["domain"].lower() or q in p["platform"].lower()
        ]

    @staticmethod
    def list_platforms() -> List[Dict[str, Any]]:
        return BUG_BOUNTY_PLATFORMS
