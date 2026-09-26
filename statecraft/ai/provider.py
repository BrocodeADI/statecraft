"""AI Provider interfaces and local NLP translator for Statecraft actions.

CRITICAL ARCHITECTURAL BOUNDARY:
The AI is strictly an ACTION PROPOSER. It has ZERO authority over simulation state.
It converts natural language into a typed ProposedAction.
The engine alone validates prerequisites, checks firewalls, and applies effects.
"""

from abc import ABC, abstractmethod
import re
from typing import Any

from statecraft.model.actions import ActionVerb, ProposedAction
from statecraft.observation.attacker_view import AttackerObservation


class BaseAIProvider(ABC):
    """Abstract interface for AI action proposers."""

    @abstractmethod
    def propose_action(
        self,
        prompt: str,
        observation: AttackerObservation,
        actor_id: str = "actor_attacker",
    ) -> ProposedAction | None:
        """Translate a natural language prompt into a ProposedAction using observation context."""
        pass


class RuleBasedNLPProvider(BaseAIProvider):
    """Self-contained, offline natural language interpreter.
    
    Translates user intents and entity keywords into strictly typed ProposedAction objects
    without requiring external APIs, cloud services, or heavy ML dependencies.
    """

    def propose_action(
        self,
        prompt: str,
        observation: AttackerObservation,
        actor_id: str = "actor_attacker",
    ) -> ProposedAction | None:
        cleaned = prompt.strip().lower()

        # 1. SCAN intent
        # Examples: "find an entry point into the university network", "scan dmz", "discover hosts on net.dmz"
        if any(w in cleaned for w in ["find entry point", "find an entry", "entry point", "recon dmz", "scan dmz", "discover dmz"]):
            return ProposedAction(actor_id=actor_id, verb=ActionVerb.scan, target_id="net.dmz")
        
        if "scan" in cleaned or "sweep" in cleaned or "discover hosts" in cleaned:
            if "internal" in cleaned or "campus" in cleaned or "net.internal" in cleaned:
                return ProposedAction(actor_id=actor_id, verb=ActionVerb.scan, target_id="net.internal")
            elif "dmz" in cleaned or "external" in cleaned or "net.dmz" in cleaned:
                return ProposedAction(actor_id=actor_id, verb=ActionVerb.scan, target_id="net.dmz")
            # If target network is discovered in observation, pick first
            for net in observation.discovered_networks:
                if net.lower() in cleaned:
                    return ProposedAction(actor_id=actor_id, verb=ActionVerb.scan, target_id=net)
            # Default to first reachable network
            target_net = observation.discovered_networks[0] if observation.discovered_networks else "net.dmz"
            return ProposedAction(actor_id=actor_id, verb=ActionVerb.scan, target_id=target_net)

        # 2. ENUMERATE intent
        # Examples: "enumerate web01", "port scan web01", "find services on web01", "inspect web server"
        if any(w in cleaned for w in ["enumerate", "port scan", "find services", "inspect host", "scan services", "services on"]):
            if "web01" in cleaned or "web" in cleaned or "server" in cleaned:
                return ProposedAction(actor_id=actor_id, verb=ActionVerb.enumerate, target_id="host.web01")
            elif "db01" in cleaned or "db" in cleaned or "database" in cleaned:
                return ProposedAction(actor_id=actor_id, verb=ActionVerb.enumerate, target_id="host.db01")
            for host in observation.discovered_hosts:
                if host.lower() in cleaned:
                    return ProposedAction(actor_id=actor_id, verb=ActionVerb.enumerate, target_id=host)
            # Default to first discovered host
            target_host = observation.discovered_hosts[0] if observation.discovered_hosts else "host.web01"
            return ProposedAction(actor_id=actor_id, verb=ActionVerb.enumerate, target_id=target_host)

        # 3. EXPLOIT intent
        # Examples: "exploit studentportal", "attack sqli", "exploit web app", "run sql injection"
        if any(w in cleaned for w in ["exploit", "attack", "sqli", "sql injection", "vulnerability", "hack web"]):
            vuln_id = "vuln.sqli-studentportal"
            target_svc = "svc.web01.app"
            return ProposedAction(
                actor_id=actor_id,
                verb=ActionVerb.exploit,
                target_id=target_svc,
                parameters={"vuln_id": vuln_id},
            )

        # 4. PIVOT intent
        # Examples: "pivot to internal", "lateral movement to internal network via web01", "pivot"
        if any(w in cleaned for w in ["pivot", "lateral", "move to internal", "tunnel"]):
            return ProposedAction(
                actor_id=actor_id,
                verb=ActionVerb.pivot,
                target_id="net.internal",
                parameters={"via": "host.web01", "via_host_id": "host.web01"},
            )

        # 5. AUTHENTICATE intent
        # Examples: "authenticate to postgres", "login to db01 using harvested credentials", "connect database"
        if any(w in cleaned for w in ["authenticate", "login", "auth", "connect to postgres", "connect to db", "use credentials"]):
            cred_id = "cred.db01.app_user" if "cred.db01.app_user" in observation.known_credentials else (
                observation.known_credentials[0] if observation.known_credentials else "cred.db01.app_user"
            )
            return ProposedAction(
                actor_id=actor_id,
                verb=ActionVerb.authenticate,
                target_id="svc.db01.postgres",
                parameters={"credential_id": cred_id},
            )

        # 6. ACCESS_DATA intent
        # Examples: "access student pii", "exfiltrate student records", "read student data", "dump database", "steal data"
        if any(w in cleaned for w in ["access", "read data", "steal", "exfiltrate", "dump", "pii", "student records", "student data"]):
            return ProposedAction(
                actor_id=actor_id,
                verb=ActionVerb.access_data,
                target_id="asset.student_pii",
            )

        # 7. ESCALATE_PRIVILEGE intent
        if any(w in cleaned for w in ["escalate", "privesc", "root", "admin", "privilege"]):
            return ProposedAction(
                actor_id=actor_id,
                verb=ActionVerb.escalate_privilege,
                target_id="host.web01",
                parameters={"method": "sudo"},
            )

        # 8. PERSIST intent
        if any(w in cleaned for w in ["persist", "backdoor", "maintain access", "cron", "persistence"]):
            return ProposedAction(
                actor_id=actor_id,
                verb=ActionVerb.persist,
                target_id="host.web01",
                parameters={"technique": "cron"},
            )

        # Unrecognized intent
        return None
