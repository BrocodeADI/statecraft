from statecraft.model.actions import ActionVerb, ProposedAction


def get_university_attack_path(actor_id: str = "actor_attacker") -> list[ProposedAction]:
    """The canonical deterministic 7-step attack path for the reference university scenario."""
    return [
        # Tick 1: Scan DMZ to discover WEB01
        ProposedAction(
            actor_id=actor_id,
            verb=ActionVerb.scan,
            target_id="net.dmz",
        ),
        # Tick 2: Enumerate WEB01 to find running services
        ProposedAction(
            actor_id=actor_id,
            verb=ActionVerb.enumerate,
            target_id="host.web01",
        ),
        # Tick 3: Exploit SQLi on StudentPortal web app
        ProposedAction(
            actor_id=actor_id,
            verb=ActionVerb.exploit,
            target_id="svc.web01.app",
            parameters={"vuln_id": "vuln.sqli-studentportal"},
        ),
        # Tick 4: Pivot to internal campus network via compromised WEB01
        ProposedAction(
            actor_id=actor_id,
            verb=ActionVerb.pivot,
            target_id="net.internal",
            parameters={"via": "host.web01", "via_host_id": "host.web01"},
        ),
        # Tick 5: Scan internal campus network to discover DB01, DC01, client01
        ProposedAction(
            actor_id=actor_id,
            verb=ActionVerb.scan,
            target_id="net.internal",
        ),
        # Tick 6: Authenticate to PostgreSQL on DB01 using harvested app_user credentials
        ProposedAction(
            actor_id=actor_id,
            verb=ActionVerb.authenticate,
            target_id="svc.db01.postgres",
            parameters={"credential_id": "cred.db01.app_user"},
        ),
        # Tick 7: Access student PII database on DB01 (achieving scenario objective)
        ProposedAction(
            actor_id=actor_id,
            verb=ActionVerb.access_data,
            target_id="asset.student_pii",
        ),
    ]
