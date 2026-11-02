"""
SentinelAI - Intrusion Prevention System (IPS) Decision & Containment Engine
Implements deterministic prevention policies, multi-tier threat confidence validation,
safety allowlist verification, duplicate block protection, temporary block expiration,
and automatic background unblocking.
"""

import os
import time
import uuid
import logging
import datetime
import threading
from typing import Dict, Any, List, Optional, Tuple

from database import DatabaseManager, get_db
from firewall_manager import (
    BaseFirewallAdapter,
    get_firewall_adapter,
    validate_ip_for_containment,
    SENTINEL_RULE_PREFIX
)

logger = logging.getLogger("SentinelAI.IPSEngine")


class IPSEngine:
    """
    Intrusion Prevention System (IPS) Orchestrator:
    - Evaluates network telemetry and correlated incidents against deterministic prevention rules.
    - Enforces safety allowlists, self-lockout prevention, and duplicate containment checks.
    - Modifies Windows Defender Firewall when in AUTOMATIC mode.
    - Monitors and logs decisions in MONITOR mode.
    - Schedules and verifies automatic unblocking of temporary rules.
    """

    def __init__(self, db: Optional[DatabaseManager] = None, adapter: Optional[BaseFirewallAdapter] = None):
        self.db = db or get_db()
        self.adapter = adapter or get_firewall_adapter()
        self._scheduler_running = False
        self._scheduler_thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._cooldown_cache: Dict[str, float] = {}  # ip -> last_evaluated_timestamp

        # Recover pending / expired rules from database on startup
        self._reconcile_startup_blocks()

        # Start background unblocking watchdog
        self.start_unblock_scheduler()

    def _reconcile_startup_blocks(self):
        """
        Reconciles active and expired blocks recorded in SQLite on application startup.
        Immediately purges any rules that expired while SentinelAI was shut down.
        """
        try:
            expired = self.db.get_expired_ips_blocks()
            if expired:
                logger.info(f"IPS Startup: Found {len(expired)} expired block(s) to reconcile.")
                for b in expired:
                    action_id = b.get("action_id")
                    fw_id = b.get("firewall_rule_id") or f"{SENTINEL_RULE_PREFIX}{action_id}"
                    ip = b.get("source_ip")
                    logger.info(f"Purging expired startup block {fw_id} for {ip}")
                    res = self.adapter.unblock_rule(fw_id)
                    now_iso = datetime.datetime.now().isoformat()
                    self.db.update_ips_action_status(
                        action_id=action_id,
                        status="UNBLOCKED",
                        unblocked_at=now_iso,
                        error_message=None if res.success else res.error_message
                    )
                    self.db.log_audit_action(
                        incident_id=b.get("incident_id"),
                        action_type="IPS_STARTUP_RECONCILE_UNBLOCK",
                        target_ip=ip,
                        execution_mode="automatic_unblock",
                        operator="IPS Startup Recovery",
                        details=f"Unblocked rule {fw_id} expired during offline interval.",
                        result="SUCCESS" if res.success else "FAILURE"
                    )
        except Exception as e:
            logger.error(f"Error during IPS startup reconciliation: {e}")

    def start_unblock_scheduler(self, interval_seconds: int = 30):
        """Starts the background thread checking for expired temporary rules every 30 seconds."""
        with self._lock:
            if self._scheduler_running:
                return
            self._scheduler_running = True

            def _worker():
                logger.info("SentinelAI IPS Unblock Watchdog started.")
                while self._scheduler_running:
                    try:
                        self.check_and_process_expirations()
                    except Exception as e:
                        logger.error(f"Error in IPS unblock watchdog: {e}")
                    time.sleep(interval_seconds)

            self._scheduler_thread = threading.Thread(
                target=_worker,
                daemon=True,
                name="SentinelAI-IPSUnblockWatchdog"
            )
            self._scheduler_thread.start()

    def stop_unblock_scheduler(self):
        """Stops the unblock scheduler thread."""
        with self._lock:
            self._scheduler_running = False

    def check_and_process_expirations(self) -> int:
        """
        Scans SQLite for expired verified blocks, calls firewall adapter to delete the rule,
        verifies that the rule is actually gone, and logs the unblock action.
        """
        settings = self.db.get_ips_settings()
        if not settings.get("automatic_unblocking_enabled", 1):
            return 0

        expired_list = self.db.get_expired_ips_blocks()
        if not expired_list:
            return 0

        unblocked_count = 0
        now_iso = datetime.datetime.now().isoformat()

        for block in expired_list:
            action_id = block.get("action_id")
            fw_id = block.get("firewall_rule_id") or f"{SENTINEL_RULE_PREFIX}{action_id}"
            ip = block.get("source_ip", "")

            logger.info(f"Expiring temporary IPS block for IP {ip} (Rule: {fw_id})")

            # Remove rule from operating system firewall
            res = self.adapter.unblock_rule(fw_id)

            if res.success:
                self.db.update_ips_action_status(
                    action_id=action_id,
                    status="UNBLOCKED",
                    unblocked_at=now_iso,
                    error_message=None
                )
                self.db.log_audit_action(
                    incident_id=block.get("incident_id"),
                    action_type="IPS_AUTO_UNBLOCK",
                    target_ip=ip,
                    execution_mode="automatic_scheduler",
                    operator="SentinelAI IPS Watchdog",
                    details=f"Temporary firewall block expired and was verified removed: {fw_id}",
                    result="SUCCESS"
                )
                unblocked_count += 1
            else:
                self.db.update_ips_action_status(
                    action_id=action_id,
                    status="VERIFIED",  # Keep verified status so it will be retried next cycle
                    error_message=f"Failed to remove rule on expiry: {res.error_message}"
                )
                self.db.log_audit_action(
                    incident_id=block.get("incident_id"),
                    action_type="IPS_AUTO_UNBLOCK_FAILED",
                    target_ip=ip,
                    execution_mode="automatic_scheduler",
                    operator="SentinelAI IPS Watchdog",
                    details=f"Failed to remove expired firewall rule {fw_id}: {res.error_message}",
                    result="FAILURE"
                )

        return unblocked_count

    def evaluate_threat(
        self,
        source_ip: str,
        category: str,
        severity: str,
        confidence: float,
        detection_reason: str,
        incident_id: Optional[str] = None,
        ml_score: Optional[float] = None,
        event_count: int = 1,
        ports_targeted: Optional[List[int]] = None
    ) -> Dict[str, Any]:
        """
        Core IPS Decision Pipeline:
        1. Query current IPS settings (prevention_mode, confidence_threshold, durations).
        2. Check IPS operating mode: if DISABLED, log and reject.
        3. Validate source IP against safety rules (self-IP, loopback, private networks, allowlists).
        4. Check for existing active blocks (Duplicate prevention).
        5. Check cooldown (prevent spamming evaluation).
        6. Determine Threat Eligibility:
           - Confidence must exceed configured confidence_threshold (default 0.85).
           - Deterministic rule agreement (Port Scan, Brute-Force, DoS volumetric, or repeated malicious activity).
           - ML anomaly score serves as corroborating evidence only (never the sole block reason).
        7. If mode is MONITOR:
           - Record in SQLite as MONITORED.
        8. If mode is AUTOMATIC:
           - Verify maximum active blocks limit.
           - Calculate block duration (15m initial, 60m repeated, up to max).
           - Invoke Windows Firewall Adapter to create inbound blocking rule.
           - Verify OS state.
           - Record in SQLite as VERIFIED or FAILED.
        """
        now = time.time()
        now_iso = datetime.datetime.fromtimestamp(now).isoformat()
        action_id = f"IPS-{uuid.uuid4().hex[:8].upper()}"

        settings = self.db.get_ips_settings()
        mode = settings.get("prevention_mode", "MONITOR").upper()
        conf_threshold = float(settings.get("confidence_threshold", 0.85))
        default_dur = int(settings.get("default_block_duration", 15))
        max_dur = int(settings.get("maximum_block_duration", 1440))
        max_blocks = int(settings.get("maximum_active_blocks", 50))
        allow_private = bool(settings.get("allow_private_network_blocks", 0))

        # Check Per-IP Cooldown (10 seconds)
        last_eval = self._cooldown_cache.get(source_ip, 0.0)
        if (now - last_eval) < 10.0 and self.db.get_active_block_by_ip(source_ip):
            # Already actively blocked or recently evaluated
            return {
                "decision": "DUPLICATE_ACTIVE_BLOCK",
                "action_id": None,
                "status": "SKIPPED_COOLDOWN",
                "message": f"IP {source_ip} is currently active or on cooldown."
            }
        self._cooldown_cache[source_ip] = now

        # ----------------------------------------------------------------------
        # 1. State: DISABLED
        # ----------------------------------------------------------------------
        if mode == "DISABLED":
            record = {
                "action_id": action_id,
                "source_ip": source_ip,
                "incident_id": incident_id,
                "detection_reason": detection_reason,
                "threat_category": category,
                "confidence": confidence,
                "action_type": "IGNORED_DISABLED",
                "firewall_rule_id": None,
                "action_status": "DISABLED",
                "created_at": now_iso,
                "expires_at": None,
                "verified_at": None,
                "unblocked_at": None,
                "error_message": "IPS prevention is currently DISABLED by administrator."
            }
            self.db.log_ips_action(record)
            return {
                "decision": "DISABLED",
                "action_id": action_id,
                "status": "DISABLED",
                "message": "IPS is in DISABLED state; no prevention actions taken."
            }

        # ----------------------------------------------------------------------
        # 2. Safety & Allowlist Validation
        # ----------------------------------------------------------------------
        is_safe, clean_ip, rejection_reason = validate_ip_for_containment(
            ip_str=source_ip,
            allow_private_networks=allow_private,
            custom_allowlist_checker=self.db.is_ip_in_ips_allowlist
        )

        if not is_safe:
            record = {
                "action_id": action_id,
                "source_ip": clean_ip,
                "incident_id": incident_id,
                "detection_reason": f"{detection_reason} (Rejected: {rejection_reason})",
                "threat_category": category,
                "confidence": confidence,
                "action_type": "REJECTED_SAFETY_POLICY",
                "firewall_rule_id": None,
                "action_status": "REJECTED",
                "created_at": now_iso,
                "expires_at": None,
                "verified_at": None,
                "unblocked_at": None,
                "error_message": rejection_reason
            }
            self.db.log_ips_action(record)
            logger.info(f"IPS Safety Guard: Rejected containment for {source_ip}: {rejection_reason}")
            return {
                "decision": "REJECTED_SAFETY",
                "action_id": action_id,
                "status": "REJECTED",
                "message": rejection_reason
            }

        # ----------------------------------------------------------------------
        # 3. Duplicate Block Check
        # ----------------------------------------------------------------------
        existing_block = self.db.get_active_block_by_ip(clean_ip)
        if existing_block:
            return {
                "decision": "ALREADY_BLOCKED",
                "action_id": existing_block.get("action_id"),
                "status": "VERIFIED",
                "message": f"IP {clean_ip} already has an active verified firewall block (Rule: {existing_block.get('firewall_rule_id')})."
            }

        # ----------------------------------------------------------------------
        # 4. Threat Criteria & Confidence Evaluation
        # ----------------------------------------------------------------------
        is_eligible = False
        rule_rationale = ""
        recurrence = self.db.get_ip_recurrence_count(clean_ip)

        cat_lower = category.lower()
        reason_lower = detection_reason.lower()

        # A. Port Scanning criteria
        if "port scan" in cat_lower or "port scan" in reason_lower or (ports_targeted and len(ports_targeted) >= 3):
            if confidence >= conf_threshold:
                is_eligible = True
                rule_rationale = f"Confirmed multi-port scanning pattern (confidence {confidence:.2f} >= threshold {conf_threshold:.2f})."

        # B. Brute-Force criteria
        elif "brute force" in cat_lower or "brute-force" in cat_lower or "auth" in reason_lower:
            if confidence >= conf_threshold or (event_count >= 3 and confidence >= 0.75):
                is_eligible = True
                rule_rationale = f"Confirmed repeated authentication attack targeting service ports (event count {event_count})."

        # C. Volumetric DoS / DDoS Flood criteria
        elif "ddos" in cat_lower or "dos flood" in cat_lower:
            if confidence >= conf_threshold and severity in ("Critical", "High"):
                is_eligible = True
                rule_rationale = f"High-confidence volumetric denial-of-service traffic surge."

        # D. High Volume Anomaly + ML score corroboration
        elif "volume anomaly" in cat_lower or "high volume" in cat_lower:
            # Do NOT block solely on volume or ML anomaly alone
            if ml_score is not None and ml_score >= 0.70 and confidence >= conf_threshold:
                is_eligible = True
                rule_rationale = f"Traffic volume surge corroborated by ML anomaly engine (score {ml_score:.2f})."
            else:
                rule_rationale = "Volume anomaly without sufficient multi-indicator corroboration (monitored only)."

        # E. Repeated Malicious Activity
        elif recurrence >= 3 and confidence >= 0.80:
            is_eligible = True
            rule_rationale = f"Repeated suspicious security events observed from host ({recurrence} historical incidents)."

        # Generic High-Confidence Fallback for explicitly confirmed threats
        elif confidence >= conf_threshold and severity in ("Critical", "High"):
            is_eligible = True
            rule_rationale = f"High-confidence threat event ({category}, confidence {confidence:.2f})."
        else:
            rule_rationale = f"Threat confidence {confidence:.2f} is below prevention threshold {conf_threshold:.2f} (monitored)."

        # ----------------------------------------------------------------------
        # 5. State: MONITOR (or threat not eligible for automated block)
        # ----------------------------------------------------------------------
        if mode == "MONITOR" or not is_eligible:
            record = {
                "action_id": action_id,
                "source_ip": clean_ip,
                "incident_id": incident_id,
                "detection_reason": detection_reason,
                "threat_category": category,
                "confidence": confidence,
                "action_type": "MONITOR_ONLY" if mode == "MONITOR" else "INSUFFICIENT_CONFIDENCE",
                "firewall_rule_id": None,
                "action_status": "MONITORED",
                "created_at": now_iso,
                "expires_at": None,
                "verified_at": None,
                "unblocked_at": None,
                "error_message": None if mode == "MONITOR" else rule_rationale
            }
            self.db.log_ips_action(record)
            logger.info(f"IPS Monitor: Evaluated {clean_ip} - Status: MONITORED ({rule_rationale})")
            return {
                "decision": "MONITORED",
                "action_id": action_id,
                "status": "MONITORED",
                "message": f"Event evaluated in {mode} mode: {rule_rationale}"
            }

        # ----------------------------------------------------------------------
        # 6. State: AUTOMATIC Execution
        # ----------------------------------------------------------------------
        # Check active blocks capacity
        active_count = len(self.db.get_active_ips_blocks())
        if active_count >= max_blocks:
            err_msg = f"Maximum active blocks limit reached ({active_count}/{max_blocks}). Automatic blocking suspended."
            record = {
                "action_id": action_id,
                "source_ip": clean_ip,
                "incident_id": incident_id,
                "detection_reason": detection_reason,
                "threat_category": category,
                "confidence": confidence,
                "action_type": "REJECTED_CAPACITY",
                "firewall_rule_id": None,
                "action_status": "FAILED",
                "created_at": now_iso,
                "expires_at": None,
                "verified_at": None,
                "unblocked_at": None,
                "error_message": err_msg
            }
            self.db.log_ips_action(record)
            logger.warning(err_msg)
            return {
                "decision": "CAPACITY_EXCEEDED",
                "action_id": action_id,
                "status": "FAILED",
                "message": err_msg
            }

        # Calculate duration: 15 min default, 60 min if recurrent, capped at max_dur
        dur_minutes = default_dur
        if recurrence >= 2:
            dur_minutes = min(max_dur, 60)
        if recurrence >= 5:
            dur_minutes = min(max_dur, 240)

        expires_dt = datetime.datetime.fromtimestamp(now) + datetime.timedelta(minutes=dur_minutes)
        expires_iso = expires_dt.isoformat()

        # Execute firewall block
        logger.info(f"IPS AUTOMATIC: Applying {dur_minutes}m block on {clean_ip} ({rule_rationale})")
        fw_res = self.adapter.block_ip(
            ip=clean_ip,
            action_id=action_id,
            reason=f"{category}: {detection_reason[:80]}"
        )

        final_status = "VERIFIED" if fw_res.verified else "FAILED"
        verified_time = now_iso if fw_res.verified else None
        err_msg = fw_res.error_message if not fw_res.verified else None

        record = {
            "action_id": action_id,
            "source_ip": clean_ip,
            "incident_id": incident_id,
            "detection_reason": detection_reason,
            "threat_category": category,
            "confidence": confidence,
            "action_type": "BLOCK",
            "firewall_rule_id": fw_res.rule_id,
            "action_status": final_status,
            "created_at": now_iso,
            "expires_at": expires_iso if fw_res.verified else None,
            "verified_at": verified_time,
            "unblocked_at": None,
            "error_message": err_msg
        }
        self.db.log_ips_action(record)

        # Audit log entry
        self.db.log_audit_action(
            incident_id=incident_id,
            action_type="IPS_AUTOMATIC_BLOCK",
            target_ip=clean_ip,
            execution_mode="automatic_prevention",
            operator="SentinelAI IPS Engine",
            details=(
                f"Rule: {fw_res.rule_id} | Category: {category} | Severity: {severity} | "
                f"Duration: {dur_minutes}m | Verified: {fw_res.verified} | Details: {fw_res.details}"
            ),
            result="SUCCESS" if fw_res.verified else "FAILURE"
        )

        return {
            "decision": "BLOCKED" if fw_res.verified else "BLOCK_FAILED",
            "action_id": action_id,
            "status": final_status,
            "firewall_rule_id": fw_res.rule_id,
            "duration_minutes": dur_minutes,
            "expires_at": expires_iso if fw_res.verified else None,
            "verified": fw_res.verified,
            "message": fw_res.details or err_msg
        }

    def manual_unblock(self, action_id_or_ip: str, operator: str = "Security Administrator") -> Dict[str, Any]:
        """
        Manually unblock an IP or action ID:
        1. Finds matching active block in SQLite.
        2. Calls firewall adapter to delete the rule.
        3. Confirms OS removal.
        4. Updates SQLite record to UNBLOCKED.
        5. Logs audit action.
        """
        target = str(action_id_or_ip).strip()
        now_iso = datetime.datetime.now().isoformat()

        # Find target action
        action = self.db.get_ips_action_by_id(target)
        if not action:
            action = self.db.get_active_block_by_ip(target)

        if not action:
            return {
                "success": False,
                "message": f"No active IPS containment block found for '{target}'."
            }

        action_id = action.get("action_id")
        fw_rule_id = action.get("firewall_rule_id") or f"{SENTINEL_RULE_PREFIX}{action_id}"
        ip = action.get("source_ip")

        logger.info(f"Manual unblock initiated by {operator} for rule {fw_rule_id} (IP: {ip})")
        res = self.adapter.unblock_rule(fw_rule_id)

        if res.success:
            self.db.update_ips_action_status(
                action_id=action_id,
                status="UNBLOCKED",
                unblocked_at=now_iso,
                error_message=None
            )
            self.db.log_audit_action(
                incident_id=action.get("incident_id"),
                action_type="IPS_MANUAL_UNBLOCK",
                target_ip=ip,
                execution_mode="manual_analyst",
                operator=operator,
                details=f"Analyst manually unblocked rule {fw_rule_id} for host {ip}.",
                result="SUCCESS"
            )
            return {
                "success": True,
                "action_id": action_id,
                "source_ip": ip,
                "message": f"Successfully removed firewall rule {fw_rule_id} and verified unblock for {ip}."
            }
        else:
            self.db.update_ips_action_status(
                action_id=action_id,
                status="FAILED",
                error_message=f"Manual unblock failed: {res.error_message}"
            )
            self.db.log_audit_action(
                incident_id=action.get("incident_id"),
                action_type="IPS_MANUAL_UNBLOCK_FAILED",
                target_ip=ip,
                execution_mode="manual_analyst",
                operator=operator,
                details=f"Failed to unblock rule {fw_rule_id}: {res.error_message}",
                result="FAILURE"
            )
            return {
                "success": False,
                "action_id": action_id,
                "source_ip": ip,
                "message": f"OS firewall unblock failed: {res.error_message}"
            }


# Singleton factory function
_global_ips_engine: Optional[IPSEngine] = None

def get_ips_engine(db: Optional[DatabaseManager] = None, force_new: bool = False) -> IPSEngine:
    global _global_ips_engine
    if _global_ips_engine is None or force_new:
        _global_ips_engine = IPSEngine(db=db)
    return _global_ips_engine
