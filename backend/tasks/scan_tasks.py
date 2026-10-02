"""
scan_tasks.py — Celery tasks for executing scans and retests.

Manages:
- full scans: runs all 15 attacks IN PARALLEL, publishes live progress via SSE channels.
- retest scans: re-evaluates previously open findings.
- Cost budget caps: checks total calls to LLM judge and generator.
"""

from datetime import datetime
import json
import redis as redis_lib
from sqlalchemy.orm import Session
from concurrent.futures import ThreadPoolExecutor, as_completed

from config import settings
from contracts import AttackType, Severity, FindingStatus, ScanStatus, ScanType
from crypto import decrypt_token
from database import SessionLocal
from models import Finding, Scan, Target
from attack_engine.runner import run_attack, MULTI_TURN_ATTACK_TYPES
from fix_engine.fix_mappings import FIX_MAPPINGS
from tasks.celery_app import celery_app

_redis = redis_lib.from_url(settings.REDIS_URL, decode_responses=True)


def translate_url_for_docker(url: str) -> str:
    """
    Translate localhost URLs to host.docker.internal for Docker container access.
    This allows targets registered as localhost:XXXX to be scanned from inside containers.
    """
    import re
    # Replace localhost with host.docker.internal
    url = re.sub(r'localhost', 'host.docker.internal', url, flags=re.IGNORECASE)
    # Also handle 127.0.0.1
    url = re.sub(r'127\.0\.0\.1', 'host.docker.internal', url)
    return url


def publish_sse_event(scan_id: str, event_type: str, data: dict):
    """Publish a live event to the Redis SSE channel for this scan."""
    channel = f"sse:{scan_id}"
    _redis.publish(channel, json.dumps({"event_type": event_type, "data": data}))


@celery_app.task(bind=True, name="tasks.scan_tasks.run_full_scan", queue="scans", max_retries=3)
def run_full_scan(self, scan_id: str, target_id: str):
    """
    Run all 15 security attacks against the target IN PARALLEL.
    Updates DB status and streams results live over Redis pub/sub.
    
    Uses ThreadPoolExecutor to run attacks concurrently for 3-6x speedup.
    Target: Complete full scan in <10 seconds (vs 30-60s sequential).
    """
    db: Session = SessionLocal()
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    target = db.query(Target).filter(Target.id == target_id).first()

    if not scan or not target:
        db.close()
        return

    # Update scan status to running
    scan.status = ScanStatus.running
    scan.started_at = datetime.utcnow()
    scan.total_attacks = len(list(AttackType))
    scan.completed_attacks = 0
    db.commit()

    publish_sse_event(scan_id, "scan_started", {"scan_id": scan_id, "total_attacks": scan.total_attacks})

    # Decrypt authorization token if target has one
    auth_token = None
    if target.auth_token_encrypted:
        try:
            auth_token = decrypt_token(target.auth_token_encrypted)
        except Exception as exc:
            scan.status = ScanStatus.failed
            db.commit()
            publish_sse_event(scan_id, "scan_failed", {"reason": f"Decryption of auth token failed: {exc}"})
            db.close()
            return

    # Reset LLM call counter for this scan
    _redis.delete(f"llm_calls:{scan_id}")

    try:
        # PARALLEL EXECUTION: Run all 15 attacks concurrently with ThreadPoolExecutor
        # Increased to 15 workers (one per attack) for maximum speed
        with ThreadPoolExecutor(max_workers=15) as executor:
            # Submit all attack tasks to thread pool
            future_to_attack = {
                executor.submit(
                    run_attack,
                    attack_type=attack_type,
                    target_url=translate_url_for_docker(target.url),
                    auth_token=auth_token,
                    scan_id=scan_id,
                ): attack_type
                for attack_type in AttackType
            }

            # Process results as they complete (not in submission order)
            for future in as_completed(future_to_attack):
                attack_type = future_to_attack[future]
                
                try:
                    result = future.result()
                    
                    # 2. Record finding if attack succeeded (vulnerability found)
                    if result.success:
                        mapping = FIX_MAPPINGS.get(
                            attack_type,
                            {
                                "severity": Severity.medium,
                                "risk_score": 5.0,
                                "owasp_category": "General safety violation",
                                "fix_recommendation": "Configure safety filters.",
                                "fix_code_snippet": None,
                            },
                        )

                        finding = Finding(
                            scan_id=scan.id,
                            target_id=target.id,
                            attack_type=attack_type,
                            severity=mapping["severity"],
                            status=FindingStatus.open,
                            attack_payload=result.payload,
                            attack_response=result.response,
                            layer_failed=result.layer_failed,
                            risk_score=mapping["risk_score"],
                            fix_recommendation=mapping["fix_recommendation"],
                            fix_code_snippet=mapping["fix_code_snippet"],
                            owasp_category=mapping["owasp_category"],
                            detection_method=result.detection_method.value,
                            confidence=result.confidence,
                            retest_history=[],
                        )
                        db.add(finding)
                        db.commit()

                        # Publish finding event
                        publish_sse_event(
                            scan_id,
                            "finding_discovered",
                            {
                                "finding_id": str(finding.id),
                                "attack_type": attack_type.value,
                                "severity": mapping["severity"].value,
                            },
                        )

                    # 3. Update completed counter
                    scan.completed_attacks += 1
                    db.commit()

                    # Publish completed attack step
                    publish_sse_event(
                        scan_id,
                        "attack_complete",
                        {
                            "attack_type": attack_type.value,
                            "success": result.success,
                            "confidence": result.confidence,
                            "completed_attacks": scan.completed_attacks,
                            "total_attacks": scan.total_attacks,
                        },
                    )
                    
                except Exception as attack_exc:
                    # Individual attack failure shouldn't crash entire scan
                    # Log and continue with other attacks
                    publish_sse_event(
                        scan_id,
                        "attack_error",
                        {
                            "attack_type": attack_type.value,
                            "error": str(attack_exc),
                        },
                    )
                    scan.completed_attacks += 1
                    db.commit()

        # Mark scan done
        scan.status = ScanStatus.done
        scan.completed_at = datetime.utcnow()
        db.commit()

        publish_sse_event(scan_id, "scan_done", {"scan_id": scan_id})

    except Exception as exc:
        db.rollback()
        if self.request.retries >= self.max_retries:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = ScanStatus.failed
                scan.completed_at = datetime.utcnow()
                db.commit()
            publish_sse_event(scan_id, "scan_failed", {"reason": f"Max retries exceeded: {exc}"})
            db.close()
            raise exc
        else:
            db.close()
            raise self.retry(exc=exc, countdown=10)
    finally:
        try:
            db.close()
        except Exception:
            pass


@celery_app.task(bind=True, name="tasks.scan_tasks.run_retest_scan", queue="scans", max_retries=3)
def run_retest_scan(self, retest_scan_id: str, target_id: str, original_scan_id: str):
    """
    Retest ONLY previously open findings to check if developer changes fixed them.
    Updates historical findings and flips status based on result.
    """
    db: Session = SessionLocal()
    retest_scan = db.query(Scan).filter(Scan.id == retest_scan_id).first()
    target = db.query(Target).filter(Target.id == target_id).first()

    if not retest_scan or not target:
        db.close()
        return

    # Find open findings from original scan
    open_findings = (
        db.query(Finding)
        .filter(Finding.target_id == target_id, Finding.status == FindingStatus.open)
        .all()
    )

    retest_scan.status = ScanStatus.running
    retest_scan.started_at = datetime.utcnow()
    retest_scan.total_attacks = len(open_findings)
    retest_scan.completed_attacks = 0
    db.commit()

    publish_sse_event(
        retest_scan_id,
        "scan_started",
        {"scan_id": retest_scan_id, "total_attacks": retest_scan.total_attacks},
    )

    if not open_findings:
        retest_scan.status = ScanStatus.done
        retest_scan.completed_at = datetime.utcnow()
        db.commit()
        publish_sse_event(retest_scan_id, "scan_done", {"scan_id": retest_scan_id})
        publish_sse_event(retest_scan_id, "fully_secure", {"target_id": target_id})
        db.close()
        return

    # Decrypt token
    auth_token = None
    if target.auth_token_encrypted:
        try:
            auth_token = decrypt_token(target.auth_token_encrypted)
        except Exception as exc:
            retest_scan.status = ScanStatus.failed
            db.commit()
            publish_sse_event(retest_scan_id, "scan_failed", {"reason": str(exc)})
            db.close()
            return

    # Reset cost cap
    _redis.delete(f"llm_calls:{retest_scan_id}")

    try:
        resolved_count = 0
        for finding in open_findings:
            # Multi-turn findings store a condensed "[Multi-turn] a -> b -> c" marker
            # as attack_payload, not a replayable single message — replaying it verbatim
            # would send that marker text as a literal single-shot prompt. Instead, let
            # run_attack re-run the canonical multi-turn conversation from the dataset.
            # All other attack types replay the exact payload that triggered the finding.
            is_multi_turn = finding.attack_type in MULTI_TURN_ATTACK_TYPES
            result = run_attack(
                attack_type=finding.attack_type,
                target_url=translate_url_for_docker(target.url),
                auth_token=auth_token,
                specific_payload=None if is_multi_turn else finding.attack_payload,
                scan_id=retest_scan_id,
            )

            # If attack still succeeds, vulnerability remains open/regressed
            # If attack fails (refused by target), vulnerability is resolved!
            is_resolved = not result.success

            new_status = FindingStatus.resolved if is_resolved else FindingStatus.open

            if is_resolved:
                resolved_count += 1

            # Update finding record
            history_item = {
                "retest_scan_id": retest_scan_id,
                "timestamp": datetime.utcnow().isoformat(),
                "success": result.success,
                "verdict": new_status.value,
                "confidence": result.confidence,
            }

            # Update history list (JSONB)
            history = list(finding.retest_history or [])
            history.append(history_item)
            finding.retest_history = history
            finding.status = new_status
            db.commit()

            retest_scan.completed_attacks += 1
            db.commit()

            publish_sse_event(
                retest_scan_id,
                "finding_retested",
                {
                    "finding_id": str(finding.id),
                    "attack_type": finding.attack_type.value,
                    "status": new_status.value,
                    "completed_attacks": retest_scan.completed_attacks,
                    "total_attacks": retest_scan.total_attacks,
                },
            )

        # Mark scan complete
        retest_scan.status = ScanStatus.done
        retest_scan.completed_at = datetime.utcnow()
        db.commit()

        publish_sse_event(retest_scan_id, "scan_done", {"scan_id": retest_scan_id})

        # If ALL open findings were resolved, notify that target is fully secure
        if resolved_count == len(open_findings):
            publish_sse_event(retest_scan_id, "fully_secure", {"target_id": target_id})

    except Exception as exc:
        db.rollback()
        if self.request.retries >= self.max_retries:
            retest_scan = db.query(Scan).filter(Scan.id == retest_scan_id).first()
            if retest_scan:
                retest_scan.status = ScanStatus.failed
                retest_scan.completed_at = datetime.utcnow()
                db.commit()
            publish_sse_event(retest_scan_id, "scan_failed", {"reason": f"Max retries exceeded: {exc}"})
            db.close()
            raise exc
        else:
            db.close()
            raise self.retry(exc=exc, countdown=10)
    finally:
        try:
            db.close()
        except Exception:
            pass
