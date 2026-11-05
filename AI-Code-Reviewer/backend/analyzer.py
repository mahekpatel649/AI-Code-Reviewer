"""End-to-end repository analysis orchestrator.

Coordinates upload extraction, multi-engine scanning, AI vulnerability
explanations, database persistence, and temporary workspace cleanup.
"""

from __future__ import annotations

import io
import uuid
from typing import Any, Callable, Dict, Optional

from ai.explanation import AIExplanationEngine
from backend.scanner import scan_repository
from backend.upload import cleanup_extraction, extract_repository, save_single_python_file
from database.db import DatabaseManager


class RepositoryAnalyzer:
    """Orchestrates the entire code intelligence and security review workflow."""

    def __init__(self, db_manager: Optional[DatabaseManager] = None):
        self.db = db_manager or DatabaseManager()
        self.ai_engine = AIExplanationEngine()

    def analyze_repository(
        self,
        upload_source: bytes | io.BytesIO | str,
        project_name: str = "Uploaded Project",
        is_single_file: bool = False,
        single_filename: str = "app.py",
        progress_callback: Optional[Callable[[str, float], None]] = None,
    ) -> Dict[str, Any]:
        """Run full end-to-end analysis on an uploaded repository archive or single file.
        
        Args:
            upload_source: ZIP bytes, BytesIO, or path
            project_name: Name of the project
            is_single_file: True if single .py file was uploaded
            single_filename: Name of single file if applicable
            progress_callback: Optional callback(stage_text, percent)
            
        Returns:
            Complete scan results dictionary including scan_id and database status.
        """
        scan_id = str(uuid.uuid4())
        extract_meta = None

        try:
            # Stage 1: Extraction & Validation
            if progress_callback:
                progress_callback("Extracting and validating archive...", 0.15)

            if is_single_file:
                raw_bytes = upload_source if isinstance(upload_source, bytes) else upload_source.read()
                extract_meta = save_single_python_file(raw_bytes, single_filename)
            else:
                extract_meta = extract_repository(upload_source)

            # Stage 2: Code Scanning
            if progress_callback:
                progress_callback(
                    f"Scanning {len(extract_meta.get('python_files', []))} Python file(s) with Bandit & AST...",
                    0.45,
                )

            scan_results = scan_repository(extract_meta, project_name=project_name)
            findings = scan_results.get("findings", [])

            # Stage 3: AI Explanation & Recommendations
            if progress_callback:
                progress_callback(
                    f"Generating AI intelligence & remediation advice for {len(findings)} finding(s)...",
                    0.75,
                )

            recommendations = self.ai_engine.explain_all_findings(findings)

            # Attach recommendations directly to findings for convenience
            for f in findings:
                f_id = f.get("finding_id")
                if f_id and f_id in recommendations:
                    rec = recommendations[f_id]
                    f["explanation"] = rec.get("explanation", "")
                    f["root_cause"] = rec.get("root_cause", "")
                    f["impact"] = rec.get("impact", "")
                    f["suggested_fix"] = rec.get("suggested_fix", "")
                    f["why_safer"] = rec.get("why_safer", "")
                    f["prevention_advice"] = rec.get("prevention_advice", "")
                    f["fix_priority"] = rec.get("fix_priority", "P2 (Medium)")

            # Stage 4: Database Storage
            if progress_callback:
                progress_callback("Persisting review results to database...", 0.90)

            self.db.save_scan_results(
                project_name=project_name,
                scan_id=scan_id,
                total_files=scan_results.get("total_files", 0),
                scanned_files=scan_results.get("scanned_files", 0),
                unsupported_files=scan_results.get("unsupported_files", 0),
                total_issues=scan_results.get("total_issues", 0),
                security_score=scan_results.get("security_score", 100.0),
                findings=findings,
                recommendations=recommendations,
                scan_status="COMPLETED",
            )

            scan_results["scan_id"] = scan_id
            scan_results["recommendations"] = recommendations

            if progress_callback:
                progress_callback("Scan completed successfully!", 1.0)

            return scan_results

        finally:
            # Stage 5: Workspace Cleanup
            if extract_meta and "extract_dir" in extract_meta:
                cleanup_extraction(extract_meta["extract_dir"])
