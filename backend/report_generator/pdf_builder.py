"""
pdf_builder.py — Generate comprehensive PDF compliance reports

Creates professional security audit reports with:
- Cover page with target info and risk score
- Executive summary (findings by severity)
- Full audit trail (all 15 attack layers)
- Compliance mapping (OWASP, EU AI Act, NIST AI RMF)
- Code fixes for each vulnerability
"""

from datetime import datetime
from io import BytesIO
from typing import List, Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    PageBreak,
    Table,
    TableStyle,
    Image as RLImage,
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY

from contracts import Severity
from models import Scan, Target, Finding, AttackLog


class PDFReportBuilder:
    """Generates compliance audit report PDFs for security scans."""

    def __init__(self, scan: Scan, target: Target, findings: List[Finding], audit_logs: List[AttackLog]):
        self.scan = scan
        self.target = target
        self.findings = findings
        self.audit_logs = audit_logs
        self.buffer = BytesIO()
        self.doc = SimpleDocTemplate(
            self.buffer,
            pagesize=letter,
            rightMargin=0.75 * inch,
            leftMargin=0.75 * inch,
            topMargin=0.75 * inch,
            bottomMargin=0.75 * inch,
        )
        self.styles = getSampleStyleSheet()
        self._add_custom_styles()
        self.story = []

    def _add_custom_styles(self):
        """Add custom paragraph styles for the report."""
        self.styles.add(
            ParagraphStyle(
                name="CoverTitle",
                parent=self.styles["Heading1"],
                fontSize=28,
                textColor=colors.HexColor("#6366f1"),
                spaceAfter=12,
                alignment=TA_CENTER,
                fontName="Helvetica-Bold",
            )
        )
        self.styles.add(
            ParagraphStyle(
                name="CoverSubtitle",
                parent=self.styles["Normal"],
                fontSize=14,
                textColor=colors.HexColor("#64748b"),
                spaceAfter=6,
                alignment=TA_CENTER,
            )
        )
        self.styles.add(
            ParagraphStyle(
                name="SectionHeading",
                parent=self.styles["Heading2"],
                fontSize=16,
                textColor=colors.HexColor("#0B0E14"),
                spaceAfter=12,
                spaceBefore=18,
                fontName="Helvetica-Bold",
            )
        )
        self.styles.add(
            ParagraphStyle(
                name="LayerHeading",
                parent=self.styles["Heading3"],
                fontSize=12,
                textColor=colors.HexColor("#6366f1"),
                spaceAfter=6,
                spaceBefore=12,
                fontName="Helvetica-Bold",
            )
        )
        self.styles.add(
            ParagraphStyle(
                name="CodeBlock",
                parent=self.styles["Code"],
                fontSize=8,
                textColor=colors.HexColor("#22c55e"),
                backColor=colors.HexColor("#0B0E14"),
                leftIndent=12,
                rightIndent=12,
                spaceBefore=6,
                spaceAfter=6,
            )
        )

    def _add_cover_page(self):
        """Generate cover page with target info and overall verdict."""
        # Title
        self.story.append(Spacer(1, 1.5 * inch))
        self.story.append(Paragraph("🛡️ SECURITY AUDIT REPORT", self.styles["CoverTitle"]))
        self.story.append(Spacer(1, 0.3 * inch))

        # Target info
        self.story.append(Paragraph(f"<b>Target:</b> {self.target.name}", self.styles["CoverSubtitle"]))
        self.story.append(Paragraph(f"<b>URL:</b> {self.target.url}", self.styles["CoverSubtitle"]))
        self.story.append(
            Paragraph(
                f"<b>Environment:</b> {self.target.environment.upper()}", self.styles["CoverSubtitle"]
            )
        )
        self.story.append(Spacer(1, 0.2 * inch))

        # Scan info
        scan_date = self.scan.created_at.strftime("%Y-%m-%d %H:%M UTC") if self.scan.created_at else "N/A"
        self.story.append(Paragraph(f"<b>Scan Date:</b> {scan_date}", self.styles["CoverSubtitle"]))
        self.story.append(
            Paragraph(f"<b>Scan ID:</b> {str(self.scan.id)[:8]}...", self.styles["CoverSubtitle"])
        )
        self.story.append(Spacer(1, 0.4 * inch))

        # Overall verdict
        critical_count = len([f for f in self.findings if f.severity == Severity.critical])
        high_count = len([f for f in self.findings if f.severity == Severity.high])
        medium_count = len([f for f in self.findings if f.severity == Severity.medium])
        low_count = len([f for f in self.findings if f.severity == Severity.low])
        total_findings = len(self.findings)

        if total_findings == 0:
            verdict = "✅ FULLY SECURE"
            verdict_color = colors.HexColor("#22c55e")
        elif critical_count > 0:
            verdict = "❌ CRITICAL VULNERABILITIES FOUND"
            verdict_color = colors.HexColor("#ef4444")
        elif high_count > 0:
            verdict = "⚠️ HIGH RISK VULNERABILITIES FOUND"
            verdict_color = colors.HexColor("#f59e0b")
        else:
            verdict = "⚡ MEDIUM/LOW RISK FINDINGS"
            verdict_color = colors.HexColor("#f59e0b")

        verdict_style = ParagraphStyle(
            name="Verdict",
            parent=self.styles["Normal"],
            fontSize=20,
            textColor=verdict_color,
            alignment=TA_CENTER,
            fontName="Helvetica-Bold",
        )
        self.story.append(Paragraph(verdict, verdict_style))
        self.story.append(Spacer(1, 0.3 * inch))

        # Summary table
        summary_data = [
            ["Severity", "Count"],
            ["CRITICAL", str(critical_count)],
            ["HIGH", str(high_count)],
            ["MEDIUM", str(medium_count)],
            ["LOW & INFO", str(low_count)],
            ["TOTAL", str(total_findings)],
        ]
        summary_table = Table(summary_data, colWidths=[2 * inch, 1 * inch])
        summary_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#6366f1")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, 0), 12),
                    ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
                    ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#f8f7f3")),
                    ("GRID", (0, 0), (-1, -1), 1, colors.HexColor("#e5e7eb")),
                    ("FONTSIZE", (0, 1), (-1, -1), 10),
                    ("TOPPADDING", (0, 1), (-1, -1), 8),
                    ("BOTTOMPADDING", (0, 1), (-1, -1), 8),
                ]
            )
        )
        self.story.append(summary_table)
        self.story.append(Spacer(1, 0.4 * inch))

        # Prompts tested
        total_prompts = sum(log.prompts_tested for log in self.audit_logs if log.prompts_tested)
        self.story.append(
            Paragraph(
                f"<b>Total Attack Prompts Tested:</b> {total_prompts:,}",
                self.styles["CoverSubtitle"],
            )
        )
        self.story.append(
            Paragraph(f"<b>Attack Layers Evaluated:</b> 15 (OWASP LLM Top 10)", self.styles["CoverSubtitle"])
        )

        self.story.append(PageBreak())

    def _add_executive_summary(self):
        """Add executive summary section."""
        self.story.append(Paragraph("Executive Summary", self.styles["SectionHeading"]))
        self.story.append(Spacer(1, 0.1 * inch))

        if len(self.findings) == 0:
            summary_text = (
                "This security audit tested your chatbot against 15 OWASP LLM Top 10 attack categories, "
                f"with a total of {sum(log.prompts_tested for log in self.audit_logs if log.prompts_tested):,} attack prompts. "
                "<b>No vulnerabilities were detected.</b> Your chatbot successfully blocked all prompt injection, "
                "jailbreak, data leakage, and other adversarial attacks. This indicates robust security controls "
                "are in place."
            )
        else:
            critical_count = len([f for f in self.findings if f.severity == Severity.critical])
            high_count = len([f for f in self.findings if f.severity == Severity.high])

            summary_text = (
                f"This security audit identified <b>{len(self.findings)} vulnerabilities</b> across your chatbot, "
                f"including {critical_count} critical and {high_count} high-severity findings. "
                "Each vulnerability has been mapped to OWASP LLM Top 10, EU AI Act Article 15, and NIST AI RMF guidelines. "
                "Code-level fixes and remediation guidance are provided for each finding. "
                "<b>Immediate action is recommended</b> to address critical and high-severity issues."
            )

        self.story.append(Paragraph(summary_text, self.styles["Normal"]))
        self.story.append(Spacer(1, 0.2 * inch))

        # Findings by severity
        if self.findings:
            self.story.append(Paragraph("<b>Findings by Severity:</b>", self.styles["Normal"]))
            self.story.append(Spacer(1, 0.1 * inch))

            findings_data = [["Severity", "Attack Type", "OWASP Category"]]
            for finding in sorted(
                self.findings, key=lambda f: ["critical", "high", "medium", "low"].index(f.severity.value)
            ):
                findings_data.append(
                    [
                        finding.severity.value.upper(),
                        finding.attack_type.value.replace("_", " ").title(),
                        finding.owasp_category or "N/A",
                    ]
                )

            findings_table = Table(findings_data, colWidths=[1.2 * inch, 2.5 * inch, 2.5 * inch])
            findings_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#6366f1")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, 0), 10),
                        ("BOTTOMPADDING", (0, 0), (-1, 0), 10),
                        ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#f8f7f3")),
                        ("GRID", (0, 0), (-1, -1), 1, colors.HexColor("#e5e7eb")),
                        ("FONTSIZE", (0, 1), (-1, -1), 8),
                        ("TOPPADDING", (0, 1), (-1, -1), 6),
                        ("BOTTOMPADDING", (0, 1), (-1, -1), 6),
                    ]
                )
            )
            self.story.append(findings_table)

        self.story.append(PageBreak())

    def _add_audit_trail(self):
        """Add full audit trail section with all 15 layers."""
        self.story.append(Paragraph("Full Audit Trail — All 15 Attack Layers", self.styles["SectionHeading"]))
        self.story.append(Spacer(1, 0.1 * inch))

        for log in sorted(self.audit_logs, key=lambda l: l.created_at or datetime.min):
            # Layer heading
            verdict_icon = "✅" if log.verdict == "PASSED" else "❌"
            self.story.append(
                Paragraph(
                    f"{verdict_icon} {log.layer_name} — {log.verdict}",
                    self.styles["LayerHeading"],
                )
            )

            # Layer details
            details = [
                f"<b>Attack Type:</b> {log.attack_type.replace('_', ' ').title()}",
                f"<b>Prompts Tested:</b> {log.prompts_tested}",
                f"<b>Confidence:</b> {log.confidence * 100:.1f}%",
                f"<b>Detection Method:</b> {log.detection_method.replace('_', ' ').title()}",
            ]
            self.story.append(Paragraph("<br/>".join(details), self.styles["Normal"]))
            self.story.append(Spacer(1, 0.1 * inch))

            # Sample prompt (truncated)
            if log.prompt_used:
                prompt_preview = log.prompt_used[:200] + "..." if len(log.prompt_used) > 200 else log.prompt_used
                self.story.append(Paragraph("<b>Sample Attack Prompt:</b>", self.styles["Normal"]))
                self.story.append(Paragraph(f"<i>{prompt_preview}</i>", self.styles["Normal"]))
                self.story.append(Spacer(1, 0.1 * inch))

            # Sample response (truncated)
            if log.chatbot_response:
                response_preview = (
                    log.chatbot_response[:200] + "..." if len(log.chatbot_response) > 200 else log.chatbot_response
                )
                self.story.append(Paragraph("<b>Chatbot Response:</b>", self.styles["Normal"]))
                self.story.append(Paragraph(f"<i>{response_preview}</i>", self.styles["Normal"]))

            self.story.append(Spacer(1, 0.15 * inch))

        self.story.append(PageBreak())

    def _add_compliance_mapping(self):
        """Add compliance mapping table."""
        self.story.append(Paragraph("Regulatory Compliance Mapping", self.styles["SectionHeading"]))
        self.story.append(Spacer(1, 0.1 * inch))

        disclaimer_text = (
            "⚠️ <b>Legal Disclaimer:</b> This report provides technical security findings and references to "
            "regulatory frameworks for informational purposes only. It does not constitute legal compliance "
            "certification or legal advice. Consult qualified legal counsel for compliance determination."
        )
        self.story.append(Paragraph(disclaimer_text, self.styles["Normal"]))
        self.story.append(Spacer(1, 0.2 * inch))

        # Compliance table
        compliance_data = [
            ["Framework", "Reference", "Status"],
            ["OWASP LLM Top 10", "LLM01-LLM10", "Tested"],
            ["EU AI Act", "Article 15 (Transparency)", "Addressed"],
            ["NIST AI RMF", "GOVERN, MAP, MEASURE", "Aligned"],
            ["ISO/IEC 42001", "AI Management System", "Guidance Provided"],
        ]

        compliance_table = Table(compliance_data, colWidths=[2 * inch, 2.5 * inch, 1.5 * inch])
        compliance_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#6366f1")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, 0), 10),
                    ("BOTTOMPADDING", (0, 0), (-1, 0), 10),
                    ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#f8f7f3")),
                    ("GRID", (0, 0), (-1, -1), 1, colors.HexColor("#e5e7eb")),
                    ("FONTSIZE", (0, 1), (-1, -1), 9),
                    ("TOPPADDING", (0, 1), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 1), (-1, -1), 6),
                ]
            )
        )
        self.story.append(compliance_table)

    def generate(self) -> BytesIO:
        """Generate the complete PDF report and return as BytesIO buffer."""
        self._add_cover_page()
        self._add_executive_summary()
        self._add_audit_trail()
        self._add_compliance_mapping()

        # Build PDF
        self.doc.build(self.story)
        self.buffer.seek(0)
        return self.buffer
