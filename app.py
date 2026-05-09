"""SOCrates — Gradio Frontend.

Entry point for the Hugging Face Space deployment.
"""

import tempfile
from collections.abc import Generator
from pathlib import Path

import gradio as gr

from socrates.crew import run_streaming

_WAIT = "*(waiting...)*"
_SCOUT_THINKING = "🔍 *Scout is fetching live threat intel from NVD...*"
_ADVERSARY_THINKING = "☠️ *Adversary is simulating the attack path...*"
_CORONER_THINKING = "📋 *Coroner is writing the MITRE ATT&CK-mapped IR report...*"


def _fmt_metrics(metrics: dict) -> str:
    elapsed = metrics.get("elapsed", 0)
    tokens = metrics.get("tokens", 0)
    token_str = f"{tokens:,} tokens | " if tokens else ""
    return f"⏱ {elapsed:.1f}s | 🔢 {token_str}💰 $0.00 — ran entirely on AMD Instinct MI300X"


def stream_analyze_cve(
    cve_query: str,
) -> Generator[tuple[str, str, str, str, str, str], None, None]:
    """Stream SOCrates results as each agent works.

    Yields:
        (scout, kill_chain, ir_report, status, metrics, trace) — updated live.
    """
    if not cve_query.strip():
        msg = "Please enter a CVE ID (e.g. CVE-2024-3400) or a keyword."
        yield msg, msg, msg, "⚠️ No input provided", "", ""
        return

    yield (
        _SCOUT_THINKING, _WAIT, _WAIT,
        "🔍 Step 1/3 — Scout fetching CVE intel...", "", "",
    )

    try:
        for scout, adversary, coroner, metrics, trace in run_streaming(cve_query.strip()):
            completed = sum(1 for x in (scout, adversary, coroner) if x)
            metrics_str = _fmt_metrics(metrics) if metrics else ""

            if completed == 0:
                yield (
                    _SCOUT_THINKING, _WAIT, _WAIT,
                    "🔍 Step 1/3 — Scout fetching CVE intel...",
                    metrics_str, trace,
                )
            elif completed == 1:
                yield (
                    scout, _ADVERSARY_THINKING, _WAIT,
                    "☠️ Step 2/3 — Adversary simulating attack path...",
                    metrics_str, trace,
                )
            elif completed == 2:
                yield (
                    scout, adversary, _CORONER_THINKING,
                    "📋 Step 3/3 — Coroner writing IR report...",
                    metrics_str, trace,
                )
            elif completed == 3:
                yield scout, adversary, coroner, "✅ Analysis complete", metrics_str, trace

    except Exception as e:
        err = f"❌ Pipeline error: {e}"
        yield err, err, err, f"❌ Failed: {e}", "", ""


def prepare_report_download(cve_query: str, report_md: str) -> str | None:
    """Write the IR report to a temp file and return the path for download."""
    if not report_md or report_md.startswith("*("):
        return None
    cve_slug = cve_query.strip().upper().replace(" ", "_") or "report"
    tmp = tempfile.NamedTemporaryFile(
        mode="w",
        suffix=".md",
        prefix=f"socrates_{cve_slug}_",
        delete=False,
        encoding="utf-8",
    )
    tmp.write(f"# SOCrates IR Report — {cve_slug}\n\n")
    tmp.write(report_md)
    tmp.close()
    return tmp.name


def build_app() -> gr.Blocks:
    """Build the Gradio interface."""
    with gr.Blocks(title="SOCrates — Autonomous SOC Analyst") as app:
        gr.Markdown(
            """
            # 🏛️ SOCrates
            ### *Every CVE deserves an interrogation.*

            Enter a CVE ID (e.g., `CVE-2024-3400`) or a keyword to search for vulnerabilities.
            SOCrates fetches live threat intel, simulates the full attack kill chain,
            and generates a MITRE ATT&CK-mapped incident response report.

            **Pipeline:** 🔍 Scout → ☠️ Adversary → 📋 Coroner
            """
        )

        with gr.Row():
            query_input = gr.Textbox(
                label="CVE ID or Search Keyword",
                placeholder="CVE-2024-21762",
                scale=4,
            )
            run_btn = gr.Button("🔍 Analyze", variant="primary", scale=1)

        with gr.Row():
            status_box = gr.Textbox(
                label="Pipeline Status",
                value="Ready — enter a CVE ID above and click Analyze.",
                interactive=False,
                scale=3,
            )
            metrics_box = gr.Textbox(
                label="Run Metrics",
                value="",
                interactive=False,
                scale=2,
            )

        with gr.Tabs():
            with gr.Tab("🔍 Scout Intel"):
                gr.Markdown(
                    "*Live CVE data from NVD — CVSS score, CISA KEV status, affected systems.*"
                )
                scout_output = gr.Markdown(value=_WAIT)

            with gr.Tab("☠️ Kill Chain"):
                gr.Markdown(
                    "*Simulated attack path — threat actor context, phase-by-phase kill chain, real-world tools, and CVE chaining.*"
                )
                adversary_output = gr.Markdown(value=_WAIT)

            with gr.Tab("📋 IR Report"):
                gr.Markdown(
                    "*MITRE ATT&CK-mapped IR report with valid Sigma detection rules and effort-labeled remediation steps.*"
                )
                coroner_output = gr.Markdown(value=_WAIT)
                with gr.Row():
                    download_btn = gr.DownloadButton(
                        label="📥 Download Report (.md)",
                        variant="secondary",
                        visible=False,
                    )

            with gr.Tab("🧠 Agent Trace"):
                gr.Markdown(
                    "*Live agent reasoning — tool calls, intermediate thoughts, and handoffs between agents.*"
                )
                trace_output = gr.Markdown(
                    value="*(trace will appear here during analysis...)*",
                )

        _outputs = [
            scout_output, adversary_output, coroner_output,
            status_box, metrics_box, trace_output,
        ]

        def _stream_and_show_download(cve_query: str):
            """Wrapper that streams results and makes the download button visible on completion."""
            last_coroner = ""
            for vals in stream_analyze_cve(cve_query):
                scout, adversary, coroner, status, metrics, trace = vals
                if coroner and not coroner.startswith("*("):
                    last_coroner = coroner
                yield scout, adversary, coroner, status, metrics, trace, gr.update(visible=False)

            # Final yield: show download button if we have a report
            if last_coroner:
                file_path = prepare_report_download(cve_query, last_coroner)
                yield scout, adversary, last_coroner, status, metrics, trace, gr.update(
                    visible=True, value=file_path
                )

        _all_outputs = _outputs + [download_btn]

        run_btn.click(fn=_stream_and_show_download, inputs=[query_input], outputs=_all_outputs)
        query_input.submit(fn=_stream_and_show_download, inputs=[query_input], outputs=_all_outputs)

        gr.Markdown(
            """
            ---
            *Built by **git happens** for the AMD x LabLab.ai Developer Hackathon (May 2026).*
            *Powered by Llama 3.3 70B + Qwen 2.5 72B on AMD Instinct MI300X (192GB VRAM) via Ollama.*
            """
        )

    return app


if __name__ == "__main__":
    app = build_app()
    app.launch(server_name="0.0.0.0", server_port=7860, theme=gr.themes.Soft())
