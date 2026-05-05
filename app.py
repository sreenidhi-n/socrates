"""SOCrates — Gradio Frontend.

Entry point for the Hugging Face Space deployment.
"""

import gradio as gr

from socrates.crew import run


def analyze_cve(cve_query: str) -> tuple[str, str, str]:
    """Run SOCrates pipeline and return results for each tab.

    Returns:
        Tuple of (full_report, status_message, raw_query)
    """
    if not cve_query.strip():
        return "Please enter a CVE ID or keyword.", "", ""

    try:
        report = run(cve_query.strip())
        return report, "✅ Analysis complete", cve_query
    except Exception as e:
        return f"❌ Error during analysis: {e}", f"❌ Failed: {e}", cve_query


def build_app() -> gr.Blocks:
    """Build the Gradio interface."""
    with gr.Blocks(
        title="SOCrates — Autonomous SOC Analyst",
        theme=gr.themes.Soft(),
    ) as app:
        gr.Markdown(
            """
            # 🏛️ SOCrates
            ### *The wisest analyst in your SOC — and it never sleeps.*

            Enter a CVE ID (e.g., `CVE-2024-3400`) or a keyword to search for vulnerabilities.
            SOCrates will analyze the threat, simulate the attack path, and generate an incident response report.

            **Agents:** Scout (threat intel) → Chaos Gremlin (attack simulation) → Coroner (IR report)
            """
        )

        with gr.Row():
            query_input = gr.Textbox(
                label="CVE ID or Search Keyword",
                placeholder="CVE-2024-3400",
                scale=4,
            )
            run_btn = gr.Button("🔍 Analyze", variant="primary", scale=1)

        status = gr.Textbox(label="Status", interactive=False)

        report_output = gr.Markdown(label="Incident Response Report")

        run_btn.click(
            fn=analyze_cve,
            inputs=[query_input],
            outputs=[report_output, status, query_input],
        )

        query_input.submit(
            fn=analyze_cve,
            inputs=[query_input],
            outputs=[report_output, status, query_input],
        )

        gr.Markdown(
            """
            ---
            *Built by **git happens** for the AMD x LabLab.ai Developer Hackathon (May 2026).*
            *Powered by Llama + Qwen on AMD Instinct MI300X via vLLM.*
            """
        )

    return app


if __name__ == "__main__":
    app = build_app()
    app.launch(server_name="0.0.0.0", server_port=7860)
