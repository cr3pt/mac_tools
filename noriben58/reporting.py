import csv, json, html

def export_session(session, version, profile, host_info=None):
    with (session.session_dir / 'timeline.csv').open('w', newline='', encoding='utf-8') as f:
        w = csv.writer(f); w.writerow(['source','category','event','vm','mitre'])
        for ev in session.timeline: w.writerow([ev.source, ev.category, ev.event, ev.vm, ev.mitre])
    with (session.session_dir / 'findings.csv').open('w', newline='', encoding='utf-8') as f:
        w = csv.writer(f); w.writerow(['type','description','score','vm','mitre'])
        for x in session.static_findings + session.dynamic_findings: w.writerow([x.kind, x.description, x.score, x.vm, x.mitre])
    (session.session_dir / 'session_summary.json').write_text(json.dumps({
        'version': version, 'sample': str(session.sample_file), 'profile': profile,
        'static_score': session.static_score, 'dynamic_score': session.dynamic_score,
        'sigma_hits': session.sigma_hits, 'mitre_hits': session.mitre_hits, 'errors': session.errors,
        'host_info': host_info or {}
    }, indent=2, ensure_ascii=False), encoding='utf-8')
    total = min(100, session.static_score + session.dynamic_score // 2)
    sigmas = ''.join(f'<li>{html.escape(x)}</li>' for x in session.sigma_hits) or '<li>Brak</li>'
    mitres = ''.join(f'<li>{html.escape(x)}</li>' for x in sorted(set(session.mitre_hits))) or '<li>Brak</li>'
    timeline = ''.join(f'<tr><td>{html.escape(e.vm)}</td><td>{html.escape(e.source)}</td><td>{html.escape(e.category)}</td><td>{html.escape(e.event)}</td><td>{html.escape(e.mitre)}</td></tr>' for e in session.timeline[:150]) or '<tr><td colspan="5">Brak</td></tr>'
    findings = ''.join(f'<tr><td>{html.escape(x.kind)}</td><td>{html.escape(x.vm)}</td><td>{html.escape(x.description)}</td><td>{x.score}</td><td>{html.escape(x.mitre)}</td></tr>' for x in session.static_findings + session.dynamic_findings) or '<tr><td colspan="5">Brak</td></tr>'
    host_block = html.escape(json.dumps(host_info or {}, ensure_ascii=False))
    report = session.session_dir / f'REPORT_{session.sample_id}.html'
    report.write_text(f'''<!doctype html><html lang="pl"><head><meta charset="utf-8"><title>Report</title><style>body{{font-family:Arial,sans-serif;background:#0b1220;color:#e5e7eb;padding:24px}}.card{{background:#111827;border:1px solid #374151;border-radius:12px;padding:16px;margin:12px 0}}h1,h2{{color:#93c5fd}}.score{{font-size:28px;font-weight:bold;color:#fca5a5}}table{{width:100%;border-collapse:collapse}}td,th{{border-bottom:1px solid #374151;padding:8px;text-align:left;vertical-align:top}}code{{white-space:pre-wrap}}</style></head><body><h1>Noriben QEMU Sandbox 5.8</h1><div class='card'><p>Próbka: {html.escape(str(session.sample_file))}</p><p>Profil: {html.escape(profile)}</p><p>Wynik: <span class='score'>{total}/100</span></p></div><div class='card'><h2>Host</h2><code>{host_block}</code></div><div class='card'><h2>MITRE</h2><ul>{mitres}</ul></div><div class='card'><h2>SIGMA</h2><ul>{sigmas}</ul></div><div class='card'><h2>Findings</h2><table><thead><tr><th>Typ</th><th>VM</th><th>Opis</th><th>Score</th><th>MITRE</th></tr></thead><tbody>{findings}</tbody></table></div><div class='card'><h2>Timeline</h2><table><thead><tr><th>VM</th><th>Źródło</th><th>Kategoria</th><th>Zdarzenie</th><th>MITRE</th></tr></thead><tbody>{timeline}</tbody></table></div></body></html>''', encoding='utf-8')
    session.reports.append(report)
