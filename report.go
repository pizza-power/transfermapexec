package main

import (
	"encoding/hex"
	"html/template"
	"os"
	"time"
)

// reportModel is the view model rendered into the HTML report. Every display
// string is computed here so the template stays logic-free.
type reportModel struct {
	Generated string
	Host      string
	Payload   reportPayload
	Note      string
	Total     int
	OK        int
	Failed    int
	Targets   []reportTarget
}

type reportPayload struct {
	Kind   string
	Name   string
	Size   string
	SHA256 string
}

type reportTarget struct {
	Label   string // e.g. "IPv4 192.168.1.50"
	Family  string
	Target  string
	OK      int
	Failed  int
	Total   int
	OKPct   int
	FailPct int
	Rows    []reportRow
}

type reportRow struct {
	Method   string
	Family   string // "IPv4" / "IPv6"
	Endpoint string
	OK       bool
	Time     string
	Rate     string
	Info     string // detail on success, the error on failure
}

// writeHTMLReport renders the client's results as a self-contained HTML file.
func writeHTMLReport(path, host string, h header, note string, results []result, targets []target, now time.Time) error {
	m := buildReportModel(host, h, note, results, targets, now)
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	if err := reportTemplate.Execute(f, m); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func buildReportModel(host string, h header, note string, results []result, targets []target, now time.Time) reportModel {
	m := reportModel{
		Generated: now.Format("2006-01-02 15:04:05 MST"),
		Host:      host,
		Note:      note,
		Payload: reportPayload{
			Kind:   h.kindName(),
			Name:   h.name,
			Size:   formatBytes(int64(h.payloadLen)),
			SHA256: hex.EncodeToString(h.sum[:]),
		},
	}
	for _, t := range targets {
		rt := reportTarget{
			Label:  t.family() + " " + t.ip.String(),
			Family: t.family(),
			Target: t.ip.String(),
		}
		for _, r := range results {
			if r.Target != t.ip.String() || r.Family != t.family() {
				continue
			}
			row := reportRow{
				Method:   r.Method,
				Family:   r.Family,
				Endpoint: r.Endpoint,
				OK:       r.OK,
				Time:     formatDuration(r.Seconds),
			}
			if r.OK {
				row.Info = r.Detail
				if r.Seconds > 0 {
					row.Rate = formatBytes(int64(float64(r.Bytes)/r.Seconds)) + "/s"
				}
				rt.OK++
				m.OK++
			} else {
				row.Info = r.Error
				rt.Failed++
				m.Failed++
			}
			rt.Rows = append(rt.Rows, row)
			rt.Total++
			m.Total++
		}
		if rt.Total > 0 {
			rt.OKPct = 100 * rt.OK / rt.Total
			rt.FailPct = 100 - rt.OKPct
		}
		m.Targets = append(m.Targets, rt)
	}
	return m
}

var reportTemplate = template.Must(template.New("report").Parse(reportHTML))

const reportHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>transfermapexec report</title>
<style>
:root{
  --bg:#f5f6f8; --card:#ffffff; --fg:#1b1f24; --muted:#5b6672; --border:#e4e8ec;
  --ok:#157a45; --ok-bg:#e7f6ee; --fail:#c0392b; --fail-bg:#fcebe9;
  --accent:#2d6cdf; --head:#f0f2f5;
  --mono:ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace;
}
@media (prefers-color-scheme:dark){
  :root{
    --bg:#0e1216; --card:#161b21; --fg:#e6e9ed; --muted:#9aa5b1; --border:#273039;
    --ok:#4ad08a; --ok-bg:#122a1d; --fail:#ff7b72; --fail-bg:#2a1512;
    --accent:#5b9bff; --head:#1b222a;
  }
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
  font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;}
.wrap{max-width:1040px;margin:0 auto;padding:36px 20px 72px;}
h1{font-size:22px;margin:0 0 2px;letter-spacing:-.01em;}
.sub{color:var(--muted);margin:0 0 26px;font-size:13.5px;}
.card{background:var(--card);border:1px solid var(--border);border-radius:12px;
  padding:20px 22px;margin-bottom:22px;}
.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px 26px;}
.meta div{min-width:0;}
.meta .k{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.04em;margin-bottom:2px;}
.meta .v{font-size:14.5px;word-break:break-word;}
.mono{font-family:var(--mono);}
.sha{font-family:var(--mono);font-size:12px;color:var(--muted);word-break:break-all;}
.note{margin-top:14px;padding:10px 14px;border-left:3px solid var(--accent);
  background:color-mix(in srgb,var(--accent) 8%,transparent);border-radius:0 8px 8px 0;
  color:var(--fg);font-size:13.5px;}
.totals{display:flex;gap:28px;flex-wrap:wrap;align-items:baseline;}
.totals .big{font-size:30px;font-weight:650;line-height:1;}
.totals .big small{font-size:14px;font-weight:500;color:var(--muted);}
.totals .ok{color:var(--ok);} .totals .fail{color:var(--fail);}
.tgt-head{display:flex;justify-content:space-between;align-items:center;gap:16px;
  flex-wrap:wrap;margin-bottom:12px;}
.tgt-head h2{font-size:16px;margin:0;}
.tgt-head .count{color:var(--muted);font-size:13.5px;}
.bar{height:8px;border-radius:5px;background:var(--fail);overflow:hidden;margin-bottom:16px;
  display:flex;}
.bar > span{display:block;height:100%;background:var(--ok);}
.filters{display:flex;gap:8px;margin-bottom:14px;flex-wrap:wrap;}
.filters button{font:inherit;font-size:13px;cursor:pointer;color:var(--fg);
  background:var(--card);border:1px solid var(--border);border-radius:999px;padding:4px 13px;}
.filters button[aria-pressed="true"]{background:var(--accent);border-color:var(--accent);color:#fff;}
table{width:100%;border-collapse:collapse;font-size:13.5px;}
th{text-align:left;font-weight:600;color:var(--muted);font-size:11.5px;text-transform:uppercase;
  letter-spacing:.04em;padding:6px 10px;border-bottom:1px solid var(--border);white-space:nowrap;}
td{padding:8px 10px;border-bottom:1px solid var(--border);vertical-align:top;}
tbody tr:last-child td{border-bottom:none;}
td.num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap;color:var(--muted);}
.pill{display:inline-block;font-size:11.5px;font-weight:600;padding:2px 9px;border-radius:999px;
  letter-spacing:.02em;}
.pill.ok{color:var(--ok);background:var(--ok-bg);}
.pill.fail{color:var(--fail);background:var(--fail-bg);}
td.method{font-family:var(--mono);font-weight:600;white-space:nowrap;}
td.ep{font-family:var(--mono);color:var(--muted);white-space:nowrap;}
td.info{color:var(--muted);}
tr.fail td.info{color:var(--fail);}
.wrap.hide-ok tr[data-ok="1"],.wrap.hide-fail tr[data-ok="0"]{display:none;}
footer{color:var(--muted);font-size:12.5px;text-align:center;margin-top:8px;}
</style>
</head>
<body>
<div class="wrap" id="wrap">
  <h1>transfermapexec report</h1>
  <p class="sub">Generated {{.Generated}}</p>

  <div class="card">
    <div class="meta">
      <div><div class="k">Server</div><div class="v mono">{{.Host}}</div></div>
      <div><div class="k">Payload</div><div class="v">{{.Payload.Kind}}{{if .Payload.Name}} &middot; <span class="mono">{{.Payload.Name}}</span>{{end}}</div></div>
      <div><div class="k">Size</div><div class="v">{{.Payload.Size}}</div></div>
      <div style="grid-column:1/-1"><div class="k">SHA-256</div><div class="v sha">{{.Payload.SHA256}}</div></div>
    </div>
    {{if .Note}}<div class="note">{{.Note}}</div>{{end}}
  </div>

  <div class="card">
    <div class="totals">
      <div class="big"><span>{{.Total}}</span> <small>transfers</small></div>
      <div class="big ok"><span>{{.OK}}</span> <small>worked</small></div>
      <div class="big fail"><span>{{.Failed}}</span> <small>failed</small></div>
    </div>
  </div>

  <div class="filters" role="group" aria-label="Filter rows">
    <button type="button" data-filter="all" aria-pressed="true">All</button>
    <button type="button" data-filter="ok">Worked only</button>
    <button type="button" data-filter="fail">Failed only</button>
  </div>

  {{range .Targets}}
  <div class="card">
    <div class="tgt-head">
      <h2 class="mono">{{.Label}}</h2>
      <div class="count">{{.OK}}/{{.Total}} worked</div>
    </div>
    <div class="bar" title="{{.OKPct}}% worked"><span style="width:{{.OKPct}}%"></span></div>
    <table>
      <thead>
        <tr><th>Status</th><th>Method</th><th>Endpoint</th><th>Time</th><th>Rate</th><th>Detail / error</th></tr>
      </thead>
      <tbody>
        {{range .Rows}}
        <tr class="{{if .OK}}ok{{else}}fail{{end}}" data-ok="{{if .OK}}1{{else}}0{{end}}">
          <td>{{if .OK}}<span class="pill ok">ok</span>{{else}}<span class="pill fail">FAIL</span>{{end}}</td>
          <td class="method">{{.Method}}</td>
          <td class="ep">{{.Endpoint}}</td>
          <td class="num">{{.Time}}</td>
          <td class="num">{{.Rate}}</td>
          <td class="info">{{.Info}}</td>
        </tr>
        {{end}}
      </tbody>
    </table>
  </div>
  {{end}}

  <footer>Generated by transfermapexec</footer>
</div>
<script>
(function(){
  var wrap=document.getElementById('wrap');
  var btns=document.querySelectorAll('.filters button');
  btns.forEach(function(b){
    b.addEventListener('click',function(){
      btns.forEach(function(x){x.setAttribute('aria-pressed',x===b?'true':'false');});
      wrap.classList.remove('hide-ok','hide-fail');
      if(b.dataset.filter==='ok')wrap.classList.add('hide-fail');
      if(b.dataset.filter==='fail')wrap.classList.add('hide-ok');
    });
  });
})();
</script>
</body>
</html>
`
