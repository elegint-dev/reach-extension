// Panel-width harness: serve the tree (python3 -m http.server) and open
// tests/panel/harness.html; sweep4(platform, indexes, openDetails) walks
// routes.json in the 320 px frame and reports the first viewport per route.
// openDetails opens every <details> (the paste fold included) for the
// overflow sweep, C7; a caller reading the first h2's position for C1
// passes openDetails=false, since C1 is the landing state with drawers
// closed, not an analyst's own open.
window.R = null;
fetch('routes.json').then(r => r.json()).then(j => { window.R = j; });
window.sweep4 = async function (platform, idxs, openDetails) {
  const f = document.getElementById('a');
  const out = [];
  for (const i of idxs) {
    const r = window.R[platform][i];
    f.contentWindow.location.hash = r;
    await new Promise((res) => setTimeout(res, 900));
    const d = f.contentDocument, w = f.contentWindow;
    w.scrollTo(0, 0);
    if (openDetails) d.querySelectorAll('details').forEach((x) => { x.open = true; });
    const rect = (el) => { if (!el) return null; const b = el.getBoundingClientRect(); return [Math.round(b.top), Math.round(b.bottom)]; };
    const main = d.querySelector('main');
    const h1 = d.querySelector('main h1') || d.querySelector('h1');
    const h2s = [...d.querySelectorAll('main h2')].map((h) => h.textContent.trim().slice(0, 50) + '@' + rect(h)[0]);
    const acts = [...(main ? main.querySelectorAll('a,button') : [])].filter((a) => a.getBoundingClientRect().height > 0).slice(0, 3).map((a) => a.textContent.trim().slice(0, 25) + '@' + rect(a)[1]);
    const page = d.querySelector('.r-page');
    const above = [...page.children].filter((e) => e !== main).map((e) => (e.className || '').toString().split(' ')[0] + ':' + rect(e) + (e.tagName === 'DETAILS' ? (e.open ? 'o' : 'c') : ''));
    const text = main ? (main.innerText || '').trim().slice(0, 200).replace(/\n+/g, ' | ') : '';
    out.push({ i, title: h1 ? h1.textContent.trim().slice(0, 40) : null, h1y: rect(h1), mainTop: rect(main) && rect(main)[0], above, h2s, acts, text, scrollH: d.documentElement.scrollHeight });
  }
  return out;
};
