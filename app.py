"""hunit – watermark remover + document polisher/humanizer (Streamlit)."""
import hashlib, hmac, io, os, re, secrets, sqlite3
from datetime import datetime

import streamlit as st

st.set_page_config(page_title="hunit", page_icon="✍️", layout="wide")
DB_PATH = os.environ.get("HUNIT_DB", "hunit.db")


# ───────────────────────── database & auth ─────────────────────────
@st.cache_resource
def get_conn():
    c = sqlite3.connect(DB_PATH, check_same_thread=False)
    c.row_factory = sqlite3.Row
    c.executescript(
        """
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL, salt BLOB NOT NULL, pw_hash BLOB NOT NULL,
            created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS history(
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
            filename TEXT, created_at TEXT, report TEXT,
            original_text TEXT, refined_text TEXT,
            refined_docx BLOB, cleaned_name TEXT, cleaned_blob BLOB);
        """
    )
    return c


def _hash(pw, salt):
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 200_000)


def signup(username, pw):
    username = username.strip().lower()
    if not re.fullmatch(r"[a-z0-9_.-]{3,32}", username):
        return "Username: 3–32 chars, letters/numbers/._- only."
    if len(pw) < 8:
        return "Password must be at least 8 characters."
    salt = secrets.token_bytes(16)
    try:
        with get_conn() as c:
            c.execute("INSERT INTO users(username,salt,pw_hash,created_at) VALUES(?,?,?,?)",
                      (username, salt, _hash(pw, salt), datetime.utcnow().isoformat()))
    except sqlite3.IntegrityError:
        return "That username is taken."
    return None


def login(username, pw):
    row = get_conn().execute("SELECT * FROM users WHERE username=?", (username.strip().lower(),)).fetchone()
    if row and hmac.compare_digest(row["pw_hash"], _hash(pw, row["salt"])):
        return {"id": row["id"], "username": row["username"]}
    return None


def auth_screen():
    st.title("✍️ hunit")
    st.caption("Clean, polish and humanize your documents.")
    t_login, t_signup = st.tabs(["Log in", "Sign up"])
    with t_login:
        u = st.text_input("Username", key="li_u")
        p = st.text_input("Password", type="password", key="li_p")
        if st.button("Log in", type="primary"):
            user = login(u, p)
            if user:
                st.session_state.user = user
                st.rerun()
            st.error("Invalid username or password.")
    with t_signup:
        u = st.text_input("Choose a username", key="su_u")
        p = st.text_input("Choose a password (8+ chars)", type="password", key="su_p")
        p2 = st.text_input("Confirm password", type="password", key="su_p2")
        if st.button("Create account"):
            if p != p2:
                st.error("Passwords don't match.")
            elif (err := signup(u, p)):
                st.error(err)
            else:
                st.session_state.user = login(u, p)
                st.rerun()


# ───────────────────────── watermark removal ─────────────────────────
def _line_text(l):
    return " ".join(s["text"] for s in l["spans"]).strip()


def _is_wm_line(l):
    dy = l["dir"][1]
    diagonal = abs(dy) > 0.05
    faint_big = False
    for s in l["spans"]:
        c, size = s["color"], s["size"]
        r, g, b = (c >> 16) & 255, (c >> 8) & 255, c & 255
        if min(r, g, b) >= 170 and size >= 24:
            faint_big = True
    return diagonal or faint_big


def pdf_clean(data, extra_terms):
    import fitz
    doc = fitz.open(stream=data, filetype="pdf")
    counts = {}
    for p in doc:
        found = set()
        for b in p.get_text("dict")["blocks"]:
            for l in b.get("lines", []):
                t = _line_text(l)
                if len(t) >= 3 and _is_wm_line(l):
                    found.add(t)
        for t in found:
            counts[t] = counts.get(t, 0) + 1
    need = max(1, len(doc) // 2)
    detected = [t for t, c in counts.items() if c >= need]
    terms = list(dict.fromkeys(detected + extra_terms))

    pat = re.compile(rb"/Artifact\s*<<[^>]*?/Subtype\s*/Watermark[^>]*?>>\s*BDC.*?EMC", re.S)
    artifacts = annots = 0
    for p in doc:
        for x in p.get_contents():
            s = doc.xref_stream(x)
            n = pat.sub(b"", s)
            if n != s:
                doc.update_stream(x, n)
                artifacts += 1
        for a in list(p.annots() or []):
            if a.type[0] == fitz.PDF_ANNOT_WATERMARK:
                p.delete_annot(a)
                annots += 1
        hit = False
        for t in terms:
            for q in p.search_for(t, quads=True):
                p.add_redact_annot(q)
                hit = True
        if hit:
            p.apply_redactions(images=fitz.PDF_REDACT_IMAGE_NONE)
    out = doc.tobytes(garbage=3, deflate=True)
    report = f"PDF: {artifacts} watermark layer(s), {annots} watermark annotation(s), text removed: {terms or 'none'}"
    return out, terms, report


def pdf_text(data, terms):
    import fitz
    doc = fitz.open(stream=data, filetype="pdf")
    out = []
    for p in doc:
        for b in p.get_text("dict")["blocks"]:
            lines = []
            for l in b.get("lines", []):
                t = _line_text(l)
                for term in terms:
                    t = t.replace(term, "")
                t = t.strip()
                if t and not _is_wm_line(l):
                    lines.append(t)
            if lines:
                out.append(" ".join(lines))
    return "\n\n".join(out)


def docx_clean(data, extra_terms):
    from docx import Document
    doc = Document(io.BytesIO(data))
    shapes = 0
    for sec in doc.sections:
        for part in (sec.header, sec.first_page_header, sec.even_page_header,
                     sec.footer, sec.first_page_footer, sec.even_page_footer):
            if part.is_linked_to_previous:
                continue
            for el in part._element.xpath(".//w:pict | .//w:drawing"):
                xml = el.xml.lower() if hasattr(el, "xml") else ""
                if "watermark" in xml or "textpath" in xml:
                    run = el.getparent()
                    if run is not None and run.getparent() is not None:
                        run.getparent().remove(run)
                        shapes += 1
    def paras():
        yield from doc.paragraphs
        for t in doc.tables:
            for row in t.rows:
                for cell in row.cells:
                    yield from cell.paragraphs
        for sec in doc.sections:
            for part in (sec.header, sec.footer):
                if not part.is_linked_to_previous:
                    yield from part.paragraphs
    for para in paras():
        for r in para.runs:
            for term in extra_terms:
                if term in r.text:
                    r.text = r.text.replace(term, "")
    buf = io.BytesIO()
    doc.save(buf)
    return buf.getvalue(), f"DOCX: {shapes} header/footer watermark shape(s), text removed: {extra_terms or 'none'}"


def docx_text(data):
    from docx import Document
    doc = Document(io.BytesIO(data))
    out = []
    for p in doc.paragraphs:
        if not p.text.strip():
            continue
        m = re.match(r"Heading (\d)", p.style.name or "")
        out.append(("#" * int(m.group(1)) + " " if m else "") + p.text.strip())
    for t in doc.tables:
        for row in t.rows:
            out.append(" | ".join(c.text.strip() for c in row.cells))
    return "\n\n".join(out)


# ───────────────────────── polish & humanize ─────────────────────────
SYSTEM = """You are a meticulous human editor. Rewrite the user's document text so it is:
- grammatically perfect (spelling, punctuation, tense, agreement) and well structured (logical order, clear headings, short paragraphs, lists where helpful);
- natural and human: plain, specific wording, varied sentence length and rhythm, active voice, no filler, no stock phrases or corporate clichés, no robotic transitions.
Rules: keep every fact, number, name, quote and the author's meaning; never invent information; drop stray page numbers, running headers/footers and leftover watermark text. Match the requested tone. Output ONLY the rewritten document in Markdown (# headings, - bullets, **bold**), no commentary."""


def chunk(text, limit=7000):
    parts, cur = [], ""
    for para in text.split("\n\n"):
        if cur and len(cur) + len(para) > limit:
            parts.append(cur)
            cur = ""
        cur += ("\n\n" if cur else "") + para
    if cur:
        parts.append(cur)
    return parts


def refine(text, tone, progress):
    import anthropic
    key = st.secrets.get("ANTHROPIC_API_KEY", os.environ.get("ANTHROPIC_API_KEY"))
    if not key:
        raise RuntimeError("ANTHROPIC_API_KEY is not configured (see README).")
    model = st.secrets.get("HUNIT_MODEL", "claude-sonnet-5-5")
    client = anthropic.Anthropic(api_key=key)
    pieces = chunk(text)
    out = []
    for i, piece in enumerate(pieces, 1):
        progress.progress((i - 1) / len(pieces), text=f"Polishing part {i} of {len(pieces)}…")
        msg = client.messages.create(
            model=model, max_tokens=8000, system=SYSTEM,
            messages=[{"role": "user", "content":
                       f"Tone: {tone}. This is part {i} of {len(pieces)} of one document.\n\n<document>\n{piece}\n</document>"}],
        )
        out.append("".join(b.text for b in msg.content if b.type == "text").strip())
    progress.progress(1.0, text="Done")
    return "\n\n".join(out)


def md_to_docx(md):
    from docx import Document
    doc = Document()

    def add_runs(par, text):
        for chunk_ in re.split(r"(\*\*[^*]+\*\*)", text):
            if chunk_.startswith("**") and chunk_.endswith("**"):
                par.add_run(chunk_[2:-2]).bold = True
            elif chunk_:
                par.add_run(chunk_)

    for line in md.splitlines():
        s = line.rstrip()
        if not s.strip():
            continue
        if m := re.match(r"(#{1,4})\s+(.*)", s):
            doc.add_heading(m.group(2), level=len(m.group(1)))
        elif m := re.match(r"\s*[-*•]\s+(.*)", s):
            add_runs(doc.add_paragraph(style="List Bullet"), m.group(1))
        elif m := re.match(r"\s*\d+[.)]\s+(.*)", s):
            add_runs(doc.add_paragraph(style="List Number"), m.group(1))
        else:
            add_runs(doc.add_paragraph(), s)
    buf = io.BytesIO()
    doc.save(buf)
    return buf.getvalue()


# ───────────────────────── app screens ─────────────────────────
def process(name, data, extra_terms, tone, remove_wm, progress):
    ext = name.rsplit(".", 1)[-1].lower()
    cleaned, cleaned_name, report = None, None, "Watermark removal skipped."
    if ext == "pdf":
        if remove_wm:
            cleaned, terms, report = pdf_clean(data, extra_terms)
            cleaned_name = f"clean_{name}"
            text = pdf_text(cleaned, terms)
        else:
            text = pdf_text(data, [])
    elif ext == "docx":
        if remove_wm:
            cleaned, report = docx_clean(data, extra_terms)
            cleaned_name = f"clean_{name}"
            data = cleaned
        text = docx_text(data)
    else:
        text = data.decode("utf-8", errors="ignore")
        for t in (extra_terms if remove_wm else []):
            text = text.replace(t, "")
        report = f"Text: removed {extra_terms or 'nothing'}" if remove_wm else report
    if not text.strip():
        raise RuntimeError("No readable text found (scanned/image-only documents aren't supported).")
    refined = refine(text, tone, progress)
    return text, refined, report, cleaned_name, cleaned


def new_doc_tab(user):
    up = st.file_uploader("Upload a document", type=["pdf", "docx", "txt", "md"])
    c1, c2 = st.columns(2)
    tone = c1.selectbox("Tone", ["Natural & professional", "Conversational", "Academic", "Friendly & warm"])
    remove_wm = c2.checkbox("Remove watermarks", value=True)
    extra = st.text_input("Watermark text to remove (optional, comma-separated)", placeholder="CONFIDENTIAL, DRAFT")
    st.caption("Only use on documents you own or have permission to edit.")
    if st.button("Refine document", type="primary", disabled=up is None):
        terms = [t.strip() for t in extra.split(",") if t.strip()]
        bar = st.progress(0, text="Starting…")
        try:
            with st.spinner("Working…"):
                orig, refined, report, cname, cblob = process(up.name, up.getvalue(), terms, tone, remove_wm, bar)
            docx_bytes = md_to_docx(refined)
            with get_conn() as c:
                c.execute("""INSERT INTO history(user_id,filename,created_at,report,original_text,refined_text,
                             refined_docx,cleaned_name,cleaned_blob) VALUES(?,?,?,?,?,?,?,?,?)""",
                          (user["id"], up.name, datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
                           report, orig, refined, docx_bytes, cname, cblob))
            st.success("Done — saved to your history.")
            st.info(report)
            st.markdown(refined)
            st.download_button("⬇ Refined (.docx)", docx_bytes, f"refined_{up.name.rsplit('.',1)[0]}.docx", key="new_docx")
            if cblob:
                st.download_button("⬇ Watermark-free original", cblob, cname, key="new_clean")
        except Exception as e:
            bar.empty()
            st.error(str(e))


def history_tab(user):
    rows = get_conn().execute(
        "SELECT id,filename,created_at,report FROM history WHERE user_id=? ORDER BY id DESC", (user["id"],)).fetchall()
    if not rows:
        st.info("No documents yet.")
    for r in rows:
        with st.expander(f"{r['filename']} — {r['created_at']}"):
            full = get_conn().execute("SELECT * FROM history WHERE id=? AND user_id=?", (r["id"], user["id"])).fetchone()
            st.caption(full["report"])
            t1, t2 = st.tabs(["Refined", "Original text"])
            t1.markdown(full["refined_text"])
            t2.text(full["original_text"])
            c1, c2, c3 = st.columns(3)
            c1.download_button("⬇ Refined (.docx)", full["refined_docx"], f"refined_{r['id']}.docx", key=f"d{r['id']}")
            if full["cleaned_blob"]:
                c2.download_button("⬇ Clean original", full["cleaned_blob"], full["cleaned_name"], key=f"c{r['id']}")
            if c3.button("🗑 Delete", key=f"x{r['id']}"):
                with get_conn() as c:
                    c.execute("DELETE FROM history WHERE id=? AND user_id=?", (r["id"], user["id"]))
                st.rerun()


def main():
    if "user" not in st.session_state:
        auth_screen()
        return
    user = st.session_state.user
    with st.sidebar:
        st.title("✍️ hunit")
        st.write(f"Signed in as **{user['username']}**")
        if st.button("Log out"):
            del st.session_state["user"]
            st.rerun()
    t_new, t_hist = st.tabs(["New document", "History"])
    with t_new:
        new_doc_tab(user)
    with t_hist:
        history_tab(user)


main()
