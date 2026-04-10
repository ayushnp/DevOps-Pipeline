# app.py
from flask import Flask, request, render_template_string, send_file, url_for
import base64, io, os, datetime






app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2MB upload limit

# -------------------------------------------------------------------------
# 1. BUILDER PAGE (The Form) - High-End Tech UI with 3D Background
# -------------------------------------------------------------------------
INDEX_HTML = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Aura | Portfolio Builder</title>
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;500;700&family=Inter:wght@300;400;600&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #030014;
      --glass: rgba(255, 255, 255, 0.03);
      --glass-border: rgba(255, 255, 255, 0.1);
      --accent: #a855f7; /* Purple Neon */
      --accent-sec: #3b82f6; /* Blue Neon */
      --text: #e2e8f0;
      --muted: #94a3b8;
    }

    /* GLOBAL RESET & ANIMATION */
    * { box-sizing: border-box; outline: none; }
    body {
      font-family: 'Inter', sans-serif;
      background: var(--bg);
      color: var(--text);
      margin: 0;
      min-height: 100vh;
      overflow-x: hidden;
      position: relative;
    }

    /* ANIMATED BACKGROUND BLOBS */
    .orb {
      position: absolute;
      border-radius: 50%;
      filter: blur(100px);
      z-index: -1;
      opacity: 0.6;
      animation: float 10s infinite ease-in-out alternate;
    }
    .orb-1 { width: 400px; height: 400px; background: var(--accent); top: -100px; left: -100px; }
    .orb-2 { width: 500px; height: 500px; background: var(--accent-sec); bottom: -100px; right: -100px; animation-delay: -5s; }

    @keyframes float {
      0% { transform: translate(0, 0); }
      100% { transform: translate(30px, 50px); }
    }

    .container {
      max-width: 1200px;
      margin: 0 auto;
      padding: 40px 20px;
      display: grid;
      grid-template-columns: 1fr 450px;
      gap: 40px;
      align-items: start;
      position: relative;
      z-index: 10;
    }

    /* LEFT SIDE: HERO & INFO */
    .hero-content {
      padding-top: 40px;
    }
    h1 {
      font-family: 'Space Grotesk', sans-serif;
      font-size: 4rem;
      line-height: 1;
      background: linear-gradient(to right, #fff, #94a3b8);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      margin: 0 0 20px 0;
      animation: slideDown 0.8s ease-out;
    }
    .subhead {
      font-size: 1.1rem;
      color: var(--muted);
      line-height: 1.6;
      max-width: 500px;
      margin-bottom: 40px;
      animation: fadeIn 1s ease-out 0.3s backwards;
    }

    /* 3D CUBE ANIMATION (CSS ONLY) */
    .scene {
      width: 200px;
      height: 200px;
      perspective: 600px;
      margin-top: 60px;
      animation: fadeIn 2s ease-out 0.5s backwards;
    }
    .cube {
      width: 100%;
      height: 100%;
      position: relative;
      transform-style: preserve-3d;
      animation: rotateCube 15s infinite linear;
    }
    .face {
      position: absolute;
      width: 200px;
      height: 200px;
      border: 2px solid rgba(168, 85, 247, 0.5);
      background: rgba(168, 85, 247, 0.05);
      box-shadow: 0 0 20px rgba(168, 85, 247, 0.2);
    }
    .front  { transform: rotateY(  0deg) translateZ(100px); }
    .back   { transform: rotateY(180deg) translateZ(100px); }
    .right  { transform: rotateY( 90deg) translateZ(100px); }
    .left   { transform: rotateY(-90deg) translateZ(100px); }
    .top    { transform: rotateX( 90deg) translateZ(100px); }
    .bottom { transform: rotateX(-90deg) translateZ(100px); }

    @keyframes rotateCube {
      from { transform: rotateX(0deg) rotateY(0deg); }
      to { transform: rotateX(360deg) rotateY(360deg); }
    }

    /* RIGHT SIDE: FORM CARD */
    .glass-card {
      background: rgba(15, 23, 42, 0.6);
      backdrop-filter: blur(20px);
      -webkit-backdrop-filter: blur(20px);
      border: 1px solid var(--glass-border);
      border-radius: 24px;
      padding: 32px;
      box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
      animation: slideUp 0.8s cubic-bezier(0.16, 1, 0.3, 1);
    }

    label {
      display: block;
      margin-top: 16px;
      font-size: 0.85rem;
      font-weight: 600;
      color: var(--muted);
      margin-bottom: 6px;
      letter-spacing: 0.5px;
    }

    input, textarea, select {
      width: 100%;
      background: rgba(0, 0, 0, 0.3);
      border: 1px solid var(--glass-border);
      color: #fff;
      padding: 12px 16px;
      border-radius: 12px;
      font-family: inherit;
      transition: all 0.3s ease;
    }
    input:focus, textarea:focus {
      border-color: var(--accent);
      box-shadow: 0 0 0 4px rgba(168, 85, 247, 0.1);
      background: rgba(0, 0, 0, 0.5);
    }
    textarea { min-height: 100px; resize: vertical; }

    button {
      width: 100%;
      margin-top: 24px;
      padding: 16px;
      background: linear-gradient(135deg, var(--accent), var(--accent-sec));
      border: none;
      border-radius: 12px;
      color: white;
      font-weight: 700;
      font-size: 1rem;
      cursor: pointer;
      transition: transform 0.2s, box-shadow 0.2s;
      text-transform: uppercase;
      letter-spacing: 1px;
    }
    button:hover {
      transform: translateY(-2px);
      box-shadow: 0 10px 20px -5px rgba(168, 85, 247, 0.5);
    }
    button:active { transform: translateY(0); }

    .hint { font-size: 0.75rem; color: #64748b; margin-top: 4px; }
    
    /* ANIMATIONS */
    @keyframes slideUp { from { opacity: 0; transform: translateY(40px); } to { opacity: 1; transform: translateY(0); } }
    @keyframes slideDown { from { opacity: 0; transform: translateY(-40px); } to { opacity: 1; transform: translateY(0); } }
    @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }

    /* RESPONSIVE */
    @media (max-width: 900px) {
      .container { grid-template-columns: 1fr; }
      h1 { font-size: 3rem; }
      .scene { margin: 40px auto; }
    }
  </style>
</head>
<body>
  <div class="orb orb-1"></div>
  <div class="orb orb-2"></div>

  <div class="container">
    
    <div class="hero-content">
      <h1>Build Your<br>Digital Legacy.</h1>
      <div class="subhead">
        Create a stunning, single-file portfolio in seconds. 
        No database, no tracking, just pure HTML & CSS magic wrapped in a futuristic design.
      </div>
      
      <div class="scene">
        <div class="cube">
          <div class="face front"></div>
          <div class="face back"></div>
          <div class="face right"></div>
          <div class="face left"></div>
          <div class="face top"></div>
          <div class="face bottom"></div>
        </div>
      </div>
    </div>

    <form method="post" action="/" enctype="multipart/form-data" class="glass-card">
      <h2 style="margin:0 0 20px 0; font-family:'Space Grotesk'; color:#fff;">Initialize Profile</h2>
      
      <label>Identity</label>
      <input name="name" type="text" placeholder="e.g. Alex Chen" required>
      
      <label>Designation</label>
      <input name="title" type="text" placeholder="e.g. Creative Developer">
      
      <label>Manifesto (Bio)</label>
      <textarea name="bio" placeholder="Brief introduction..."></textarea>
      
      <label>Tech Stack <span class="hint">(Comma separated)</span></label>
      <input name="skills" type="text" placeholder="React, Python, AWS, Three.js">
      
      <label>Missions (Projects) <span class="hint">(Format: Title - Description - URL)</span></label>
      <textarea name="projects" placeholder="Project Alpha - AI Interface - https://github.com..."></textarea>
      
      <label>Connect</label>
      <input name="website" type="url" placeholder="Your Website URL" style="margin-bottom:8px;">
      <input name="links" type="text" placeholder="LinkedIn, GitHub, Twitter URLs...">
      
      <label>Avatar Upload</label>
      <input name="avatar" type="file" accept="image/*" style="padding: 8px;">

      <button type="submit">Generate System</button>
    </form>
  </div>
</body>
</html>
"""

# -------------------------------------------------------------------------
# 2. GENERATED PORTFOLIO - "Soochna" Inspired Dark/Glass Theme
# -------------------------------------------------------------------------
PORTFOLIO_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>{{ name }} | Portfolio</title>
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;700&family=Inter:wght@300;400;600&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #050505;
      --card-bg: rgba(20, 20, 20, 0.6);
      --border: rgba(255, 255, 255, 0.08);
      --accent: #6366f1; /* Indigo */
      --accent-glow: rgba(99, 102, 241, 0.4);
      --text-main: #f8fafc;
      --text-sec: #94a3b8;
    }
    
    body {
      margin: 0;
      background-color: var(--bg);
      background-image: 
        radial-gradient(at 0% 0%, rgba(99, 102, 241, 0.15) 0px, transparent 50%),
        radial-gradient(at 100% 100%, rgba(168, 85, 247, 0.15) 0px, transparent 50%);
      color: var(--text-main);
      font-family: 'Inter', sans-serif;
      min-height: 100vh;
      overflow-x: hidden;
    }

    /* BACKGROUND MESH GRID ANIMATION */
    .grid-bg {
      position: fixed;
      top: 0; left: 0; width: 100%; height: 100%;
      background-size: 50px 50px;
      background-image: linear-gradient(to right, rgba(255,255,255,0.02) 1px, transparent 1px),
                        linear-gradient(to bottom, rgba(255,255,255,0.02) 1px, transparent 1px);
      z-index: -1;
      transform: perspective(500px) rotateX(60deg) translateY(-100px) scale(2);
      animation: gridMove 20s linear infinite;
      pointer-events: none;
    }
    @keyframes gridMove { 0% { transform: perspective(500px) rotateX(60deg) translateY(0) scale(2); } 100% { transform: perspective(500px) rotateX(60deg) translateY(50px) scale(2); } }

    .wrap {
      max-width: 900px;
      margin: 0 auto;
      padding: 60px 24px;
      animation: entryFade 1s ease-out;
    }

    /* HEADER / PROFILE */
    .header {
      display: flex;
      flex-direction: column;
      align-items: center;
      text-align: center;
      margin-bottom: 60px;
      position: relative;
    }
    
    .avatar-container {
      position: relative;
      margin-bottom: 24px;
    }
    
    /* SPINNING GLOW RING */
    .avatar-ring {
      position: absolute;
      top: -5px; left: -5px; right: -5px; bottom: -5px;
      border-radius: 50%;
      background: linear-gradient(45deg, var(--accent), transparent, var(--accent));
      animation: spin 4s linear infinite;
      z-index: 0;
      filter: blur(8px);
    }
    @keyframes spin { 100% { transform: rotate(360deg); } }

    .avatar {
      width: 140px; 
      height: 140px; 
      border-radius: 50%; 
      object-fit: cover;
      position: relative;
      z-index: 1;
      border: 4px solid #000;
      background: #111;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 2rem;
      font-weight: bold;
      color: #333;
    }

    h1 {
      font-family: 'Space Grotesk', sans-serif;
      font-size: 3.5rem;
      margin: 0;
      background: linear-gradient(to bottom, #fff, #94a3b8);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      letter-spacing: -1px;
    }
    
    .role {
      font-size: 1.25rem;
      color: var(--accent);
      margin-top: 8px;
      font-weight: 500;
      text-transform: uppercase;
      letter-spacing: 2px;
      opacity: 0.9;
    }

    .bio {
      margin-top: 24px;
      max-width: 600px;
      line-height: 1.7;
      color: var(--text-sec);
      font-size: 1.1rem;
    }

    /* LINKS ROW */
    .socials {
      display: flex;
      gap: 16px;
      margin-top: 24px;
      flex-wrap: wrap;
      justify-content: center;
    }
    .social-link {
      padding: 10px 20px;
      background: rgba(255,255,255,0.03);
      border: 1px solid var(--border);
      border-radius: 100px;
      text-decoration: none;
      color: var(--text-main);
      font-size: 0.9rem;
      transition: all 0.3s;
    }
    .social-link:hover {
      background: var(--accent);
      border-color: var(--accent);
      box-shadow: 0 0 15px var(--accent-glow);
      transform: translateY(-2px);
    }

    /* SECTIONS */
    .section-title {
      font-family: 'Space Grotesk';
      font-size: 1.5rem;
      border-bottom: 1px solid var(--border);
      padding-bottom: 10px;
      margin: 60px 0 30px 0;
      color: var(--text-main);
      display: flex;
      align-items: center;
      gap: 10px;
    }
    .section-title::before {
      content: ''; display: block; width: 8px; height: 8px; background: var(--accent); border-radius: 50%; box-shadow: 0 0 10px var(--accent);
    }

    /* SKILLS */
    .skills-grid {
      display: flex;
      flex-wrap: wrap;
      gap: 12px;
    }
    .pill {
      background: rgba(255,255,255,0.03);
      border: 1px solid var(--border);
      padding: 8px 16px;
      border-radius: 6px;
      font-size: 0.9rem;
      color: var(--text-sec);
      transition: 0.3s;
    }
    .pill:hover {
      border-color: var(--accent);
      color: #fff;
      transform: scale(1.05);
    }

    /* PROJECTS - 3D CARDS */
    .project-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
      gap: 24px;
    }
    
    .card {
      background: var(--card-bg);
      backdrop-filter: blur(12px);
      border: 1px solid var(--border);
      padding: 24px;
      border-radius: 16px;
      transition: all 0.4s ease;
      position: relative;
      overflow: hidden;
      display: flex;
      flex-direction: column;
    }
    /* Hover Glow Effect */
    .card::before {
      content: '';
      position: absolute;
      top: 0; left: 0; width: 100%; height: 100%;
      background: radial-gradient(circle at 50% 0%, rgba(255,255,255,0.1), transparent 70%);
      opacity: 0;
      transition: 0.4s;
    }
    .card:hover {
      transform: translateY(-10px) scale(1.02);
      border-color: rgba(255,255,255,0.3);
      box-shadow: 0 20px 40px rgba(0,0,0,0.5);
    }
    .card:hover::before { opacity: 1; }

    .card h3 { margin: 0 0 10px 0; font-size: 1.25rem; }
    .card p { color: var(--text-sec); line-height: 1.5; font-size: 0.95rem; flex-grow: 1; }
    .card-link {
      margin-top: 16px;
      align-self: flex-start;
      color: var(--accent);
      text-decoration: none;
      font-weight: 600;
      font-size: 0.9rem;
      display: flex;
      align-items: center;
      gap: 5px;
    }
    .card-link:hover { text-decoration: underline; }

    footer {
      margin-top: 80px;
      text-align: center;
      color: #555;
      font-size: 0.8rem;
    }

    .download-btn {
      position: fixed;
      bottom: 30px;
      right: 30px;
      background: var(--text-main);
      color: #000;
      padding: 12px 24px;
      border-radius: 50px;
      text-decoration: none;
      font-weight: bold;
      box-shadow: 0 10px 20px rgba(0,0,0,0.5);
      transition: 0.3s;
      z-index: 100;
      opacity: 0.5;
    }
    .download-btn:hover { opacity: 1; transform: scale(1.1); }

    @keyframes entryFade { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }
    
    @media (max-width: 600px) {
      h1 { font-size: 2.5rem; }
    }
  </style>
</head>
<body>
  <div class="grid-bg"></div>

  <div class="wrap">
    <header class="header">
      <div class="avatar-container">
        <div class="avatar-ring"></div>
        {% if avatar_data %}
          <img class="avatar" src="{{ avatar_data }}" alt="Profile">
        {% else %}
          <div class="avatar">{{ initials }}</div>
        {% endif %}
      </div>
      
      <h1>{{ name }}</h1>
      <div class="role">{{ title }}</div>
      
      {% if bio %}
        <div class="bio">{{ bio }}</div>
      {% endif %}

      <div class="socials">
        {% if website %}<a class="social-link" href="{{ website }}" target="_blank">Portfolio</a>{% endif %}
        {% for l in links_list %}
          <a class="social-link" href="{{ l }}" target="_blank">{{ l|replace('https://','')|replace('http://','')|replace('www.','')|truncate(15, True, '...') }}</a>
        {% endfor %}
      </div>
    </header>

    {% if skills %}
      <div class="section-title">Technical Arsenal</div>
      <div class="skills-grid">
        {% for s in skills %}
          <div class="pill">{{ s }}</div>
        {% endfor %}
      </div>
    {% endif %}

    {% if projects %}
      <div class="section-title">Deployed Systems</div>
      <div class="project-grid">
        {% for p in projects %}
          <div class="card">
            <h3>{{ p.title }}</h3>
            <p>{{ p.desc }}</p>
            {% if p.url %}
              <a href="{{ p.url }}" target="_blank" class="card-link">View Deployment &rarr;</a>
            {% endif %}
          </div>
        {% endfor %}
      </div>
    {% endif %}

    <footer>
      Generated on {{ date }}
    </footer>
  </div>

  <a class="download-btn" href="{{ download_url }}">Download HTML</a>
</body>
</html>
"""

# -------------------------------------------------------------------------
# 3. PYTHON LOGIC (Helpers & Routes)
# -------------------------------------------------------------------------

def image_file_to_data_url(file_storage):
    """Return a data URL for the uploaded image (base64) or None."""
    if not file_storage:
        return None
    try:
        raw = file_storage.read()
        if not raw:
            return None
        mime = file_storage.mimetype or 'image/png'
        b64 = base64.b64encode(raw).decode('ascii')
        return f"data:{mime};base64,{b64}"
    except Exception:
        return None

def parse_skills(text):
    if not text:
        return []
    items = [s.strip() for s in text.split(',') if s.strip()]
    return items[:30]

def parse_projects(text):
    """Expect each line: Title - description - optional url"""
    if not text:
        return []
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    parsed = []
    for ln in lines[:20]:
        parts = [p.strip() for p in ln.split(' - ')]
        title = parts[0] if parts else ''
        desc = parts[1] if len(parts) >= 2 else ''
        url = parts[2] if len(parts) >= 3 else ''
        # Simple heuristic to find URL if user forgot separators
        if url == '' and 'http' in desc:
            tokens = desc.rsplit(' ', 1)
            if tokens and tokens[-1].startswith('http'):
                url = tokens[-1]
                desc = tokens[0]
        parsed.append({'title': title, 'desc': desc, 'url': url})
    return parsed

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'GET':
        return render_template_string(INDEX_HTML)
    
    # POST - Processing
    name = request.form.get('name', '').strip() or 'Anonymous'
    title = request.form.get('title', '').strip()
    bio = request.form.get('bio', '').strip()
    skills = parse_skills(request.form.get('skills', ''))
    projects = parse_projects(request.form.get('projects', ''))
    website = request.form.get('website', '').strip()
    links_raw = request.form.get('links', '').strip()
    links_list = [l.strip() for l in links_raw.split(',') if l.strip()]

    avatar_file = request.files.get('avatar')
    avatar_data = image_file_to_data_url(avatar_file) if avatar_file and avatar_file.filename else None

    initials = ''.join([part[:1].upper() for part in name.split()[:2]]) or 'A'

    # Render final portfolio
    date = datetime.datetime.now().strftime('%B %d, %Y')
    token = str(int(datetime.datetime.utcnow().timestamp() * 1000))
    
    rendered = render_template_string(PORTFOLIO_TEMPLATE,
                                      name=name, title=title, bio=bio, skills=skills,
                                      projects=projects, avatar_data=avatar_data, initials=initials,
                                      website=website, links_list=links_list, date=date,
                                      download_url=url_for('download_html', token=token))
    
    # Simple in-memory storage (clears on restart)
    if not hasattr(app, 'generated_html_store'):
        app.generated_html_store = {}
    app.generated_html_store[token] = rendered

    return rendered

@app.route('/download/<token>')
def download_html(token):
    store = getattr(app, 'generated_html_store', {})
    html = store.get(token)
    if not html:
        return "No generated portfolio found (it may have expired). Go back and generate again.", 404
    
    fname = "portfolio_{}.html".format(datetime.datetime.utcnow().strftime('%Y%m%d%H%M%S'))
    return send_file(io.BytesIO(html.encode('utf-8')),
                     download_name=fname,
                     as_attachment=True,
                     mimetype='text/html')



if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
