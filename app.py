import hashlib
import io
import math
import re
from collections import Counter
from urllib.parse import urlparse
import cv2
from flask import Flask, jsonify, render_template_string, request
import numpy as np

app = Flask(__name__)

# Config & Allowed Extensions
ALLOWED_PHOTO_EXT = {".png", ".jpg", ".jpeg", ".webp", ".bmp"}
EXEC_EXT = {".exe", ".msi", ".bat", ".cmd", ".vbs", ".ps1", ".js", ".scr", ".jar"}
MACRO_EXT = {".docm", ".xlsm", ".pptm"}
DOC_EXT = {".pdf", ".docx", ".pptx", ".xlsx", ".apk", ".txt"}
IMAGE_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp"}

POPULAR_TARGETS = [
    "paypal.com", "google.com", "amazon.com", "netflix.com",
    "apple.com", "microsoft.com", "facebook.com", "instagram.com"
]

# Optional C++/Fast Decoders
PYZBAR_AVAILABLE = False
try:
    from pyzbar.pyzbar import decode as pyzbar_decode
    PYZBAR_AVAILABLE = True
except ImportError:
    pass

ZXING_AVAILABLE = False
try:
    import zxingcpp
    ZXING_AVAILABLE = True
except ImportError:
    pass

# ==========================================
# FAST OPTIMIZED HELPER FUNCTIONS
# ==========================================
def is_valid_url(url):
    return bool(re.match(r"^(https?:\/\/)?" r"(([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,})" r"(:\d+)?" r"(\/.*)?$", url.strip()))

def calculate_entropy(data_bytes):
    if not data_bytes: 
        return 0.0
    sample = data_bytes[:10000]
    length = len(sample)
    # Fast O(N) byte counting
    counts = Counter(sample)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())

def levenshtein_distance(s1, s2):
    if len(s1) < len(s2): return levenshtein_distance(s2, s1)
    if len(s2) == 0: return len(s1)
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]

def inspect_file(filename, file_bytes):
    flags, risk_score = [], 0
    lower_name = filename.lower()
    ext = "." + lower_name.split(".")[-1] if "." in lower_name else ""
    sha256 = hashlib.sha256(file_bytes[:1024*1024]).hexdigest()

    if re.search(r"\.[a-z0-9]+\.(exe|bat|vbs|scr|js|ps1)$", lower_name):
        risk_score += 65
        flags.append("Double extension spoofing detected (+65)")

    header = file_bytes[:16]
    is_mz = header.startswith(b"MZ")

    if (ext in DOC_EXT or ext in IMAGE_EXT) and is_mz:
        risk_score += 85
        flags.append(f"CRITICAL: Executable binary disguised as {ext.upper()} (+85)")

    if ext in EXEC_EXT: risk_score += 40; flags.append(f"Executable extension ({ext}) (+40)")
    if ext in MACRO_EXT: risk_score += 35; flags.append(f"Macro-enabled document ({ext}) (+35)")
    if calculate_entropy(file_bytes) > 7.3:
        risk_score += 25; flags.append("High entropy payload (+25)")

    return min(risk_score, 100), flags, sha256, ext

def generate_ai_explanation(verdict, score, flags, context_type, lang="en-IN"):
    lang = (lang or "en-IN").lower()
    
    # TAMIL RESPONSE (ta)
    if lang.startswith("ta"):
        if verdict == "SAFE":
            return f"ஏஜிஸ் AI பகுப்பாய்வு: ஸ்கேன் செய்யப்பட்ட {context_type} பாதுகாப்பானது. ஆபத்து மதிப்பெண்: {score}/100. அச்சுறுத்தல் எதுவும் கண்டறியப்படவில்லை."
        advice = "இதில் உள்ள இணைப்புகளைத் திறக்கவோ அல்லது கோப்புகளை பதிவிறக்கம் செய்யவோ வேண்டாம். "
        if "quishing" in " ".join(flags).lower() or "qr" in context_type.lower():
            advice += "இந்த QR குறியீடு போலியானது (Quishing), இது உங்களை ஆபத்தான இடத்திற்கு திசைதிருப்பக்கூடும். "
        return f"ஏஜிஸ் AI எச்சரிக்கை: ஆபத்து கண்டறியப்பட்டுள்ளது! நிலை: {verdict}, ஆபத்து மதிப்பெண்: {score}/100. எச்சரிக்கை: {', '.join(flags[:2])}. நடவடிக்கை: {advice}"

    # HINDI RESPONSE (hi)
    elif lang.startswith("hi"):
        if verdict == "SAFE":
            return f"एजिस एआई विश्लेषण: स्कैन किया गया {context_type} सुरक्षित है। जोखिम स्कोर: {score}/100।"
        advice = "इस स्रोत से लिंक न खोलें और न ही सामग्री डाउनलोड करें। "
        return f"एजिस एआई चेतावनी: खतरा पाया गया! निर्णय: {verdict}, जोखिम स्कोर: {score}/100। कार्रवाई: {advice}"

    # SPANISH RESPONSE (es)
    elif lang.startswith("es"):
        if verdict == "SAFE":
            return f"Análisis de Aegis AI: El {context_type} escaneado es seguro con una puntuación de riesgo de {score}/100."
        return f"Advertencia de Aegis AI: ¡Amenaza detectada! Veredicto: {verdict} ({score}/100). Acción: No abra enlaces ni descargue archivos."

    # DEFAULT ENGLISH RESPONSE
    if verdict == "SAFE":
        return f"Aegis AI Analysis: The scanned {context_type} is clean with a low risk score of {score}. No threat patterns were detected."
    advice = "Do not open attached links or download content from this source. "
    if "quishing" in " ".join(flags).lower() or "qr" in context_type.lower():
        advice += "This QR code employs Quishing techniques to redirect to an unverified location or download prompt. "
    return f"Aegis AI Warning: Threat detected! Verdict is {verdict} with a severity score of {score}/100. Flags: {', '.join(flags[:2])}. Action: {advice}"

def decode_qr_enhanced(img):
    # 1. Fast Path: ZXing C++ reader (Instant)
    if ZXING_AVAILABLE:
        try:
            results = zxingcpp.read_barcodes(img)
            for r in results:
                if r.text: return r.text
        except Exception:
            pass

    detector = cv2.QRCodeDetector()
    
    # 2. Fast Path: Native OpenCV on raw BGR
    try:
        res, _, _ = detector.detectAndDecode(img)
        if res: return res
    except Exception:
        pass

    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    
    # 3. Fast Path: Native OpenCV on Grayscale
    try:
        res, _, _ = detector.detectAndDecode(gray)
        if res: return res
    except Exception:
        pass

    # 4. Fast Path: PyZbar reader
    if PYZBAR_AVAILABLE:
        try:
            barcodes = pyzbar_decode(gray)
            for barcode in barcodes:
                if barcode.data: return barcode.data.decode("utf-8")
        except Exception:
            pass

    # 5. Fallbacks: Only execute heavy filters if fast checks fail
    try:
        res, _, _ = detector.detectAndDecode(cv2.bitwise_not(gray))
        if res: return res
    except Exception:
        pass

    _, otsu = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    try:
        res, _, _ = detector.detectAndDecode(otsu)
        if res: return res
    except Exception:
        pass

    h, w = gray.shape[:2]
    if max(h, w) > 1500:
        resized = cv2.resize(gray, (0, 0), fx=0.5, fy=0.5, interpolation=cv2.INTER_AREA)
        try:
            res, _, _ = detector.detectAndDecode(resized)
            if res: return res
        except Exception:
            pass

    return None

# ==========================================
# API ROUTES
# ==========================================
@app.route("/scan-url", methods=["POST"])
def scan_url_route():
    try:
        req_data = request.get_json() or {}
        raw_url = req_data.get("url", "").strip()
        lang = req_data.get("lang", "en-IN")

        if not is_valid_url(raw_url): 
            return jsonify({"error": "Invalid URL structure."}), 400

        flags, risk_score = [], 0
        domain = urlparse(raw_url if raw_url.startswith(("http://", "https://")) else f"http://{raw_url}").netloc.split(":")[0].lower()

        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain):
            risk_score += 40; flags.append("Raw IP address target (+40)")

        for target in POPULAR_TARGETS:
            if domain != target and 0 < levenshtein_distance(domain, target) <= 2:
                risk_score += 50; flags.append(f"Typosquatting target '{target}' (+50)"); break

        score = min(risk_score, 100)
        verdict = "DANGER" if score >= 60 else "SUSPICIOUS" if score >= 30 else "SAFE"
        ai_reply = generate_ai_explanation(verdict, score, flags, "URL link", lang)

        return jsonify({"risk_score": score, "verdict": verdict, "flags": flags or ["Clean URL pattern."], "ai_reply": ai_reply})
    except Exception as e:
        return jsonify({"error": f"URL scan error: {str(e)}"}), 500

@app.route("/scan-message", methods=["POST"])
def scan_message_route():
    try:
        req_data = request.get_json() or {}
        msg = req_data.get("message", "").strip()
        lang = req_data.get("lang", "en-IN")

        if not msg: return jsonify({"error": "Empty message."}), 400

        flags, risk_score, lower = [], 0, msg.lower()
        u_count = sum(1 for k in ["urgent", "suspended", "immediately", "locked", "verify"] if k in lower)
        if u_count: risk_score += min(u_count * 25, 50); flags.append(f"Urgency manipulation ({u_count}) (+{min(u_count*25,50)})")

        score = min(risk_score, 100)
        verdict = "DANGER" if score >= 60 else "SUSPICIOUS" if score >= 30 else "SAFE"
        ai_reply = generate_ai_explanation(verdict, score, flags, "message", lang)

        return jsonify({"risk_score": score, "verdict": verdict, "flags": flags or ["No threat triggers."], "ai_reply": ai_reply})
    except Exception as e:
        return jsonify({"error": f"Message scan error: {str(e)}"}), 500

@app.route("/scan-file", methods=["POST"])
def scan_file_route():
    try:
        if "file" not in request.files: return jsonify({"error": "No file uploaded."}), 400
        f = request.files["file"]
        lang = request.form.get("lang", "en-IN")

        score, flags, sha, ext = inspect_file(f.filename, f.read())
        verdict = "DANGER" if score >= 60 else "SUSPICIOUS" if score >= 30 else "SAFE"
        ai_reply = generate_ai_explanation(verdict, score, flags, f"{ext.upper()} file", lang)

        return jsonify({"filename": f.filename, "sha256": sha, "ext": ext.upper() or "FILE", "risk_score": score, "verdict": verdict, "flags": flags or ["Clean binary signature."], "ai_reply": ai_reply})
    except Exception as e:
        return jsonify({"error": f"File analysis error: {str(e)}"}), 500

@app.route("/scan-qr", methods=["POST"])
def scan_qr_route():
    try:
        if "file" not in request.files: 
            return jsonify({"error": "No QR image uploaded."}), 400
        
        file = request.files["file"]
        lang = request.form.get("lang", "en-IN")
        filename = file.filename.lower()
        photo_ext = "." + filename.split(".")[-1] if "." in filename else ""

        if photo_ext not in ALLOWED_PHOTO_EXT:
            return jsonify({"error": f"Unsupported photo format '{photo_ext}'. Upload PNG, JPG, JPEG, WEBP, or BMP."}), 400

        file_bytes = file.read()
        if not file_bytes:
            return jsonify({"error": "Uploaded image file is empty."}), 400

        nparr = np.frombuffer(file_bytes, np.uint8)
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)

        if img is None: 
            return jsonify({"error": "Corrupted or unreadable image file."}), 400

        data = decode_qr_enhanced(img)
        if not data: 
            return jsonify({"error": "No readable QR code found in photo."}), 400

        flags, risk_score = [f"Decoded QR Payload: {data}", f"Photo Format: {photo_ext.upper()}"], 0
        lower_data = data.lower()

        payload_ext = ""
        for ext in EXEC_EXT | MACRO_EXT | DOC_EXT | IMAGE_EXT:
            if lower_data.endswith(ext) or f"{ext}?" in lower_data:
                payload_ext = ext
                break

        if payload_ext in EXEC_EXT:
            risk_score += 80; flags.append(f"HIGH ALERT: QR code directly downloads an executable file ({payload_ext}) (+80)")
        elif payload_ext in MACRO_EXT:
            risk_score += 60; flags.append(f"WARNING: QR code points to a macro-enabled file ({payload_ext}) (+60)")

        if is_valid_url(data):
            domain = urlparse(data if data.startswith(("http://", "https://")) else f"http://{data}").netloc.split(":")[0].lower()
            for target in POPULAR_TARGETS:
                if domain != target and 0 < levenshtein_distance(domain, target) <= 2:
                    risk_score += 50; flags.append(f"Quishing Attack: QR spoofs major brand '{target}' (+50)"); break

        score = min(risk_score, 100)
        verdict = "DANGER" if score >= 60 else "SUSPICIOUS" if score >= 30 else "SAFE"
        ai_reply = generate_ai_explanation(verdict, score, flags, f"QR code ({photo_ext.upper()} photo)", lang)

        return jsonify({"extracted_data": data, "photo_extension": photo_ext.upper(), "payload_extension": payload_ext.upper() or "NONE", "risk_score": score, "verdict": verdict, "flags": flags, "ai_reply": ai_reply})
    except Exception as e:
        return jsonify({"error": f"QR processing failed: {str(e)}"}), 500

@app.route("/ai-assistant", methods=["POST"])
def ai_assistant_route():
    try:
        data = request.get_json() or {}
        user_query = data.get("query", "").strip()
        lang = (data.get("lang") or "en-IN").lower()

        if not user_query: return jsonify({"error": "Empty prompt."}), 400
        
        if lang.startswith("ta"):
            reply = f"ஏஜிஸ் AI பாதுகாப்பு: '{user_query}' பற்றிய உங்கள் கேள்விக்கு — சந்தேகத்திற்குரிய பதிவிறக்க இணைப்புகளை எப்போதும் சரிபார்க்கவும் மற்றும் ஆபத்தான கோப்புகளை ஸ்கேன் செய்யவும்."
        elif lang.startswith("hi"):
            reply = f"एजिस एआई सुरक्षा: '{user_query}' के बारे में — हमेशा संदिग्ध डाउनलोड लिंक की जांच करें और फाइलों को स्कैन करें।"
        elif lang.startswith("es"):
            reply = f"Seguridad Aegis AI: Con respecto a '{user_query}', verifique siempre los enlaces de descarga sospechosos."
        else:
            reply = f"Aegis AI Security: Regarding '{user_query}', always verify suspicious download links and scan executable files before running."

        return jsonify({"reply": reply})
    except Exception as e:
        return jsonify({"error": f"AI Assistant error: {str(e)}"}), 500

@app.route("/")
def index():
    return render_template_string(UI_TEMPLATE)

# ==========================================
# DASHBOARD UI TEMPLATE
# ==========================================
UI_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Aegis Cyber AI Threat Platform</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg: #070a12;
            --panel: rgba(18, 26, 43, 0.8);
            --accent: #00f2fe;
            --accent-glow: rgba(0, 242, 254, 0.3);
            --danger: #ff3366;
            --warning: #ffb703;
            --safe: #00e676;
            --text: #f1f5f9;
            --text-dim: #94a3b8;
        }
        * { box-sizing: border-box; transition: all 0.2s ease; }
        body {
            background: radial-gradient(circle at 50% 0%, #0f172a 0%, var(--bg) 100%);
            color: var(--text); font-family: 'Inter', sans-serif;
            min-height: 100vh; margin: 0; display: flex; align-items: center; justify-content: center; padding: 20px;
        }
        .dashboard {
            width: 100%; max-width: 850px; background: var(--panel);
            backdrop-filter: blur(16px); border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 16px; padding: 32px; box-shadow: 0 20px 50px rgba(0,0,0,0.6);
        }
        .header { text-align: center; margin-bottom: 24px; }
        .header h1 {
            font-size: 26px; font-weight: 700;
            background: linear-gradient(90deg, #4facfe 0%, #00f2fe 100%);
            -webkit-background-clip: text; -webkit-text-fill-color: transparent; margin: 0 0 6px 0;
        }
        .tabs { display: flex; gap: 8px; background: rgba(0, 0, 0, 0.3); padding: 6px; border-radius: 12px; margin-bottom: 24px; }
        .tab { flex: 1; padding: 10px; background: transparent; border: none; color: var(--text-dim); font-weight: 600; font-size: 12px; border-radius: 8px; cursor: pointer; }
        .tab.active { background: var(--accent); color: #000; box-shadow: 0 0 15px var(--accent-glow); }
        .panel { display: none; }
        .panel.active { display: block; }
        input, textarea, select {
            width: 100%; padding: 14px; background: rgba(0, 0, 0, 0.4);
            border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 10px; color: var(--text);
            font-family: 'JetBrains Mono', monospace; font-size: 13px; outline: none; margin-bottom: 14px;
        }
        select option { background: #0f172a; color: white; }
        .btn {
            width: 100%; padding: 14px; background: linear-gradient(90deg, #00c6ff 0%, #0072ff 100%);
            border: none; border-radius: 10px; color: white; font-weight: 700; cursor: pointer; font-size: 14px;
        }
        .voice-bar { display: flex; align-items: center; justify-content: space-between; background: rgba(0,0,0,0.2); padding: 10px 16px; border-radius: 8px; margin-bottom: 16px; font-size: 13px; }
        .result-card { margin-top: 20px; background: rgba(0,0,0,0.3); border-radius: 12px; padding: 20px; border: 1px solid rgba(255,255,255,0.05); display: none; }
        .badge { padding: 6px 14px; border-radius: 20px; font-weight: 700; font-size: 12px; }
        .ai-box { background: rgba(0, 242, 254, 0.05); border-left: 3px solid var(--accent); padding: 12px 16px; border-radius: 4px; margin-top: 14px; font-size: 13px; color: #e2e8f0; }
        .error { color: var(--danger); font-size: 13px; margin-top: 10px; display: none; }
        .supported-ext { font-size: 11px; color: var(--text-dim); margin-top: -8px; margin-bottom: 12px; }
        
        .chat-input-group { display: flex; gap: 8px; margin-bottom: 14px; }
        .chat-input-group input { margin-bottom: 0; }
        .mic-btn { width: auto; padding: 0 18px; background: #2563eb; white-space: nowrap; }
        .mic-btn.listening { background: #ef4444; animation: pulse 1.5s infinite; }
        @keyframes pulse { 0% { opacity: 1; } 50% { opacity: 0.5; } 100% { opacity: 1; } }
    </style>
</head>
<body>
    <div class="dashboard">
        <div class="header">
            <h1>AEGIS CYBER AI PLATFORM</h1>
            <p style="font-size: 12px; color: var(--text-dim);">Dynamic Multi-Language Voice Input & Output AI</p>
        </div>

        <div class="voice-bar">
            <span>🌐 Select Voice Language:</span>
            <div style="display:flex; align-items:center; gap:10px;">
                <select id="langSelect" style="width: auto; padding: 4px 8px; margin-bottom: 0;">
                    <option value="ta-IN">Tamil (தமிழ்)</option>
                    <option value="en-IN">English (India)</option>
                    <option value="hi-IN">Hindi (हिन्दी)</option>
                    <option value="te-IN">Telugu (తెలుగు)</option>
                    <option value="bn-IN">Bengali (বাংলা)</option>
                    <option value="mr-IN">Marathi (मराठी)</option>
                    <option value="gu-IN">Gujarati (ગુજરાતી)</option>
                    <option value="kn-IN">Kannada (கன்னடம்)</option>
                    <option value="ml-IN">Malayalam (மலையாளம்)</option>
                    <option value="pa-IN">Punjabi (பஞ்சாபி)</option>
                    <option value="ur-IN">Urdu (உருது)</option>
                    <option value="en-US">English (US)</option>
                    <option value="es-ES">Spanish (Español)</option>
                    <option value="fr-FR">French (Français)</option>
                    <option value="de-DE">German (Deutsch)</option>
                    <option value="zh-CN">Chinese (中文)</option>
                    <option value="ja-JP">Japanese (日本語)</option>
                    <option value="ar-SA">Arabic (العربية)</option>
                    <option value="pt-BR">Portuguese (Português)</option>
                    <option value="ru-RU">Russian (Русский)</option>
                </select>
                <label style="cursor:pointer;"><input type="checkbox" id="voiceToggle" checked> Speak Response</label>
            </div>
        </div>

        <div class="tabs">
            <button class="tab active" onclick="switchTab('url', this)">URL SCAN</button>
            <button class="tab" onclick="switchTab('msg', this)">MESSAGE</button>
            <button class="tab" onclick="switchTab('file', this)">UNIVERSAL FILE</button>
            <button class="tab" onclick="switchTab('qr', this)">📷 QR CODE</button>
            <button class="tab" onclick="switchTab('chat', this)">🤖 AI CHAT</button>
        </div>

        <div id="urlPanel" class="panel active">
            <input type="text" id="urlInput" placeholder="https://secure-paypa1-update.com/login">
            <button class="btn" onclick="sendReq('/scan-url', {url: val('urlInput')})">RUN URL SCAN</button>
        </div>

        <div id="msgPanel" class="panel">
            <textarea id="msgInput" rows="3" placeholder="Urgent! Your account is suspended. Click here to unlock."></textarea>
            <button class="btn" onclick="sendReq('/scan-message', {message: val('msgInput')})">SCAN MESSAGE</button>
        </div>

        <div id="filePanel" class="panel">
            <input type="file" id="fileInput">
            <div class="supported-ext">Supports: .pdf, .docx, .png, .jpg, .exe, .zip, .apk</div>
            <button class="btn" onclick="sendFile('/scan-file', 'fileInput')">INSPECT FILE</button>
        </div>

        <div id="qrPanel" class="panel">
            <input type="file" id="qrInput" accept=".png, .jpg, .jpeg, .webp, .bmp">
            <div class="supported-ext">Photo Formats Allowed: PNG, JPG, JPEG, WEBP, BMP</div>
            <button class="btn" onclick="sendFile('/scan-qr', 'qrInput')">DECODE & INSPECT QR</button>
        </div>

        <div id="chatPanel" class="panel">
            <div class="chat-input-group">
                <input type="text" id="chatInput" placeholder="Type or click 🎙️ Mic to speak in selected language...">
                <button id="micBtn" class="btn mic-btn" onclick="toggleVoiceInput()">🎙️ Mic</button>
            </div>
            <button class="btn" onclick="askAIChat()">ASK AI ASSISTANT</button>
        </div>

        <div id="error" class="error"></div>

        <div id="result" class="result-card">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
                <span id="badge" class="badge">SAFE</span>
                <button onclick="speakCurrentResult()" style="background:none; border:1px solid var(--accent); color:var(--accent); padding:4px 10px; border-radius:6px; cursor:pointer; font-size:11px;">🔊 Replay Voice</button>
            </div>
            <div id="aiBox" class="ai-box"></div>
            <h4 style="font-size:13px; margin: 14px 0 6px 0;">Detection Flags:</h4>
            <ul id="flags" style="padding-left:18px; font-size:12px; color: var(--text-dim);"></ul>
        </div>
    </div>

    <script>
        let currentVoiceText = "";
        let recognition = null;
        let isListening = false;
        let cachedVoices = [];
        const val = id => document.getElementById(id).value;

        // FAST VOICE INITIALIZATION & CACHING
        function initVoices() {
            if ('speechSynthesis' in window) {
                cachedVoices = window.speechSynthesis.getVoices();
            }
        }
        if ('speechSynthesis' in window) {
            initVoices();
            window.speechSynthesis.onvoiceschanged = initVoices;
        }

        const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;

        if (SpeechRecognition) {
            recognition = new SpeechRecognition();
            recognition.continuous = false;
            recognition.interimResults = false;

            recognition.onresult = function(event) {
                const transcript = event.results[0][0].transcript;
                document.getElementById('chatInput').value = transcript;
                stopListening();
                askAIChat();
            };

            recognition.onerror = function(event) {
                let errorMsg = "Voice Error: " + event.error;
                if (event.error === 'not-allowed') {
                    errorMsg = "Microphone blocked! Allow microphone access in your browser settings.";
                } else if (event.error === 'network') {
                    errorMsg = "Speech recognition network error. Use http://localhost or HTTPS.";
                }
                showErr(errorMsg);
                stopListening();
            };

            recognition.onend = function() {
                stopListening();
            };
        }

        function toggleVoiceInput() {
            if (!window.isSecureContext && location.hostname !== "localhost" && location.hostname !== "127.0.0.1") {
                return showErr("Microphone requires http://localhost or HTTPS.");
            }
            if (!recognition) {
                return showErr("Speech recognition not supported in this browser.");
            }
            if (isListening) {
                stopListening();
            } else {
                startListening();
            }
        }

        function startListening() {
            try {
                const selectedLang = document.getElementById('langSelect').value;
                recognition.lang = selectedLang;
                recognition.start();
                isListening = true;
                const btn = document.getElementById('micBtn');
                btn.innerText = "🛑 Listening...";
                btn.classList.add('listening');
            } catch(e) {
                showErr("Failed to start voice recognition: " + e.message);
            }
        }

        function stopListening() {
            if (recognition && isListening) {
                recognition.stop();
            }
            isListening = false;
            const btn = document.getElementById('micBtn');
            if (btn) {
                btn.innerText = "🎙️ Mic";
                btn.classList.remove('listening');
            }
        }

        // ULTRA-FAST LOW LATENCY VOICE REPLAY
        function speakText(text) {
            if (!('speechSynthesis' in window) || !text) return;

            window.speechSynthesis.cancel(); // Stop active speech streams

            // Fast-Path: Speak 1st sentence immediately instead of waiting for full paragraph
            const primarySentence = text.split('.')[0] + '.';
            const utterance = new SpeechSynthesisUtterance(primarySentence);
            
            const selectedLang = document.getElementById('langSelect').value;
            utterance.lang = selectedLang;
            utterance.rate = 1.1; // Slightly faster audio output

            // Pick offline local voice to avoid cloud TTS network delay
            if (cachedVoices.length > 0) {
                const targetLangCode = selectedLang.split('-')[0];
                const bestVoice = cachedVoices.find(v => v.lang.startsWith(targetLangCode) && v.localService) 
                               || cachedVoices.find(v => v.lang.startsWith(targetLangCode));
                if (bestVoice) {
                    utterance.voice = bestVoice;
                }
            }

            window.speechSynthesis.resume();
            window.speechSynthesis.speak(utterance);
        }

        function speakCurrentResult() { 
            if (currentVoiceText) speakText(currentVoiceText); 
        }

        function switchTab(type, btn) {
            document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.getElementById(type + 'Panel').classList.add('active');
            btn.classList.add('active');
            document.getElementById('result').style.display = 'none';
            document.getElementById('error').style.display = 'none';
        }

        function render(data) {
            document.getElementById('error').style.display = 'none';
            const badge = document.getElementById('badge');
            badge.innerText = data.verdict || "AI RESPONSE";
            badge.style.background = data.verdict === 'DANGER' ? 'var(--danger)' : data.verdict === 'SUSPICIOUS' ? 'var(--warning)' : 'var(--safe)';
            badge.style.color = data.verdict === 'SUSPICIOUS' ? '#000' : '#fff';

            document.getElementById('aiBox').innerText = data.ai_reply || data.reply;
            currentVoiceText = data.ai_reply || data.reply;

            const ul = document.getElementById('flags');
            ul.innerHTML = '';
            (data.flags || ["Completed."]).forEach(f => { const li = document.createElement('li'); li.innerText = f; ul.appendChild(li); });
            document.getElementById('result').style.display = 'block';

            if (document.getElementById('voiceToggle').checked) speakText(currentVoiceText);
        }

        async function sendReq(url, body) {
            try {
                body.lang = val('langSelect');
                const r = await fetch(url, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)});
                let d;
                try { d = await r.json(); } catch(e) { return showErr("Server Error (" + r.status + ")"); }
                if (!r.ok) return showErr(d.error || "Request failed.");
                render(d);
            } catch (e) { showErr("Connection failed."); }
        }

        async function sendFile(url, inputId) {
            const files = document.getElementById(inputId).files;
            if(!files.length) return showErr("Please select a file first.");
            const fd = new FormData();
            fd.append('file', files[0]);
            fd.append('lang', val('langSelect'));
            try {
                const r = await fetch(url, {method: 'POST', body: fd});
                let d;
                try { d = await r.json(); } catch(e) { return showErr("Server Error (" + r.status + ")"); }
                if (!r.ok) return showErr(d.error || "Analysis failed.");
                render(d);
            } catch (e) { showErr("Network or file reading error."); }
        }

        async function askAIChat() {
            const query = val('chatInput');
            if(!query) return showErr("Enter a question or speak using the microphone.");
            sendReq('/ai-assistant', {query});
        }

        function showErr(msg) {
            const e = document.getElementById('error');
            e.innerText = msg; e.style.display = 'block';
        }
    </script>
</body>
</html>
"""

if __name__ == "__main__":
    app.run(debug=True, port=5000)
