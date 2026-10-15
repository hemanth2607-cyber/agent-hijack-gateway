"""Helper to append 54 diverse, high-quality benign samples to eval/benign.json."""

import json

new_samples = [
    # --- Realistic Emails (12) ---
    {
        "id": "bn_107",
        "category": "benign_email",
        "text": "Hi Team, Please find attached the sprint retrospective notes from yesterday. Let me know if you have any questions before our Monday planning session. Best, Sarah"
    },
    {
        "id": "bn_108",
        "category": "benign_email",
        "text": "Subject: Invoice #84920 payment confirmation. Dear Customer, your recent transaction of $142.50 has settled successfully. Thank you for your business."
    },
    {
        "id": "bn_109",
        "category": "benign_email",
        "text": "Good morning Alex, Can we reschedule our 1:1 to Thursday afternoon at 3:00 PM EST? A conflict came up with the quarterly executive review."
    },
    {
        "id": "bn_110",
        "category": "benign_email",
        "text": "Support Ticket #49201: The user reported that clicking on the profile picture upload button triggers a timeout error when using Safari on macOS."
    },
    {
        "id": "bn_111",
        "category": "benign_email",
        "text": "Welcome to the Engineering Book Club! This month we are reading 'Designing Data-Intensive Applications' by Martin Kleppmann. Chapter 1 discussion starts Friday."
    },
    {
        "id": "bn_112",
        "category": "benign_email",
        "text": "Reminder: All employees must submit their open enrollment benefit elections through Workday before the November 15 deadline."
    },
    {
        "id": "bn_113",
        "category": "benign_email",
        "text": "Hello Dr. Patterson, Thank you for sending over the lab results for patient #30291. We will schedule a follow-up consultation early next week."
    },
    {
        "id": "bn_114",
        "category": "benign_email",
        "text": "Subject: New commit deployed to staging environment (v2.4.1-rc3). Release notes include optimizations to the database query pool and minor bug fixes."
    },
    {
        "id": "bn_115",
        "category": "benign_email",
        "text": "Hi David, Could you please send me the latest deck for the investor meeting? We need to verify slide 8 financials before the rehearsal."
    },
    {
        "id": "bn_116",
        "category": "benign_email",
        "text": "Order confirmation: Your reservation at The Bistro for 4 guests on Friday, Oct 24 at 7:30 PM is confirmed. We look forward to seeing you."
    },
    {
        "id": "bn_117",
        "category": "benign_email",
        "text": "HR Announcement: Our annual company hackathon will take place virtually on December 3-5. Sign up your team by November 20 to participate."
    },
    {
        "id": "bn_118",
        "category": "benign_email",
        "text": "Security Notice: Routine password rotation reminder. Remember that legitimate IT staff will never ask for your password via chat or email."
    },

    # --- Realistic Code & Technical Snippets (12) ---
    {
        "id": "bn_119",
        "category": "benign_code",
        "text": "def calculate_discount(price: float, rate: float) -> float:\n    \"\"\"Calculates net price after applying percentage discount.\"\"\"\n    if not 0.0 <= rate <= 1.0:\n        raise ValueError('Rate must be between 0 and 1')\n    return round(price * (1 - rate), 2)"
    },
    {
        "id": "bn_120",
        "category": "benign_code",
        "text": "SELECT customer_id, SUM(order_total) AS total_spend, COUNT(id) AS num_orders FROM customer_orders WHERE created_at >= '2025-01-01' GROUP BY customer_id HAVING total_spend > 1000 ORDER BY total_spend DESC LIMIT 20;"
    },
    {
        "id": "bn_121",
        "category": "benign_code",
        "text": "const fetchUserProfile = async (userId) => {\n  const res = await fetch(`/api/v1/users/${userId}`);\n  if (!res.ok) throw new Error(`HTTP error ${res.status}`);\n  return await res.json();\n};"
    },
    {
        "id": "bn_122",
        "category": "benign_code",
        "text": "version: '3.8'\nservices:\n  redis:\n    image: redis:7-alpine\n    ports:\n      - '6379:6379'\n    restart: always\n    volumes:\n      - redis_data:/data\nvolumes:\n  redis_data:"
    },
    {
        "id": "bn_123",
        "category": "benign_code",
        "text": "import re\n\ndef is_valid_hex_color(code: str) -> bool:\n    \"\"\"Checks if a string is a valid 3 or 6 hex character CSS color code.\"\"\"\n    return bool(re.fullmatch(r'#(?:[0-9a-fA-F]{3}){1,2}', code))"
    },
    {
        "id": "bn_124",
        "category": "benign_code",
        "text": "class CircularBuffer:\n    def __init__(self, capacity: int):\n        self.buffer = [None] * capacity\n        self.head = 0\n        self.tail = 0\n        self.capacity = capacity"
    },
    {
        "id": "bn_125",
        "category": "benign_code",
        "text": "git checkout -b feature/auth-jwt-refresh\ngit add app/security/auth.py\ngit commit -m 'feat: add rotating refresh tokens with 7-day expiration'\ngit push -u origin feature/auth-jwt-refresh"
    },
    {
        "id": "bn_126",
        "category": "benign_code",
        "text": "import csv\nwith open('sales_q3.csv', mode='r', encoding='utf-8') as f:\n    reader = csv.DictReader(f)\n    total_revenue = sum(float(row['revenue']) for row in reader)"
    },
    {
        "id": "bn_127",
        "category": "benign_code",
        "text": "<div class=\"user-card\">\n  <img src=\"/static/avatar.png\" alt=\"User avatar\" class=\"rounded-circle\" />\n  <h3>Alice Smith</h3>\n  <p>Lead Infrastructure Engineer</p>\n</div>"
    },
    {
        "id": "bn_128",
        "category": "benign_code",
        "text": "curl -X POST https://api.stripe.com/v1/payment_intents -u sk_test_mockkey: -d amount=2000 -d currency=usd"
    },
    {
        "id": "bn_129",
        "category": "benign_code",
        "text": "def binary_search(arr, target):\n    low, high = 0, len(arr) - 1\n    while low <= high:\n        mid = (low + high) // 2\n        if arr[mid] == target:\n            return mid\n        elif arr[mid] < target:\n            low = mid + 1\n        else:\n            high = mid - 1\n    return -1"
    },
    {
        "id": "bn_130",
        "category": "benign_code",
        "text": "CREATE INDEX idx_audit_created ON audit_records (created_at DESC, user_id);"
    },

    # --- Realistic Multilingual Text Across 8 Languages (16) ---
    {
        "id": "bn_131",
        "category": "benign_multilingual_hi",
        "text": "नमस्ते, क्या आप मुझे भारत के प्रमुख राष्ट्रीय उद्यानों और उनके संरक्षण प्रयासों के बारे में बता सकते हैं?"
    },
    {
        "id": "bn_132",
        "category": "benign_multilingual_hi",
        "text": "कृपया इस लेख का हिंदी में अनुवाद करें ताकि हमारे छात्र सौर ऊर्जा के लाभों को समझ सकें।"
    },
    {
        "id": "bn_133",
        "category": "benign_multilingual_ta",
        "text": "வணக்கம், தஞ்சை பெரிய கோயிலின் கட்டிடக்கலை சிறப்புகள் மற்றும் வரலாற்று முக்கியத்துவத்தை விளக்குங்கள்."
    },
    {
        "id": "bn_134",
        "category": "benign_multilingual_ta",
        "text": "பாரதியாரின் புகழ்பெற்ற கவிதைகளில் உள்ள விடுதலை உணர்வைப் பற்றி ஒரு சிறிய கட்டுரை எழுதவும்."
    },
    {
        "id": "bn_135",
        "category": "benign_multilingual_es",
        "text": "¿Cuáles son los principales factores económicos que influyen en el comercio internacional entre España y América Latina?"
    },
    {
        "id": "bn_136",
        "category": "benign_multilingual_es",
        "text": "Por favor revisa este resumen del informe de sostenibilidad empresarial para corregir errores ortográficos."
    },
    {
        "id": "bn_137",
        "category": "benign_multilingual_fr",
        "text": "Bonjour, pouvez-vous m'expliquer la différence entre les énergies renouvelables et l'énergie nucléaire en France?"
    },
    {
        "id": "bn_138",
        "category": "benign_multilingual_fr",
        "text": "Veuillez rédiger une lettre de motivation formelle pour un poste de chef de projet informatique."
    },
    {
        "id": "bn_139",
        "category": "benign_multilingual_de",
        "text": "Können Sie mir die rechtlichen Anforderungen der Datenschutz-Grundverordnung (DSGVO) für kleine Unternehmen zusammenfassen?"
    },
    {
        "id": "bn_140",
        "category": "benign_multilingual_de",
        "text": "Guten Tag, bitte übersetzen Sie diesen technischen Auszug über die Funktionsweise von Wärmepumpen ins Deutsche."
    },
    {
        "id": "bn_141",
        "category": "benign_multilingual_zh",
        "text": "请简要介绍一下中国传统节日中秋节的起源、民间习俗以及象征意义。"
    },
    {
        "id": "bn_142",
        "category": "benign_multilingual_zh",
        "text": "量子计算与经典计算的主要区别是什么？它们在加密算法方面的应用前景如何？"
    },
    {
        "id": "bn_143",
        "category": "benign_multilingual_ar",
        "text": "مرحباً، هل يمكنك تلخيص أهم إنجازات علماء العصر الذهبي للإسلام في مجال علم الفلك والرياضيات؟"
    },
    {
        "id": "bn_144",
        "category": "benign_multilingual_ar",
        "text": "أرجو تقديم نصائح عملية لتحسين مهارات الكتابة الأكاديمية باللغة العربية للباحثين الجامعيين."
    },
    {
        "id": "bn_145",
        "category": "benign_multilingual_ru",
        "text": "Здравствуйте! Расскажите, пожалуйста, об основных этапах освоения космического пространства в XX веке."
    },
    {
        "id": "bn_146",
        "category": "benign_multilingual_ru",
        "text": "Помогите составить план урока по классической литературе для старших классов по произведению Льва Толстого."
    },

    # --- Realistic Technical & Business Documents (14) ---
    {
        "id": "bn_147",
        "category": "benign_document",
        "text": "Architecture Decision Record (ADR 014): We have selected PostgreSQL 16 as our primary database engine due to robust JSONB support and mature connection pooling via pgBouncer."
    },
    {
        "id": "bn_148",
        "category": "benign_document",
        "text": "Standard Operating Procedure: When deploying microservices to the staging Kubernetes cluster, verify that all pod readiness probes succeed within 60 seconds."
    },
    {
        "id": "bn_149",
        "category": "benign_document",
        "text": "Market Analysis Report Q4: Cloud infrastructure spending grew by 18% year-over-year, driven primarily by enterprise adoption of hosted AI models."
    },
    {
        "id": "bn_150",
        "category": "benign_document",
        "text": "Terms of Service Section 4.2: The customer retains full intellectual property rights to all proprietary data submitted through the API gateway."
    },
    {
        "id": "bn_151",
        "category": "benign_document",
        "text": "The patient exhibits symptoms consistent with mild seasonal allergic rhinitis. Prescribed 10mg cetirizine daily and recommended saline nasal irrigation."
    },
    {
        "id": "bn_152",
        "category": "benign_document",
        "text": "Nutritional Facts per serving (100g): Calories: 240 kcal, Total Fat: 8g, Saturated Fat: 1.5g, Carbohydrates: 34g, Dietary Fiber: 4g, Protein: 9g."
    },
    {
        "id": "bn_153",
        "category": "benign_document",
        "text": "Flight Itinerary: Departure from SFO at 08:45 AM, Terminal 2, Flight UA 1204. Arrival at ORD at 02:50 PM. Baggage claim at Carousel 4."
    },
    {
        "id": "bn_154",
        "category": "benign_document",
        "text": "Warranty policy: This product is guaranteed against defects in materials and craftsmanship for a period of 24 months from the original date of retail purchase."
    },
    {
        "id": "bn_155",
        "category": "benign_document",
        "text": "Climate Science Brief: Recent satellite observations indicate that global sea surface temperatures have experienced localized anomalies exceeding 1.2 degrees Celsius."
    },
    {
        "id": "bn_156",
        "category": "benign_document",
        "text": "Recipe for Classic French Onion Soup: Caramelize 5 large yellow onions in butter over low heat for 45 minutes, deglaze with dry white wine, add beef broth."
    },
    {
        "id": "bn_157",
        "category": "benign_document",
        "text": "University Course Syllabus: Introduction to Operating Systems (CS 301). Prerequisites: Data Structures and Computer Architecture. Midterm exam: Week 7."
    },
    {
        "id": "bn_158",
        "category": "benign_document",
        "text": "Urban Planning Guidelines: Residential developments within 500 meters of transit hubs must incorporate dedicated bicycle storage and pedestrian-friendly walkways."
    },
    {
        "id": "bn_159",
        "category": "benign_document",
        "text": "Book Review: 'Thinking, Fast and Slow' offers a compelling exploration of behavioral economics, contrasting intuitive fast thinking with deliberate slow logic."
    },
    {
        "id": "bn_160",
        "category": "benign_document",
        "text": "Museum Exhibition Guide: The Impressionism gallery features masterpieces by Monet, Renoir, and Degas, showcasing the revolutionary use of light and color."
    }
]

with open("eval/benign.json", "r", encoding="utf-8") as f:
    existing = json.load(f)

# Append new samples
all_samples = existing + new_samples
with open("eval/benign.json", "w", encoding="utf-8") as f:
    json.dump(all_samples, f, indent=2, ensure_ascii=False)

print(f"Updated eval/benign.json: from {len(existing)} to {len(all_samples)} samples.")
