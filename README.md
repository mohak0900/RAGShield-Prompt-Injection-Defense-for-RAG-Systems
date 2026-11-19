# RAGShield 🛡️
**Prompt Injection Detection & Defense for RAG Applications**

RAGShield is a security-focused RAG application that detects malicious instructions in retrieved documents, blocks unsafe context, and filters sensitive information from generated responses.

### Tech Stack
Python · FastAPI · Streamlit · ChromaDB · Sentence Transformers · Groq API

### Key Features
- Semantic document retrieval using ChromaDB.
- Regex-based prompt injection detection.
- Malicious document filtering before LLM generation.
- Sensitive information redaction.
- Interactive security monitoring dashboard.

### Security Evaluation

| Metric | Result |
|---|---:|
| Synthetic attack patterns detected | 10/10 |
| Normal chunks incorrectly flagged | 0/51 |
| Controlled attack scenarios detected | 5/5 |
| Fake secret leaks in controlled tests | 0 |

*Results are from a limited synthetic test suite, not a guarantee of production-level security.*

### Run Locally

```bash
pip install -r requirements.txt
```

Set your `GROQ_API_KEY` and `GROQ_MODEL` environment variables, then start the backend:

```bash
$env:PYTHONPATH="$PWD\backend"
uvicorn main:app --app-dir backend --reload
```

In a second terminal:

```bash
streamlit run frontend/app.py
```
