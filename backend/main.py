
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from src.rag import RAGPipeline

app = FastAPI(title="RAGShield API")

rag = RAGPipeline()


class ChatRequest(BaseModel):
    question: str


@app.get("/")
def home():
    return {"message": "RAGShield API is running"}


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/chat")
def chat(request: ChatRequest):
    if not request.question.strip():
        raise HTTPException(status_code=400, detail="Question cannot be empty")

    try:
        return rag.ask(request.question)
    except Exception:
        raise HTTPException(
            status_code=500,
            detail="An error occurred while generating the answer"
        )
