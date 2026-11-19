
import streamlit as st
import requests

st.set_page_config(
    page_title="RAGShield",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ RAGShield")
st.caption("Prompt Injection Detection & Defense for RAG Applications")

API_URL = "http://127.0.0.1:8000/chat"

# Initialize chat history
if "messages" not in st.session_state:
    st.session_state.messages = []

# Calculate session security metrics
assistant_messages = [
    msg for msg in st.session_state.messages
    if msg["role"] == "assistant"
]

total_questions = len(assistant_messages)

total_detected = sum(
    1 for msg in assistant_messages
    if msg.get("security", {}).get("injection_detected", False)
)

total_blocked = sum(
    msg.get("security", {}).get("flagged_count", 0)
    for msg in assistant_messages
)
detection_rate = (
    (total_detected / total_questions) * 100
    if total_questions > 0
    else 0
)

# Security dashboard
with st.sidebar:
    st.header("🛡️ Security Dashboard")

    st.metric("Questions Asked", total_questions)
    st.metric("Injections Detected", total_detected)
    st.metric("Malicious Chunks Blocked", total_blocked)
    st.metric("Detection Rate", f"{detection_rate:.1f}%")

    if total_detected > 0:
        st.warning("Prompt injection activity detected!")
    else:
        st.success("No injection detected in this session.")

    if st.button("Clear Chat & Dashboard"):
        st.session_state.messages = []
        st.rerun()

st.divider()

# Display previous chat messages
for message in st.session_state.messages:

    with st.chat_message(message["role"]):
        st.markdown(message["content"])

        if message["role"] == "assistant":

            security = message.get("security", {})

            if security.get("injection_detected", False):
                st.warning("⚠️ Prompt injection detected!")
            else:
                st.success("✅ No prompt injection detected.")

            st.caption(
                f"Malicious chunks blocked: "
                f"{security.get('flagged_count', 0)}"
            )

            with st.expander("View Security Analysis"):

                st.write("**Safe Documents**")

                for chunk in message.get("safe_chunks", []):
                    st.write(f"Source: {chunk['source']}")
                    st.write(chunk["text"])
                    st.divider()

                st.write("**Flagged Documents**")

                flagged = message.get("flagged_chunks", [])

                if flagged:
                    for chunk in flagged:
                        st.error(f"Blocked: {chunk['source']}")
                        st.write(chunk["text"])
                        st.divider()
                else:
                    st.success("No malicious documents flagged.")

# Chat input
question = st.chat_input("Ask a question about your account...")

if question:

    st.session_state.messages.append({
        "role": "user",
        "content": question
    })

    with st.chat_message("user"):
        st.markdown(question)

    with st.chat_message("assistant"):

        with st.spinner("Searching knowledge base and checking security..."):

            try:
                response = requests.post(
                    API_URL,
                    json={"question": question},
                    timeout=120
                )

                response.raise_for_status()
                data = response.json()

                answer = data["answer"]
                safe_chunks = data.get("safe_chunks", [])
                flagged_chunks = data.get("flagged_chunks", [])
                security = data.get("security", {})

                st.markdown(answer)

                if security.get("injection_detected", False):
                    st.warning("⚠️ Prompt injection detected!")
                else:
                    st.success("✅ No prompt injection detected.")

                st.caption(
                    f"Malicious chunks blocked: "
                    f"{security.get('flagged_count', 0)}"
                )

                with st.expander("View Security Analysis"):

                    st.write("**Safe Documents**")

                    for chunk in safe_chunks:
                        st.write(f"Source: {chunk['source']}")
                        st.write(chunk["text"])
                        st.divider()

                    st.write("**Flagged Documents**")

                    if flagged_chunks:
                        for chunk in flagged_chunks:
                            st.error(f"Blocked: {chunk['source']}")
                            st.write(chunk["text"])
                            st.divider()
                    else:
                        st.success("No malicious documents flagged.")

                st.session_state.messages.append({
                    "role": "assistant",
                    "content": answer,
                    "safe_chunks": safe_chunks,
                    "flagged_chunks": flagged_chunks,
                    "security": security
                })

            except requests.RequestException:
                st.error(
                    "Could not connect to the RAGShield backend. "
                    "Make sure the FastAPI server is running."
                )
