import streamlit as st

# Quiz data
quiz = [
    {
        "q": "What does DNS do?",
        "options": [
            "Stores your passwords",
            "Maps domain names to IP addresses",
            "Encrypts your emails",
            "Connects to WiFi"
        ],
        "answer": 1,
        "explanation": "DNS maps human-friendly domain names to IP addresses."
    },
    {
        "q": "What is DNS Spoofing (Cache Poisoning)?",
        "options": [
            "Making DNS faster",
            "Tricking DNS servers into giving wrong IPs",
            "Encrypting data",
            "Clearing browser cache"
        ],
        "answer": 1,
        "explanation": "DNS spoofing means providing false IP addresses for domains."
    },
    {
        "q": "Which technology protects DNS records with cryptographic signatures?",
        "options": [
            "HTTP",
            "DNSSEC",
            "FTP",
            "SMTP"
        ],
        "answer": 1,
        "explanation": "DNSSEC uses cryptographic signatures to protect DNS records."
    },
    {
        "q": "How can you spot a spoofed (phishing) site?",
        "options": [
            "Check for HTTPS and valid certificate",
            "It always uses bright colors",
            "It loads very slowly",
            "It asks for a phone number"
        ],
        "answer": 0,
        "explanation": "A real site should use HTTPS and have a valid certificate."
    }
]

st.title("DNS Security Quiz")

if "quiz_answers" not in st.session_state:
    st.session_state["quiz_answers"] = {}

# Render quiz
for i, q in enumerate(quiz):
    st.session_state["quiz_answers"][i] = st.radio(
        f"Q{i+1}: {q['q']}", q['options'], key=f"quiz_q{i}")

if st.button("Submit Quiz"):
    score = 0
    for i, q in enumerate(quiz):
        user_ans = st.session_state["quiz_answers"][i]
        correct_ans = q['options'][q['answer']]
        is_correct = (user_ans == correct_ans)

        # Highlighting with HTML/CSS
        if is_correct:
            st.markdown(
                f"<div style='background-color:#e6ffe6;padding:10px;border-radius:6px'><b>Q{i+1} Correct ✔️</b><br>"
                f"<span style='color:green;'>Your answer: {user_ans}</span></div>",
                unsafe_allow_html=True)
            score += 1
        else:
            st.markdown(
                f"<div style='background-color:#ffe6e6;padding:10px;border-radius:6px'><b>Q{i+1} Incorrect ❌</b><br>"
                f"<span style='color:red;'>Your answer: {user_ans}</span><br>"
                f"<span style='color:green;'>Correct answer: {correct_ans}</span></div>",
                unsafe_allow_html=True)
        st.info(f"Explanation: {q['explanation']}")
    st.markdown(
        f"<h3 style='color:#155724;background-color:#d4edda;padding:10px;border-radius:6px;'>Total Score: {score} / {len(quiz)}</h3>",
        unsafe_allow_html=True)