import streamlit as st

if st.button("Show Simulated DNS Packet"):
    st.code("""
    ;; QUESTION SECTION:
    ;www.bank.com.   IN   A

    ;; ANSWER SECTION:
    www.bank.com.  300 IN A 93.184.216.34   ; (spoofed record)

    ;; AUTHORITY SECTION:
    bank.com.  172800 IN NS ns1.bank.com.

    ;; ADDITIONAL SECTION:
    ns1.bank.com. 172800 IN A 192.168.1.1
    """, language="text")