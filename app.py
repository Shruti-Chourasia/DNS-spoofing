import streamlit as st
from datetime import datetime

# ------------- Initialization (Run Once) -------------
def init_session_state():
    if "dns_cache" not in st.session_state:
        st.session_state["dns_cache"] = {
            "www.bank.com": {"ip": "192.168.1.100", "timestamp": None, "spoofed": False},
            "www.example.com": {"ip": "203.0.113.5", "timestamp": None, "spoofed": False},
            "www.school.edu": {"ip": "198.51.100.42", "timestamp": None, "spoofed": False},
        }
    if "spoofing_enabled" not in st.session_state:
        st.session_state["spoofing_enabled"] = False
    if "phishing_log" not in st.session_state:
        st.session_state["phishing_log"] = []
    if "quiz_answers" not in st.session_state:
        st.session_state["quiz_answers"] = {}

init_session_state()

# ------------- Sidebar Navigation -------------
st.sidebar.title("DNS Spoofing Simulator")
pages = [
    "Home",
    "DNS Lookup",
    "Simulate Spoofing",
    "Fake Site Access",
    "Prevention & Protection"
]
selected_page = st.sidebar.radio("Navigation", pages)

# ------------- Helper Functions -------------
def dns_lookup(domain):
    cache = st.session_state["dns_cache"]
    if domain in cache:
        return cache[domain]["ip"], cache[domain]["spoofed"]
    else:
        return None, False

def spoof_dns(domain, fake_ip):
    cache = st.session_state["dns_cache"]
    cache[domain] = {
        "ip": fake_ip,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "spoofed": True
    }
    st.session_state["dns_cache"] = cache

def reset_cache():
    st.session_state["dns_cache"] = {
        "www.bank.com": {"ip": "192.168.1.100", "timestamp": None, "spoofed": False},
        "www.example.com": {"ip": "203.0.113.5", "timestamp": None, "spoofed": False},
        "www.school.edu": {"ip": "198.51.100.42", "timestamp": None, "spoofed": False},
    }

def get_dns_table():
    cache = st.session_state["dns_cache"]
    table = []
    for domain, data in cache.items():
        table.append({
            "Domain": domain,
            "IP Address": data["ip"],
            "Spoofed?": "Yes" if data["spoofed"] else "No",
            "Timestamp": data["timestamp"] if data["timestamp"] else "-"
        })
    return table

# ------------- 1. Home Page -------------
if selected_page == "Home":
    st.title("🔐 DNS Spoofing Simulator")
    st.markdown("""
    ### What is DNS?
    The **Domain Name System (DNS)** is like the Internet's phonebook. 
    When you type a website (like `www.bank.com`), DNS finds its IP address so your computer can connect.

    #### Example:
    - You enter: `www.bank.com`  
    - DNS responds: `192.168.1.100`

    ---
    ### DNS Request Flow

    ![DNS Flow](https://i.imgur.com/EfZ3W1M.png)
    """)
    st.markdown("""
    1. You ask for a website.
    2. Your computer asks the DNS server for its IP.
    3. DNS server replies with the IP.
    4. Your browser connects you to that IP.

    ---

    ### What is DNS Spoofing/Cache Poisoning?
    - **DNS Spoofing** (or **Cache Poisoning**) means tricking a DNS server into giving out the wrong IP address for a domain.
    - Attackers can redirect you to fake (phishing) websites.

    """)
    st.info("This app is a safe **simulation** of DNS spoofing for learning purposes only.")

    st.divider()

    # Spoofing Toggle
    st.markdown("#### DNS Spoofing Simulation Toggle")
    spoofing_toggle = st.checkbox("Enable DNS Spoofing", value=st.session_state["spoofing_enabled"])
    st.session_state["spoofing_enabled"] = spoofing_toggle

    if spoofing_toggle:
        st.warning("Spoofing is ENABLED. DNS lookups will use spoofed (fake) results if available.", icon="⚠️")
    else:
        st.success("Spoofing is DISABLED. DNS lookups will use real (simulated) results.", icon="✅")

# ------------- 2. DNS Lookup Page -------------
elif selected_page == "DNS Lookup":
    st.title("🔎 DNS Lookup")
    st.markdown("Enter a domain name below to see how DNS resolves it.")

    with st.form(key="dns_lookup_form"):
        domain = st.text_input("Domain", value="www.bank.com")
        submitted = st.form_submit_button("Lookup")

    if submitted:
        cache = st.session_state["dns_cache"]
        spoofing = st.session_state["spoofing_enabled"]
        if domain not in cache:
            st.error("Domain not found in DNS cache. Try one of: " + ", ".join(cache.keys()))
        else:
            record = cache[domain]
            if spoofing and record["spoofed"]:
                st.warning(f"DNS Spoofing is ON! Showing spoofed IP for {domain}.", icon="⚠️")
            elif spoofing:
                st.info(f"DNS Spoofing is ON, but no spoofed record found for {domain}.", icon="ℹ️")
            else:
                st.success(f"Showing real (simulated) IP for {domain}.", icon="✅")
            st.markdown(f"**{domain} resolves to:**")
            st.code(record['ip'])

    st.divider()
    st.markdown("#### DNS Cache Table")
    st.table(get_dns_table())

    st.button("Reset DNS Cache", on_click=reset_cache)

# ------------- 3. Simulate Spoofing Page -------------
elif selected_page == "Simulate Spoofing":
    st.title("💀 Simulate DNS Spoofing / Cache Poisoning")
    st.markdown("""
    Here, you can simulate a DNS cache poisoning attack by injecting a fake IP for any domain.
    """)

    with st.form("poison_form"):
        domain = st.text_input("Domain to Spoof", value="www.bank.com")
        fake_ip = st.text_input("Attacker's Fake IP", value="93.184.216.34")
        poison_btn = st.form_submit_button("Poison Cache")

    if poison_btn:
        if not domain or not fake_ip:
            st.error("Both domain and attacker IP are required.")
        else:
            spoof_dns(domain, fake_ip)
            st.success(f"Spoofed {domain} to resolve to {fake_ip}")

    st.markdown("#### Current DNS Cache")
    st.table(get_dns_table())

    st.button("Reset DNS Cache", on_click=reset_cache)

    st.error("⚠️ This is a simulation. No real DNS servers or domains are affected.", icon="🚫")

# ------------- 4. Fake Site Access Page -------------
elif selected_page == "Fake Site Access":
    st.title("🏦 Visit Bank Website (Simulated)")
    st.markdown("""
    Simulate what happens when visiting a website that may be spoofed by a DNS attack.
    """)

    cache = st.session_state["dns_cache"]
    spoofing = st.session_state["spoofing_enabled"]

    domain = st.selectbox("Choose a domain to visit", list(cache.keys()), index=0)
    record = cache[domain]
    is_spoofed = record["spoofed"] and spoofing

    if is_spoofed:
        st.error("You have been redirected to a spoofed (phishing) site! (Simulation)", icon="⚠️")
        st.markdown("## 🛑 Spoofed Site (Phishing Simulation)")
        st.markdown("**This is a fake login page designed to steal your credentials.**")
        with st.form("phish_login"):
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            login_submitted = st.form_submit_button("Login (Simulated)")
            if login_submitted:
                st.session_state["phishing_log"].append({
                    "domain": domain,
                    "username": username,
                    "password": password,
                    "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                })
                st.warning("Your credentials have been 'stolen' (simulated)!", icon="😱")
                st.code(f"Stolen credentials: {username} / {password}")

        if st.button("Show Attacker Log"):
            st.markdown("#### Attacker's Log (Simulation Only)")
            if st.session_state["phishing_log"]:
                for entry in st.session_state["phishing_log"]:
                    st.write(entry)
            else:
                st.info("No credentials have been stolen yet (simulation).")
    else:
        st.success("You are visiting the correct bank website (simulation).", icon="✅")
        st.markdown("""
        <div style='background-color: #f5fafd; padding: 2em; border-radius: 8px;'>
        <h3>Welcome to Secure Bank</h3>
        <form>
        <label>Username</label><br>
        <input type="text" placeholder="Enter username"><br>
        <label>Password</label><br>
        <input type="password" placeholder="Enter password"><br>
        <button disabled style="background-color: #5cb85c; color: white; margin-top: 1em;">Login (Disabled)</button>
        </form>
        <p style="color: gray; font-size: 0.9em;">🔒 This is a safe, non-interactive demo page.</p>
        </div>
        """, unsafe_allow_html=True)

# ------------- 5. Prevention & Protection Page -------------
elif selected_page == "Prevention & Protection":
    st.title("🛡️ Prevention & Protection")

    st.markdown("""
    ## How to Prevent DNS Spoofing?
    - **DNSSEC**: DNS Security Extensions add cryptographic signatures to DNS records, preventing tampering.
    - **HTTPS (SSL/TLS)**: Secure connections ensure you talk to the real website, not a fake one.
    - **Certificate Pinning**: Browsers check website certificates, making spoofing harder.
    - **Trusted DNS Providers**: Use known DNS servers like Google DNS (`8.8.8.8`), Cloudflare, or OpenDNS.
    - **Check URLs**: Always verify links before entering credentials.
    """)

    st.divider()
    st.header("Test Your Knowledge! (Quiz)")

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

    if "quiz_answers" not in st.session_state:
        st.session_state["quiz_answers"] = {}

    for i, q in enumerate(quiz):
        st.session_state["quiz_answers"][i] = st.radio(
            f"Q{i+1}: {q['q']}",
            q['options'],
            key=f"quiz_q{i}"
        )

    if st.button("Submit Quiz"):
        score = 0
        for i, q in enumerate(quiz):
            user_ans = st.session_state["quiz_answers"][i]
            correct_ans = q['options'][q['answer']]
            is_correct = (user_ans == correct_ans)
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

    st.divider()
    st.markdown("""
    **Responsible Cybersecurity Practice:**  
    - Never try to attack real DNS infrastructure.
    - Only use these techniques in safe, educational labs.
    - Protect yourself and others online!
    """)
    st.markdown("""        **🎯 How Actual DNS Spoofing is Done (Step-by-Step)**

**✅ Technique 1: DNS Cache Poisoning**

a). Attacker sends a fake DNS response with incorrect IP to the DNS resolver.

b). If timed correctly, the resolver caches the fake IP for the domain.

c). Any user querying that domain now receives the attacker’s IP.

📌 Key Element: The attacker must guess the correct transaction ID and match the request source port to succeed.

**✅ Technique 2: Man-in-the-Middle (MitM) DNS Spoofing**

a). Attacker positions themselves between the victim and DNS server (e.g., on a public Wi-Fi).

b). Intercepts DNS queries and responds with forged DNS answers.

c). Victim’s system resolves domain to malicious IP.

**✅ Technique 3: Rogue DNS Server Setup**

a). Attacker configures the victim’s system (via malware or DHCP spoofing) to use a malicious DNS server.

b). All DNS requests go through the attacker’s DNS server.

c). Attacker selectively returns fake responses for key domains.

**🛠 Tools Commonly Used for DNS Spoofing**

 **Tool**	     **Purpose**

 Ettercap - ARP spoofing and DNS spoofing in LAN

 dnsspoof - Intercept DNS requests and spoof replies

 Bettercap - MitM framework including DNS spoofing

 Responder - DNS/NBNS spoofing for Windows networks


""")