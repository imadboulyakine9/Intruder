This is a highly ambitious but achievable plan for a 2-month PFE, especially since you are using **Kali Linux** (pre-installed tools) and **Celery** (professional async processing).

Since you are the **sole developer**, this roadmap is optimized for "Code once, reuse often."

**Your Architecture:**
*   **OS:** Kali Linux.
*   **Backend:** Python 3 + Flask + Celery (Task Queue) + Redis (Broker) + Flask-SocketIO (Real-time).
*   **Database:** MongoDB (PyMongo).
*   **Frontend:** Bootstrap 5 + Jinja2 Templates.
*   **Tools:** Nmap, Subfinder, Wappalyzer, Nuclei, SQLMap, WPScan, Dalfox.

Here is your **100-Step "Jarvis" Execution Plan**.

---

### Phase 1: The Skeleton & Infrastructure (Week 1)
*Goal: Get the "Hello World" of async tasks working.*

1.  **Repo Setup:** Create a private GitHub repo. Create branches: `dev`, `main`.
2.  **OS Prep:** Update Kali: `sudo apt update && sudo apt install redis-server mongodb`.
3.  **Project Structure:** Create folders: `app/`, `app/templates`, `app/static`, `app/tasks`, `scans/`.
4.  **Virtual Env:** `python3 -m venv venv` and `source venv/bin/activate`.
5.  **Dependencies:** Install `flask`, `celery`, `redis`, `pymongo`, `flask-socketio`, `eventlet`.
6.  **Database Connection:** Write `db.py` to connect to MongoDB.
7.  **Celery Config:** Create `celery_worker.py`. Configure Redis as the broker.
8.  **SocketIO Setup:** Initialize `socketio = SocketIO(app, message_queue='redis://')`.
9.  **Hello World Task:** Write a Celery task that waits 5 seconds and returns "Task Complete".
10. **Hello World UI:** Create a button in Flask that triggers the task.
11. **Verification:** Click button $\to$ Task goes to Redis $\to$ Worker executes $\to$ Result prints in console.
12. **Real-time Test:** Modify the task to emit a SocketIO event ("Progress: 50%").
13. **Frontend Listener:** Add Javascript (`socket.on('message')`) to log the event to the browser console.

### Phase 2: The "Eyes" - Recon Module (Week 2)
*Goal: Input URL, Output Subdomains & Tech stack.*

14. **Tool Check:** Verify `subfinder` and `nmap` are in your generic system path (`which subfinder`).
15. **Wrapper Class:** Create `ScanManager.py`. This class will handle `subprocess.run` calls.
16. **Subdomain Task:** Write a function to run `subfinder -d target.com -o output.txt`.
17. **File Parsing:** Write code to read `output.txt` and clean the data.
18. **DB Save:** Save subdomains to MongoDB `{ "target": "site.com", "subdomains": [...] }`.
19. **Nmap Task:** Write a task for `nmap -F target.com` (Fast scan). Parse XML output.
20. **Wappalyzer:** Install `python-Wappalyzer` or use the CLI wrapper.
21. **Tech Detection:** Integrate Wappalyzer to detect "WordPress", "PHP", "Apache".
22. **The "Recon" UI:** Create `recon.html`. Add checkboxes for [Subfinder], [Nmap], [Wappalyzer].
23. **Progress Bar:** Connect Celery progress updates to a Bootstrap Progress Bar in the UI.
24. **Results Display:** Create a "Recon Results" card showing the list of subdomains found.
25. **Manual Test:** Scan `scanme.nmap.org`. Ensure data appears in MongoDB Compass.

### Phase 3: The "Brain" - Logic & Gamification (Week 3)
*Goal: Jarvis analyzes Recon data and suggests attacks.*

26. **Analysis Engine:** Create `analyzer.py`.
27. **Rule 1 (WP):** `if "WordPress" in technologies: suggest_tool("WPScan")`.
28. **Rule 2 (SQLi):** Parse all URLs found. `if "?" in url: suggest_tool("SQLMap")`.
29. **Rule 3 (General):** Always suggest "Nuclei" for general sweep.
30. **Dashboard Update:** Create the "Mission Control" page.
31. **Card Design:** Use Bootstrap Cards. Title: "Potential Vulnerability". Button: "Launch Attack".
32. **State Management:** Add a `status` field in DB: `scanned`, `analyzed`, `attacking`.
33. **URL Discovery:** Integrate `hakrawler` or `katana` to find URLs with parameters (Essential for SQLMap).
34. **Filter Logic:** Filter URLs to keep only those with parameters (`id=`, `search=`).
35. **DB Update:** Store discovered "Attackable URLs" in a separate collection.

### Phase 4: The "Fist" - Attack Integration (Weeks 4-5)
*Goal: Wrapping the heavy tools (Nuclei, SQLMap, Dalfox).*

**Week 4: Nuclei & Dalfox**
36. **Nuclei Setup:** Ensure `nuclei` binary is ready. Update templates: `nuclei -ut`.
37. **Nuclei Task:** Command: `nuclei -u target.com -json -o results.json`.
38. **JSON Parsing:** Nuclei outputs huge JSON. Write a parser to extract only `info.severity > low`.
39. **Dalfox Setup:** Ensure `dalfox` is installed.
40. **Dalfox Task:** Pass the `katana` URLs to Dalfox: `dalfox file urls.txt`.
41. **XSS Parsing:** Capture the output. If Dalfox finds a PoC, save it to DB.
42. **Real-time Logs:** Make these tools pipe their `stdout` line-by-line to the Frontend via WebSockets.
43. **UI Terminal:** Create a black `div` in HTML that appends these log lines (Matrix style).

**Week 5: SQLMap & WPScan**
44. **SQLMap Logic:** *Crucial Step.* You cannot run SQLMap on the whole domain.
45. **Target Selection:** The task should take *one* specific URL `http://site.com?id=1`.
46. **SQLMap Command:** `sqlmap -u URL --batch --dbs --random-agent --json`.
47. **Optimization:** Add `--timeout=10` to prevent hanging.
48. **WPScan Logic:** Only trigger if Wappalyzer detected WordPress.
49. **WPScan Command:** `wpscan --url target.com --enumerate u,vp`.
50. **Authenticated Scan Logic:** Add an input field in "Recon" for `Cookie String`.
51. **Cookie Passing:** Pass this string to Nuclei (`-H "Cookie: ..."`) and SQLMap (`--cookie "..."`).
52. **Integration Test:** Run a full flow on a Docker DVWA container.

### Phase 5: IDOR & Advanced Features (Week 6)
*Goal: The unique selling point (PFE Bonus).*

53. **IDOR Concept:** Create `idor_engine.py`.
54. **Input UI:** Modal asking for "Cookie User A" and "Cookie User B".
55. **Pattern Matching:** Regex to find numeric IDs in URLs (e.g., `/user/1234`).
56. **The Swap:** Function that takes User A's URL, replaces cookies with User B, and requests it.
57. **Comparison:** Compare HTTP Status Code and Content Length.
58. **False Positive Check:** If sizes are identical, it's likely a finding.
59. **Reporting IDOR:** Save as a "High Severity" finding in DB.
60. **Websocket Polish:** Ensure the "Terminal" auto-scrolls to the bottom.
61. **Stop Button:** Implement a way to kill a Celery task (revoke ID).

### Phase 6: Reporting & Viz (Week 7)
*Goal: Generate the PDF for the Jury.*

62. **Matplotlib:** Write a script to generate a Pie Chart: "Vulnerabilities by Severity".
63. **Chart Saving:** Save the chart as `static/chart_scanID.png`.
64. **PDF Library:** Install `fpdf` or `weasyprint`.
65. **HTML Template:** Create `report_template.html` with placeholders `{{ scan.target }}`, `{{ vulns }}`.
66. **Rendering:** Render HTML with data, then convert to PDF.
67. **Download Button:** In the dashboard, add "Download Report".
68. **Executive Summary:** Auto-generate text: "Jarvis scanned [Target] and found [N] issues."
69. **Cleanup:** Ensure the PDF includes the "Jarvis" logo and your names.

### Phase 7: Testing & Documentation (Week 8)
*Goal: Prepare for the Defense.*

70. **Lab Setup:** Your team members must set up **DVWA** and **Juice Shop** on Docker.
71. **Scenario 1:** Run "Recon" on Juice Shop. Verify Tech detection.
72. **Scenario 2:** Run "SQLMap" on DVWA SQLi Blind section. Verify detection.
73. **Scenario 3:** Run "IDOR" on a custom script (Team member must code a simple vulnerable PHP page).
74. **Bug Fixing:** Fix the inevitable crashes when tools timeout.
75. **Error Handling:** Wrap `subprocess` calls in `try/except` blocks.
76. **Code Cleanup:** Add comments (docstrings) to all Python functions.
77. **Requirements.txt:** `pip freeze > requirements.txt`.
78. **Readme:** Write a professional README on GitHub.
79. **Presentation Slides:** Start making the PPT.
80. **Demo Video:** Record a video of the tool working (Backup in case live demo fails).

---

### Phase 8: The "Polish" (If you have time)
*Little details that get extra points.*

81. **Dark Mode:** Ensure the Bootstrap theme is Dark Mode (Hacker vibe).
82. **Sound Effects:** A tiny "beep" when a scan finishes (Javascript).
83. **History Tab:** View previous scans from MongoDB.
84. **Re-Scan:** Button to restart a scan with same parameters.
85. **Tool Config:** A "Settings" page to add API keys (e.g., for Subfinder pro).
86. **Help Page:** A simple guide on how to use Jarvis.
87. **Login Page:** Simple hardcoded login for the App itself (admin/admin).
88. **Logo:** Design a cool "Jarvis" logo using AI.
89. **Favicon:** Add the logo to the browser tab.
90. **Loading Spinners:** Add CSS animations while waiting for Celery.

### Phase 9: Team Utilization (How to manage your group)

91. **You (Dev):** Focus purely on steps 1-70.
92. **Member 2 (Tester):**
    *   Steps 70-73 (Setting up Docker Labs).
    *   Testing every button you build.
    *   Finding the "Command Line Arguments" that work best for Nuclei/SQLMap so you don't have to guess.
93. **Member 3 (Reporter):**
    *   Writing the "Thesis/Rapport".
    *   Designing the HTML Template for the PDF (Step 65).
    *   Creating the "Custom Vulnerable IDOR Page" (PHP/Python) for the demo.
    *   Steps 79-80 (Slides/Video).

### Final 10 Steps: The Defense Prep
94. **Dry Run 1:** Full scan with team watching.
95. **Dry Run 2:** Full scan on a fresh Kali VM.
96. **Timing:** Measure how long the demo takes. If >10 mins, record a video.
97. **Backup:** Have the PDF reports pre-generated.
98. **Sleep:** Don't code 24 hours before the defense.
99. **Confidence:** You built an Orchestrator. Own it.
100. **Submit.**

**Can you start with Step 1-13 (The Infrastructure) this weekend?** That is the hardest part. Once "Hello World" works with Celery, the rest is just adding scripts.