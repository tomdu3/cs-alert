# 🛡️ CS-Alert — Automated Threat Hunting & Playbook API

An intelligent security dashboard that ingests attack data, categorises threats by severity, and automatically serves up NIST-aligned incident response playbooks.

Built with **Python 3.14 · FastAPI · Jinja2 · Vanilla CSS/JS**

---

## 📚 Data References

- **`playbooks.json`**: The incident response playbooks are based on the **[NIST Special Publication 800-61 Revision 2](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)** (Computer Security Incident Handling Guide). They have been adapted into a structured JSON format to enable automated matching and phase-by-phase presentation.
- **`sample_attacks.json`**: Contains synthetically generated sample network, endpoint, and email logs designed to trigger specific detection rules within the Threat Engine. These are provided for testing and demonstration purposes.

---

## 📄 License

MIT
