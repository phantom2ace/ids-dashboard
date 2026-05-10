# IDSSD - Intelligent Intrusion Detection System Dashboard

IDSSD is a professional, enterprise-grade Security Operations Center (SOC) dashboard inspired by the Fortinet FortiOS aesthetic. It integrates machine learning-based intrusion detection with real-time monitoring, vulnerability tracking, and automated alerting.

![Dashboard Preview](https://via.placeholder.com/800x450?text=IDSSD+Dashboard+Preview)

## 🚀 Features

- **Enterprise UI**: Fortinet-inspired dark/light technical theme with high-density data visualization.
- **Real-Time Monitoring**: Live alerts log with ML prediction status, severity levels, and CVE deep-links.
- **Machine Learning Integration**: Built-in support for model inference (`ids_model.pkl`) with confidence scoring.
- **Interactive Analytics**: Deep statistical breakdown of attack vectors, traffic trends, and threat timelines.
- **Threat Actor Management**: Dedicated page to monitor malicious IPs with manual Block/Unblock capabilities.
- **Automated Alerting**: Telegram Bot integration for instant notifications on high-severity detections.
- **Investigation Modals**: Detailed technical view for each alert, including raw feature vectors and ML metrics.
- **Data Export**: Export live alert logs to CSV for reporting and forensic analysis.

## 🛠️ Tech Stack

- **Backend**: Flask (Python)
- **Frontend**: Tailwind CSS, Chart.js, Vanilla JavaScript
- **Database**: SQLite3
- **ML Engine**: Scikit-learn, Pandas, Joblib
- **Notifications**: Telegram Bot API

## 📋 Prerequisites

- Python 3.8+
- A trained scikit-learn model saved as `ids_model.pkl` (placed in the root directory).

## ⚙️ Installation & Setup

1. **Clone the repository**:
   ```bash
   git clone https://github.com/YOUR_USERNAME/ids-dashboard.git
   cd ids-dashboard
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure environment variables**:
   Create a `.env` file in the root directory (use `.env.example` as a template):
   ```env
   SECRET_KEY=your_secret_key
   TELEGRAM_BOT_TOKEN=your_bot_token
   TELEGRAM_CHAT_ID=your_chat_id
   ```

4. **Initialize the database**:
   ```bash
   python3 init_db.py
   ```

5. **Run the application**:
   ```bash
   python3 app.py
   ```
   The dashboard will be available at `http://localhost:5000`.

## 🧪 Testing with Simulation

To test the dashboard without live network traffic, use the included simulator:
```bash
python3 simulate_traffic.py
```
This script generates diverse network traffic scenarios (DDoS, SQLi, etc.) and sends them to the dashboard to demonstrate detection and visualization capabilities.

## 🔒 Security Note

- Ensure `.env` and `config.json` are never committed to version control (already configured in `.gitignore`).
- Change the `SECRET_KEY` in production.

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.
