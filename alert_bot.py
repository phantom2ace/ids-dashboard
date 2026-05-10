import requests
import os

class AlertBot:
    def __init__(self, token=None, chat_id=None):
        # Prefer provided args, then config.json, then env variables
        self.token = token
        self.chat_id = chat_id
        
        if not self.token or not self.chat_id:
            try:
                import json
                with open('config.json', 'r') as f:
                    config = json.load(f)
                    self.token = self.token or config.get('bot_token')
                    self.chat_id = self.chat_id or config.get('chat_id')
            except FileNotFoundError:
                pass

        self.token = self.token or os.environ.get('TELEGRAM_BOT_TOKEN')
        self.chat_id = self.chat_id or os.environ.get('TELEGRAM_CHAT_ID')

    def send_alert(self, message):
        if not self.token or not self.chat_id:
            print("Telegram bot not configured. Alert not sent.")
            return False

        url = f"https://api.telegram.org/bot{self.token}/sendMessage"
        payload = {
            "chat_id": self.chat_id,
            "text": f"🚨 IDS ALERT: {message}",
            "parse_mode": "HTML"
        }
        
        try:
            response = requests.post(url, json=payload)
            return response.status_code == 200
        except Exception as e:
            print(f"Failed to send alert: {e}")
            return False

if __name__ == "__main__":
    # Test alert
    bot = AlertBot()
    bot.send_alert("System initialized and monitoring started.")
