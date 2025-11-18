"""
Advanced Alerting System
Multi-channel notifications: Email, Slack, Telegram, Webhook
"""

import smtplib
import json
import requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, List, Optional
from datetime import datetime
import time
from collections import deque


class AlertingSystem:
    """Multi-channel alerting system for threat notifications"""
    
    def __init__(self, config: Dict = None):
        """
        Args:
            config: Configuration dictionary with alert channels
                - email: {enabled: bool, smtp_server: str, smtp_port: int, 
                          username: str, password: str, recipients: [str]}
                - slack: {enabled: bool, webhook_url: str, channel: str}
                - telegram: {enabled: bool, bot_token: str, chat_id: str}
                - webhook: {enabled: bool, url: str, headers: dict}
        """
        self.config = config or {}
        self.alert_history = deque(maxlen=1000)
        self.rate_limiter = {}  # {channel: last_sent_time}
        self.min_alert_interval = 60  # Minimum seconds between alerts per channel
        
        # Initialize channels
        self.email_config = self.config.get('email', {})
        self.slack_config = self.config.get('slack', {})
        self.telegram_config = self.config.get('telegram', {})
        self.webhook_config = self.config.get('webhook', {})
    
    def send_alert(self, alert_data: Dict, channels: List[str] = None) -> Dict:
        """
        Send alert through configured channels
        Args:
            alert_data: Alert information
                - severity: 'low', 'medium', 'high', 'critical'
                - title: Alert title
                - message: Alert message
                - threat_type: Type of threat
                - src_ip: Source IP
                - dst_ip: Destination IP
                - timestamp: Alert timestamp
                - details: Additional details dict
            channels: List of channels to use (None = all enabled)
        Returns:
            Result of alert sending
        """
        if channels is None:
            channels = []
            if self.email_config.get('enabled'):
                channels.append('email')
            if self.slack_config.get('enabled'):
                channels.append('slack')
            if self.telegram_config.get('enabled'):
                channels.append('telegram')
            if self.webhook_config.get('enabled'):
                channels.append('webhook')
        
        results = {}
        
        for channel in channels:
            if self._should_send_alert(channel, alert_data.get('severity', 'low')):
                try:
                    if channel == 'email':
                        results['email'] = self._send_email(alert_data)
                    elif channel == 'slack':
                        results['slack'] = self._send_slack(alert_data)
                    elif channel == 'telegram':
                        results['telegram'] = self._send_telegram(alert_data)
                    elif channel == 'webhook':
                        results['webhook'] = self._send_webhook(alert_data)
                    
                    # Update rate limiter
                    self.rate_limiter[channel] = time.time()
                except Exception as e:
                    results[channel] = {'success': False, 'error': str(e)}
            else:
                results[channel] = {'success': False, 'reason': 'rate_limited'}
        
        # Store alert in history
        alert_entry = {
            **alert_data,
            'timestamp': alert_data.get('timestamp', time.time()),
            'channels': channels,
            'results': results
        }
        self.alert_history.append(alert_entry)
        
        return results
    
    def _should_send_alert(self, channel: str, severity: str) -> bool:
        """Check if alert should be sent (rate limiting)"""
        if channel not in self.rate_limiter:
            return True
        
        last_sent = self.rate_limiter[channel]
        time_since_last = time.time() - last_sent
        
        # Adjust interval based on severity
        interval = self.min_alert_interval
        if severity == 'critical':
            interval = 10  # 10 seconds for critical
        elif severity == 'high':
            interval = 30  # 30 seconds for high
        elif severity == 'medium':
            interval = 60  # 1 minute for medium
        
        return time_since_last >= interval
    
    def _send_email(self, alert_data: Dict) -> Dict:
        """Send email alert"""
        if not self.email_config.get('enabled'):
            return {'success': False, 'reason': 'not_enabled'}
        
        try:
            smtp_server = self.email_config.get('smtp_server', 'smtp.gmail.com')
            smtp_port = self.email_config.get('smtp_port', 587)
            username = self.email_config.get('username')
            password = self.email_config.get('password')
            recipients = self.email_config.get('recipients', [])
            
            if not username or not password or not recipients:
                return {'success': False, 'reason': 'missing_config'}
            
            # Create message
            msg = MIMEMultipart()
            msg['From'] = username
            msg['To'] = ', '.join(recipients)
            msg['Subject'] = f"[{alert_data.get('severity', 'ALERT').upper()}] {alert_data.get('title', 'Network Threat Detected')}"
            
            # Create body
            body = self._format_email_body(alert_data)
            msg.attach(MIMEText(body, 'html'))
            
            # Send email
            server = smtplib.SMTP(smtp_server, smtp_port)
            server.starttls()
            server.login(username, password)
            server.send_message(msg)
            server.quit()
            
            return {'success': True, 'recipients': recipients}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _format_email_body(self, alert_data: Dict) -> str:
        """Format email body as HTML"""
        severity = alert_data.get('severity', 'low')
        severity_colors = {
            'critical': '#FF0000',
            'high': '#FF6600',
            'medium': '#FFAA00',
            'low': '#FFDD00'
        }
        color = severity_colors.get(severity, '#000000')
        
        timestamp = datetime.fromtimestamp(
            alert_data.get('timestamp', time.time())
        ).strftime('%Y-%m-%d %H:%M:%S')
        
        html = f"""
        <html>
        <body>
            <h2 style="color: {color};">{alert_data.get('title', 'Network Threat Detected')}</h2>
            <p><strong>Severity:</strong> <span style="color: {color};">{severity.upper()}</span></p>
            <p><strong>Time:</strong> {timestamp}</p>
            <p><strong>Threat Type:</strong> {alert_data.get('threat_type', 'Unknown')}</p>
            <hr>
            <h3>Details:</h3>
            <p>{alert_data.get('message', 'No additional details')}</p>
            <hr>
            <h3>Network Information:</h3>
            <ul>
                <li><strong>Source IP:</strong> {alert_data.get('src_ip', 'Unknown')}</li>
                <li><strong>Destination IP:</strong> {alert_data.get('dst_ip', 'Unknown')}</li>
            </ul>
        </body>
        </html>
        """
        return html
    
    def _send_slack(self, alert_data: Dict) -> Dict:
        """Send Slack alert"""
        if not self.slack_config.get('enabled'):
            return {'success': False, 'reason': 'not_enabled'}
        
        try:
            webhook_url = self.slack_config.get('webhook_url')
            channel = self.slack_config.get('channel', '#alerts')
            
            if not webhook_url:
                return {'success': False, 'reason': 'missing_webhook_url'}
            
            severity = alert_data.get('severity', 'low')
            severity_colors = {
                'critical': 'danger',
                'high': 'warning',
                'medium': 'warning',
                'low': 'good'
            }
            color = severity_colors.get(severity, 'good')
            
            timestamp = datetime.fromtimestamp(
                alert_data.get('timestamp', time.time())
            ).strftime('%Y-%m-%d %H:%M:%S')
            
            payload = {
                'channel': channel,
                'username': 'NetSniff Guard',
                'icon_emoji': ':warning:',
                'attachments': [{
                    'color': color,
                    'title': alert_data.get('title', 'Network Threat Detected'),
                    'fields': [
                        {
                            'title': 'Severity',
                            'value': severity.upper(),
                            'short': True
                        },
                        {
                            'title': 'Time',
                            'value': timestamp,
                            'short': True
                        },
                        {
                            'title': 'Threat Type',
                            'value': alert_data.get('threat_type', 'Unknown'),
                            'short': True
                        },
                        {
                            'title': 'Source IP',
                            'value': alert_data.get('src_ip', 'Unknown'),
                            'short': True
                        },
                        {
                            'title': 'Destination IP',
                            'value': alert_data.get('dst_ip', 'Unknown'),
                            'short': True
                        },
                        {
                            'title': 'Description',
                            'value': alert_data.get('message', 'No additional details'),
                            'short': False
                        }
                    ]
                }]
            }
            
            response = requests.post(webhook_url, json=payload, timeout=10)
            response.raise_for_status()
            
            return {'success': True, 'channel': channel}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _send_telegram(self, alert_data: Dict) -> Dict:
        """Send Telegram alert"""
        if not self.telegram_config.get('enabled'):
            return {'success': False, 'reason': 'not_enabled'}
        
        try:
            bot_token = self.telegram_config.get('bot_token')
            chat_id = self.telegram_config.get('chat_id')
            
            if not bot_token or not chat_id:
                return {'success': False, 'reason': 'missing_config'}
            
            severity = alert_data.get('severity', 'low')
            emoji = '🔴' if severity == 'critical' else '🟠' if severity == 'high' else '🟡'
            
            timestamp = datetime.fromtimestamp(
                alert_data.get('timestamp', time.time())
            ).strftime('%Y-%m-%d %H:%M:%S')
            
            message = f"""
{emoji} <b>{alert_data.get('title', 'Network Threat Detected')}</b>

<b>Severity:</b> {severity.upper()}
<b>Time:</b> {timestamp}
<b>Threat Type:</b> {alert_data.get('threat_type', 'Unknown')}

<b>Details:</b>
{alert_data.get('message', 'No additional details')}

<b>Network Info:</b>
Source IP: {alert_data.get('src_ip', 'Unknown')}
Destination IP: {alert_data.get('dst_ip', 'Unknown')}
            """
            
            url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
            payload = {
                'chat_id': chat_id,
                'text': message,
                'parse_mode': 'HTML'
            }
            
            response = requests.post(url, json=payload, timeout=10)
            response.raise_for_status()
            
            return {'success': True, 'chat_id': chat_id}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _send_webhook(self, alert_data: Dict) -> Dict:
        """Send webhook alert"""
        if not self.webhook_config.get('enabled'):
            return {'success': False, 'reason': 'not_enabled'}
        
        try:
            url = self.webhook_config.get('url')
            headers = self.webhook_config.get('headers', {'Content-Type': 'application/json'})
            
            if not url:
                return {'success': False, 'reason': 'missing_url'}
            
            payload = {
                'alert': alert_data,
                'timestamp': alert_data.get('timestamp', time.time()),
                'source': 'netsniff_guard'
            }
            
            response = requests.post(url, json=payload, headers=headers, timeout=10)
            response.raise_for_status()
            
            return {'success': True, 'status_code': response.status_code}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def get_alert_history(self, time_window: int = 3600) -> List[Dict]:
        """Get alert history within time window"""
        cutoff_time = time.time() - time_window
        return [alert for alert in self.alert_history 
                if alert.get('timestamp', 0) >= cutoff_time]
    
    def test_channels(self) -> Dict:
        """Test all enabled alert channels"""
        test_alert = {
            'severity': 'low',
            'title': 'Test Alert',
            'message': 'This is a test alert from NetSniff Guard',
            'threat_type': 'test',
            'src_ip': '127.0.0.1',
            'dst_ip': '127.0.0.1',
            'timestamp': time.time()
        }
        
        return self.send_alert(test_alert)

