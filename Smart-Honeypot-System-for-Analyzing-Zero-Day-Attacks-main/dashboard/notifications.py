"""
Notification System for Smart Honeypot
---------------------------------------
Email (Gmail) + SMS (Twilio - free trial available) alerts
jab bhi CRITICAL ya HIGH severity alert aaye.

Setup:
  pip install twilio

Fir honeypot/settings.py mein add karo (neeche diya hai).
"""

import logging
from django.core.mail import send_mail, EmailMultiAlternatives
from django.conf import settings
from django.utils import timezone

logger = logging.getLogger('honeypot')


# -------------------------------------------------
# EMAIL NOTIFICATION
# -------------------------------------------------

def send_email_alert(alert):
    """
    Critical/High alert pe email bhejta hai.
    Gmail SMTP use karta hai (settings.py mein configure karo).
    """
    if not getattr(settings, 'ALERT_EMAIL_ENABLED', False):
        return

    recipient = getattr(settings, 'ALERT_EMAIL_TO', None)
    if not recipient:
        logger.warning("ALERT_EMAIL_TO settings mein nahi hai.")
        return

    severity_emoji = {
        'CRITICAL': '🚨',
        'HIGH':     '⚠️',
        'MEDIUM':   '🔔',
        'LOW':      'ℹ️',
        'INFO':     '📋',
    }
    emoji = severity_emoji.get(alert.severity, '🔔')

    subject = f"{emoji} [{alert.severity}] Honeypot Alert: {alert.title}"

    text_body = f"""
Smart Honeypot — Security Alert
================================
Severity  : {alert.severity}
Type      : {alert.get_alert_type_display()}
IP Address: {alert.ip_address or 'N/A'}
Time      : {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')}

{alert.description}

Dashboard: http://127.0.0.1:8000/
    """.strip()

    colour = {
        'CRITICAL': '#e53e3e',
        'HIGH':     '#dd6b20',
        'MEDIUM':   '#d69e2e',
        'LOW':      '#3182ce',
        'INFO':     '#718096',
    }.get(alert.severity, '#718096')

    html_body = f"""
    <div style="font-family:Arial,sans-serif;max-width:600px;margin:auto">
      <div style="background:{colour};color:#fff;padding:16px 24px;border-radius:8px 8px 0 0">
        <h2 style="margin:0">{emoji} {alert.severity} Alert</h2>
        <p style="margin:4px 0 0">{alert.title}</p>
      </div>
      <div style="background:#f7fafc;padding:24px;border:1px solid #e2e8f0;border-radius:0 0 8px 8px">
        <table style="width:100%;border-collapse:collapse">
          <tr><td style="padding:6px 0;color:#718096;width:120px">Type</td>
              <td style="padding:6px 0;font-weight:600">{alert.get_alert_type_display()}</td></tr>
          <tr><td style="padding:6px 0;color:#718096">IP Address</td>
              <td style="padding:6px 0;font-weight:600">{alert.ip_address or 'N/A'}</td></tr>
          <tr><td style="padding:6px 0;color:#718096">Time</td>
              <td style="padding:6px 0">{alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')}</td></tr>
        </table>
        <hr style="border:none;border-top:1px solid #e2e8f0;margin:16px 0">
        <p style="color:#4a5568">{alert.description}</p>
        <a href="http://127.0.0.1:8000/alerts/"
           style="display:inline-block;margin-top:12px;background:{colour};
                  color:#fff;padding:10px 20px;border-radius:6px;text-decoration:none">
          Dashboard Dekho
        </a>
      </div>
    </div>
    """

    try:
        msg = EmailMultiAlternatives(
            subject=subject,
            body=text_body,
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=[recipient],
        )
        msg.attach_alternative(html_body, "text/html")
        msg.send()
        logger.info(f"Email alert bheja: {alert.title} to {recipient}")
    except Exception as e:
        logger.error(f"Email bhejne mein error: {e}")


# -------------------------------------------------
# RESOLUTION EMAIL  <-- NEW
# -------------------------------------------------

def send_resolution_email(alert):
    """
    Alert resolve/escalate hone pe email bhejta hai.
    """
    if not getattr(settings, 'ALERT_EMAIL_ENABLED', False):
        return

    recipient = getattr(settings, 'ALERT_EMAIL_TO', None)
    if not recipient:
        return

    status_info = {
        'RESOLVED':  ('✅', '#38a169', 'Alert Resolved'),
        'ESCALATED': ('⚠️', '#e53e3e', 'Alert Escalated'),
    }
    emoji, colour, label = status_info.get(alert.status, ('🔔', '#718096', 'Alert Updated'))

    subject = f"{emoji} [{label}] {alert.title}"

    resolved_at = alert.resolved_at.strftime('%Y-%m-%d %H:%M:%S') if alert.resolved_at else 'N/A'

    text_body = f"""
Smart Honeypot — Alert {label}
================================
Alert     : {alert.title}
Severity  : {alert.severity}
IP Address: {alert.ip_address or 'N/A'}
Status    : {alert.status}
Resolved By: {alert.resolved_by or 'N/A'}
Time      : {resolved_at}
Note      : {alert.resolution_note or 'No note'}

Dashboard: http://127.0.0.1:8000/alerts/
    """.strip()

    html_body = f"""
    <div style="font-family:Arial,sans-serif;max-width:600px;margin:auto">
      <div style="background:{colour};color:#fff;padding:16px 24px;border-radius:8px 8px 0 0">
        <h2 style="margin:0">{emoji} {label}</h2>
        <p style="margin:4px 0 0">{alert.title}</p>
      </div>
      <div style="background:#f7fafc;padding:24px;border:1px solid #e2e8f0;border-radius:0 0 8px 8px">
        <table style="width:100%;border-collapse:collapse">
          <tr><td style="padding:6px 0;color:#718096;width:130px">Severity</td>
              <td style="padding:6px 0;font-weight:600">{alert.severity}</td></tr>
          <tr><td style="padding:6px 0;color:#718096">IP Address</td>
              <td style="padding:6px 0;font-weight:600">{alert.ip_address or 'N/A'}</td></tr>
          <tr><td style="padding:6px 0;color:#718096">Resolved By</td>
              <td style="padding:6px 0;font-weight:600">{alert.resolved_by or 'N/A'}</td></tr>
          <tr><td style="padding:6px 0;color:#718096">Time</td>
              <td style="padding:6px 0">{resolved_at}</td></tr>
        </table>
        <hr style="border:none;border-top:1px solid #e2e8f0;margin:16px 0">
        <p style="color:#4a5568"><strong>Note:</strong> {alert.resolution_note or 'No note provided'}</p>
        <a href="http://127.0.0.1:8000/alerts/"
           style="display:inline-block;margin-top:12px;background:{colour};
                  color:#fff;padding:10px 20px;border-radius:6px;text-decoration:none">
          Dashboard Dekho
        </a>
      </div>
    </div>
    """

    try:
        msg = EmailMultiAlternatives(
            subject=subject,
            body=text_body,
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=[recipient],
        )
        msg.attach_alternative(html_body, "text/html")
        msg.send()
        logger.info(f"Resolution email bheja: {alert.title} to {recipient}")
    except Exception as e:
        logger.error(f"Resolution email error: {e}")


# -------------------------------------------------
# SMS NOTIFICATION (Twilio)
# -------------------------------------------------

def send_sms_alert(alert):
    """
    Critical alert pe SMS bhejta hai via Twilio.
    Free trial mein ~1500 SMS milte hain.
    """
    if not getattr(settings, 'ALERT_SMS_ENABLED', False):
        return

    try:
        from twilio.rest import Client
    except ImportError:
        logger.error("Twilio install nahi hai. Run: pip install twilio")
        return

    sid   = getattr(settings, 'TWILIO_ACCOUNT_SID', None)
    token = getattr(settings, 'TWILIO_AUTH_TOKEN', None)
    from_ = getattr(settings, 'TWILIO_FROM_NUMBER', None)
    to    = getattr(settings, 'ALERT_SMS_TO', None)

    if not all([sid, token, from_, to]):
        logger.warning("Twilio settings incomplete hain.")
        return

    body = (
        f"[HONEYPOT] {alert.severity} ALERT!\n"
        f"Type: {alert.get_alert_type_display()}\n"
        f"IP: {alert.ip_address or 'N/A'}\n"
        f"{alert.title[:80]}"
    )

    try:
        client = Client(sid, token)
        message = client.messages.create(body=body, from_=from_, to=to)
        logger.info(f"SMS bheja: SID={message.sid}")
    except Exception as e:
        logger.error(f"SMS bhejne mein error: {e}")


# -------------------------------------------------
# MAIN FUNCTION
# -------------------------------------------------

def notify_on_alert(alert):
    """
    Ye function call karo jab naya alert bane.
    Severity ke hisaab se email/SMS bhejta hai:
      CRITICAL → Email + SMS
      HIGH     → Email only
      MEDIUM/LOW/INFO → kuch nahi (configure kar sakte ho)
    """
    if alert.severity == 'CRITICAL':
        send_email_alert(alert)
        send_sms_alert(alert)
    elif alert.severity == 'HIGH':
        send_email_alert(alert)
    # LOW/MEDIUM ke liye bhi chahiye to ye line uncomment karo:
    # elif alert.severity in ('MEDIUM', 'LOW'):
    #     send_email_alert(alert)
