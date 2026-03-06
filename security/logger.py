"""
Comprehensive logging and audit trail
"""

import logging
import logging.handlers
import json
from datetime import datetime, timezone
from config import get_config

config = get_config()

# ===========================
# STRUCTURED LOGGING
# ===========================

class JSONFormatter(logging.Formatter):
    """JSON format for logs"""
    
    def format(self, record):
        log_obj = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
        }
        
        # Add extra fields if present
        if hasattr(record, 'user_id'):
            log_obj['user_id'] = record.user_id
        if hasattr(record, 'ip'):
            log_obj['ip'] = record.ip
        if hasattr(record, 'action'):
            log_obj['action'] = record.action
        
        return json.dumps(log_obj)

# ===========================
# LOGGER SETUP
# ===========================

def setup_logging():
    """Setup all loggers"""
    
    # Main application logger
    app_logger = logging.getLogger('app')
    app_logger.setLevel(getattr(logging, config.LOG_LEVEL))
    
    # File handler with rotation
    app_handler = logging.handlers.RotatingFileHandler(
        config.LOG_FILE,
        maxBytes=config.LOG_MAX_SIZE_MB * 1024 * 1024,
        backupCount=config.LOG_BACKUP_COUNT
    )
    
    if config.LOG_FORMAT == 'json':
        formatter = JSONFormatter()
    else:
        formatter = logging.Formatter(
            '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
        )
    
    app_handler.setFormatter(formatter)
    app_logger.addHandler(app_handler)
    
    # Security logger
    security_logger = logging.getLogger('security')
    security_logger.setLevel(logging.WARNING)
    
    security_handler = logging.handlers.RotatingFileHandler(
        config.SECURITY_LOG_FILE,
        maxBytes=config.LOG_MAX_SIZE_MB * 1024 * 1024,
        backupCount=config.LOG_BACKUP_COUNT
    )
    security_handler.setFormatter(formatter)
    security_logger.addHandler(security_handler)
    
    # Audit logger
    audit_logger = logging.getLogger('audit')
    audit_logger.setLevel(logging.INFO)
    
    audit_handler = logging.handlers.RotatingFileHandler(
        config.AUDIT_LOG_FILE,
        maxBytes=config.LOG_MAX_SIZE_MB * 1024 * 1024,
        backupCount=config.LOG_BACKUP_COUNT
    )
    audit_handler.setFormatter(formatter)
    audit_logger.addHandler(audit_handler)
    
    return app_logger, security_logger, audit_logger

# Initialize loggers
app_logger, security_logger, audit_logger = setup_logging()

# Helper functions
def log_security_event(event_type: str, ip: str, details: str):
    """Log security event"""
    security_logger.warning(f"[{event_type}] IP: {ip} | {details}")

def log_audit_event(action: str, user: str, resource: str, result: str):
    """Log audit event"""
    audit_logger.info(f"Action: {action} | User: {user} | Resource: {resource} | Result: {result}")

def log_threat_detection(threat_type: str, ip: str, query: str, action: str):
    """Log threat detection"""
    audit_logger.warning(f"Threat: {threat_type} | IP: {ip} | Query: {query[:100]} | Action: {action}")
