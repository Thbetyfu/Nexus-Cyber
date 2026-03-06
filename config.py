"""
Configuration management
Loads from environment variables with sensible defaults
"""

import os
from dotenv import load_dotenv
from typing import Dict, Any

# Load .env file
load_dotenv()

class Config:
    """Base configuration"""
    
    # Flask
    SECRET_KEY = os.getenv('FLASK_SECRET_KEY', 'dev-only-change-in-production')
    FLASK_ENV = os.getenv('FLASK_ENV', 'development')
    FLASK_DEBUG = os.getenv('FLASK_DEBUG', 'false').lower() == 'true'
    
    # Database
    DB_HOST = os.getenv('DB_HOST', 'localhost')
    DB_PORT = int(os.getenv('DB_PORT', 3307))
    DB_USER = os.getenv('DB_USER', 'ktp_user')
    DB_PASSWORD = os.getenv('DB_PASSWORD', 'default-password')
    DB_NAME = os.getenv('DB_NAME', 'ktp_database')
    DB_POOL_SIZE = int(os.getenv('DB_POOL_SIZE', 10))
    
    # Proxy
    PROXY_LISTEN_HOST = os.getenv('PROXY_LISTEN_HOST', '0.0.0.0')
    PROXY_LISTEN_PORT = int(os.getenv('PROXY_LISTEN_PORT', 3306))
    PROXY_BACKEND_HOST = os.getenv('PROXY_BACKEND_HOST', 'localhost')
    PROXY_BACKEND_PORT = int(os.getenv('PROXY_BACKEND_PORT', 3307))
    
    # Authentication
    ADMIN_USERNAME = os.getenv('ADMIN_USERNAME', 'admin')
    ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', 'default-password')
    ADMIN_IP_WHITELIST = os.getenv('ADMIN_IP_WHITELIST', '127.0.0.1').split(',')
    
    # Session
    SESSION_TIMEOUT_MINUTES = int(os.getenv('SESSION_TIMEOUT_MINUTES', 480))
    SESSION_SECURE_COOKIE = os.getenv('SESSION_SECURE_COOKIE', 'true').lower() == 'true'
    SESSION_HTTPONLY = os.getenv('SESSION_HTTPONLY', 'true').lower() == 'true'
    SESSION_SAMESITE = os.getenv('SESSION_SAMESITE', 'Strict')
    
    # Ollama/AI
    OLLAMA_HOST = os.getenv('OLLAMA_HOST', 'http://localhost:11434')
    OLLAMA_TIMEOUT = int(os.getenv('OLLAMA_TIMEOUT', 60))
    QWEN_MODEL = os.getenv('QWEN_MODEL', 'qwen2.5-coder')
    LLAMA_MODEL = os.getenv('LLAMA_MODEL', 'llama3')
    
    # Telegram
    TELEGRAM_ENABLED = os.getenv('TELEGRAM_ENABLED', 'true').lower() == 'true'
    TELEGRAM_TOKEN = os.getenv('TELEGRAM_TOKEN')
    TELEGRAM_CHAT_ID = os.getenv('TELEGRAM_CHAT_ID')
    
    # Logging
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    LOG_FORMAT = os.getenv('LOG_FORMAT', 'json')
    LOG_FILE = os.getenv('LOG_FILE', 'logs/app.log')
    LOG_MAX_SIZE_MB = int(os.getenv('LOG_MAX_SIZE_MB', 100))
    LOG_BACKUP_COUNT = int(os.getenv('LOG_BACKUP_COUNT', 10))
    SECURITY_LOG_FILE = os.getenv('SECURITY_LOG_FILE', 'logs/security.log')
    AUDIT_LOG_FILE = os.getenv('AUDIT_LOG_FILE', 'logs/audit.log')
    
    # Rate limiting
    RATE_LIMIT_ENABLED = os.getenv('RATE_LIMIT_ENABLED', 'true').lower() == 'true'
    RATE_LIMIT_QUERIES_PER_MINUTE = int(os.getenv('RATE_LIMIT_QUERIES_PER_MINUTE', 100))
    
    # Security
    ENABLE_IPTABLES = os.getenv('ENABLE_IPTABLES', 'true').lower() == 'true'
    BAN_DURATION_HOURS = int(os.getenv('BAN_DURATION_HOURS', 24))
    
    @classmethod
    def validate(cls) -> Dict[str, Any]:
        """Validate critical configuration"""
        
        errors = []
        warnings = []
        
        # Critical checks
        if cls.FLASK_ENV == 'production':
            if cls.SECRET_KEY == 'dev-only-change-in-production':
                errors.append("FLASK_SECRET_KEY not set for production!")
            
            if cls.DB_PASSWORD == 'default-password':
                errors.append("DB_PASSWORD not set for production!")
            
            if cls.ADMIN_PASSWORD == 'default-password':
                errors.append("ADMIN_PASSWORD not set for production!")
            
            if cls.FLASK_DEBUG:
                warnings.append("FLASK_DEBUG is True in production!")
        
        # Warnings
        if not cls.TELEGRAM_TOKEN and cls.TELEGRAM_ENABLED:
            warnings.append("TELEGRAM_ENABLED but TELEGRAM_TOKEN not set")
        
        return {
            'valid': len(errors) == 0,
            'errors': errors,
            'warnings': warnings
        }
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert config to dictionary (exclude secrets)"""
        
        return {
            'FLASK_ENV': self.FLASK_ENV,
            'DB_HOST': self.DB_HOST,
            'DB_PORT': self.DB_PORT,
            'PROXY_LISTEN_PORT': self.PROXY_LISTEN_PORT,
            'PROXY_BACKEND_PORT': self.PROXY_BACKEND_PORT,
            'LOG_LEVEL': self.LOG_LEVEL,
            'RATE_LIMIT_ENABLED': self.RATE_LIMIT_ENABLED,
            'ENABLE_IPTABLES': self.ENABLE_IPTABLES,
        }


class DevelopmentConfig(Config):
    """Development configuration"""
    FLASK_DEBUG = True
    FLASK_ENV = 'development'


class ProductionConfig(Config):
    """Production configuration"""
    FLASK_DEBUG = False
    FLASK_ENV = 'production'
    SESSION_SECURE_COOKIE = True


# Configuration factory
def get_config() -> Config:
    """Get configuration based on environment"""
    
    env = os.getenv('FLASK_ENV', 'development')
    
    if env == 'production':
        return ProductionConfig()
    else:
        return DevelopmentConfig()


# Validate on import
if __name__ == '__main__':
    config = get_config()
    validation = config.validate()
    
    print("Configuration Validation Results:")
    print(f"Valid: {validation['valid']}")
    
    if validation['errors']:
        print("\n❌ Errors:")
        for error in validation['errors']:
            print(f"  - {error}")
    
    if validation['warnings']:
        print("\n⚠️  Warnings:")
        for warning in validation['warnings']:
            print(f"  - {warning}")
    
    print("\nConfiguration (public only):")
    for key, value in config.to_dict().items():
        print(f"  {key}: {value}")
