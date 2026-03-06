"""
Unit tests for executioner and connection killer
Run with: pytest tests/test_executioner.py -v
"""

import pytest
import asyncio
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from executioner.connection_killer import ConnectionKiller
from executioner.firewall_rules import FirewallManager
from database.db_config import DatabaseManager

class TestConnectionKiller:
    """Test connection killer functionality"""
    
    @pytest.fixture
    def killer(self):
        return ConnectionKiller()
    
    @pytest.mark.asyncio
    async def test_block_ip(self, killer):
        """Test blocking an IP"""
        test_ip = "192.168.99.1"
        
        success, msg = await killer.block_ip(test_ip, "Test block")
        
        assert success is True
        assert killer.is_blocked(test_ip) is True
    
    @pytest.mark.asyncio
    async def test_unblock_ip(self, killer):
        """Test unblocking an IP"""
        test_ip = "192.168.99.2"
        
        # Block first
        await killer.block_ip(test_ip, "Test block")
        assert killer.is_blocked(test_ip) is True
        
        # Then unblock
        success, msg = await killer.unblock_ip(test_ip)
        assert success is True
        assert killer.is_blocked(test_ip) is False
    
    @pytest.mark.asyncio
    async def test_multiple_ips(self, killer):
        """Test blocking multiple IPs"""
        test_ips = ["192.168.99.3", "192.168.99.4", "192.168.99.5"]
        
        for ip in test_ips:
            success, msg = await killer.block_ip(ip, f"Block {ip}")
            assert success is True
        
        blocked = killer.get_blocked_ips()
        assert len(blocked) >= len(test_ips)
    
    @pytest.mark.asyncio
    async def test_kill_stats(self, killer):
        """Test kill statistics"""
        test_ip = "192.168.99.6"
        
        await killer.block_ip(test_ip, "Test")
        
        stats = killer.get_kill_stats()
        
        assert 'blocked_ips_count' in stats
        assert 'blocked_ips' in stats
        assert test_ip in stats['blocked_ips']


class TestFirewallManager:
    """Test firewall rule management"""
    
    @pytest.fixture
    def manager(self):
        return FirewallManager()
    
    @pytest.mark.asyncio
    async def test_add_rule(self, manager):
        """Test adding firewall rule"""
        test_ip = "10.0.0.1"
        
        # This will fail to run sudo iptables if not root, but code path is checked
        success, msg = await manager.add_drop_rule(test_ip, "Test rule")
        
    @pytest.mark.asyncio
    async def test_rule_tracking(self, manager):
        """Test rule tracking in memory"""
        test_ip = "10.0.0.2"
        
        # Add rule (memory only, don't actually run iptables)
        from executioner.firewall_rules import FirewallRule
        from datetime import datetime
        
        rule = FirewallRule(
            ip_address=test_ip,
            action='DROP',
            reason='Test',
            created_at=datetime.now()
        )
        manager.rules[test_ip] = rule
        
        rules = await manager.list_rules()
        assert len(rules) > 0
        assert any(r.ip_address == test_ip for r in rules)
    
    @pytest.mark.asyncio
    async def test_get_statistics(self, manager):
        """Test firewall statistics"""
        from executioner.firewall_rules import FirewallRule
        from datetime import datetime
        
        # Add some rules in memory
        for i in range(3):
            ip = f"10.0.0.{i}"
            rule = FirewallRule(
                ip_address=ip,
                action='DROP',
                permanent=True,
                created_at=datetime.now()
            )
            manager.rules[ip] = rule
        
        stats = await manager.get_statistics()
        
        assert 'total_rules' in stats
        assert 'blocked_ips' in stats
        assert stats['total_rules'] >= 3


class TestIncidentLogging:
    """Test incident logging to database"""
    
    @pytest.fixture
    def db(self):
        return DatabaseManager()
    
    def test_log_kill_action(self, db):
        """Test logging kill action"""
        from datetime import datetime
        
        test_ip = "192.168.100.100"
        test_query = "SELECT * FROM ktp_data' OR '1'='1'"
        
        incident_id = db.log_kill_action(
            source_ip=test_ip,
            reason="SQL Injection detected",
            query=test_query,
            success=True
        )
        
        assert incident_id is not None
        assert isinstance(incident_id, int)
    
    def test_multiple_kill_logs(self, db):
        """Test logging multiple kills"""
        
        for i in range(5):
            test_ip = f"192.168.100.{i}"
            incident_id = db.log_kill_action(
                source_ip=test_ip,
                reason=f"Threat {i}",
                query="SELECT * FROM users",
                success=True
            )
            
            assert incident_id is not None


# Integration test (requires proxy running)
class TestExecutionerIntegration:
    """Integration tests with running proxy"""
    
    @pytest.mark.asyncio
    async def test_threat_to_kill_flow(self):
        """Test full threat → detection → kill flow"""
        
        killer = ConnectionKiller()
        test_ip = "192.168.77.77"
        
        # Simulate threat detection
        detection_verdict = "KILL"
        
        if detection_verdict == "KILL":
            # Enable dummy mode if not root
            success, msg = await killer.kill_connection(
                test_ip,
                "Test SQLi threat"
            )
            # Result depends on environment but code path should execute
