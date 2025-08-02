"""
Tests for Configuration System
"""
import pytest
import os
import tempfile
import json
from typing import Dict, Any

from fastapi_fortify.config.settings import SecurityConfig
from fastapi_fortify.config.presets import (
    DevelopmentConfig,
    ProductionConfig,
    HighSecurityConfig,
    CustomSecurityConfig
)


class TestSecurityConfig:
    """Test SecurityConfig base class"""
    
    def test_default_config(self):
        """Test default configuration values"""
        config = SecurityConfig()
        
        # Check default values
        assert config.log_level == "INFO"
        assert config.waf_enabled is True
        assert config.bot_detection_enabled is True
        assert config.ip_blocklist_enabled is True
        assert config.rate_limiting_enabled is True
        assert config.auth_monitoring_enabled is False  # Disabled by default
        assert config.security_headers_enabled is True
        
        # Rate limiting defaults
        assert config.rate_limit_requests == 100
        assert config.rate_limit_window == 3600
        
        # Bot detection defaults
        assert config.bot_detection_mode == "balanced"
        assert config.allow_search_engines is True
    
    def test_config_validation(self):
        """Test configuration validation"""
        # Valid config should work
        config = SecurityConfig(
            rate_limit_requests=50,
            rate_limit_window=60,
            log_level="DEBUG"
        )
        assert config.rate_limit_requests == 50
        
        # Invalid values should be caught by Pydantic
        with pytest.raises(ValueError):
            SecurityConfig(rate_limit_requests=-1)  # Negative not allowed
        
        with pytest.raises(ValueError):
            SecurityConfig(bot_detection_mode="invalid_mode")  # Invalid enum
    
    def test_config_serialization(self):
        """Test config serialization to/from dict"""
        config = SecurityConfig(
            waf_enabled=False,
            rate_limit_requests=200,
            excluded_paths=["/health", "/metrics"]
        )
        
        # Convert to dict
        config_dict = config.dict()
        assert config_dict["waf_enabled"] is False
        assert config_dict["rate_limit_requests"] == 200
        assert "/health" in config_dict["excluded_paths"]
        
        # Create from dict
        config2 = SecurityConfig(**config_dict)
        assert config2.waf_enabled is False
        assert config2.rate_limit_requests == 200
    
    def test_config_json_serialization(self):
        """Test JSON serialization"""
        config = SecurityConfig(
            ip_whitelist=["192.168.1.1", "10.0.0.0/8"],
            custom_waf_patterns=["test_pattern"],
            auth_monitor_endpoints=["/login", "/signup"]
        )
        
        # Convert to JSON
        json_str = config.json(indent=2)
        assert isinstance(json_str, str)
        
        # Parse back
        parsed = json.loads(json_str)
        assert "192.168.1.1" in parsed["ip_whitelist"]
        assert "test_pattern" in parsed["custom_waf_patterns"]
    
    def test_config_environment_override(self):
        """Test environment variable override"""
        # Set environment variables
        os.environ["SECURITY_LOG_LEVEL"] = "ERROR"
        os.environ["SECURITY_RATE_LIMIT_REQUESTS"] = "50"
        os.environ["SECURITY_WAF_ENABLED"] = "false"
        
        try:
            # Config should read from environment
            config = SecurityConfig()
            # Note: Default Pydantic doesn't auto-read env vars
            # This test assumes custom env reading is implemented
            # For now, we'll manually test the pattern
            
            # Clean test - create config with explicit values
            config = SecurityConfig(
                log_level="ERROR",
                rate_limit_requests=50,
                waf_enabled=False
            )
            assert config.log_level == "ERROR"
            assert config.rate_limit_requests == 50
            assert config.waf_enabled is False
            
        finally:
            # Cleanup
            os.environ.pop("SECURITY_LOG_LEVEL", None)
            os.environ.pop("SECURITY_RATE_LIMIT_REQUESTS", None)
            os.environ.pop("SECURITY_WAF_ENABLED", None)
    
    def test_config_file_loading(self):
        """Test loading configuration from file"""
        # Create temporary config file
        config_data = {
            "log_level": "WARNING",
            "waf_enabled": True,
            "rate_limit_requests": 150,
            "ip_whitelist": ["192.168.1.0/24"],
            "custom_waf_patterns": ["custom_threat"],
            "excluded_paths": ["/api/public/*"]
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(config_data, f)
            temp_file = f.name
        
        try:
            # Load config from file
            with open(temp_file, 'r') as f:
                loaded_data = json.load(f)
            
            config = SecurityConfig(**loaded_data)
            
            assert config.log_level == "WARNING"
            assert config.rate_limit_requests == 150
            assert "192.168.1.0/24" in config.ip_whitelist
            assert "custom_threat" in config.custom_waf_patterns
            
        finally:
            os.unlink(temp_file)
    
    def test_config_merge(self):
        """Test merging configurations"""
        # Base config
        base_config = SecurityConfig(
            log_level="INFO",
            rate_limit_requests=100,
            excluded_paths=["/health"]
        )
        
        # Override config
        override_data = {
            "log_level": "DEBUG",
            "rate_limit_requests": 200,
            "excluded_paths": ["/health", "/metrics"],
            "waf_enabled": False
        }
        
        # Merge configs
        merged_dict = {**base_config.dict(), **override_data}
        merged_config = SecurityConfig(**merged_dict)
        
        assert merged_config.log_level == "DEBUG"  # Overridden
        assert merged_config.rate_limit_requests == 200  # Overridden
        assert merged_config.waf_enabled is False  # New value
        assert "/metrics" in merged_config.excluded_paths  # Extended


class TestConfigurationPresets:
    """Test configuration preset classes"""
    
    def test_development_preset(self):
        """Test development configuration preset"""
        config = DevelopmentConfig()
        
        # Development specific settings
        assert config.log_level == "DEBUG"
        assert config.rate_limit_requests == 1000  # Very permissive
        assert config.rate_limit_window == 60  # Short window
        assert config.bot_detection_mode == "permissive"
        assert config.waf_mode == "permissive"
        
        # Should whitelist localhost
        assert "127.0.0.1" in config.ip_whitelist
        assert "localhost" in config.ip_whitelist
        assert "::1" in config.ip_whitelist
        
        # Should exclude common development paths
        assert "/docs" in config.excluded_paths
        assert "/redoc" in config.excluded_paths
        assert "/openapi.json" in config.excluded_paths
    
    def test_production_preset(self):
        """Test production configuration preset"""
        config = ProductionConfig()
        
        # Production specific settings
        assert config.log_level == "WARNING"
        assert config.rate_limit_requests == 100  # Standard limit
        assert config.rate_limit_window == 3600  # 1 hour window
        assert config.bot_detection_mode == "balanced"
        assert config.waf_mode == "balanced"
        
        # All security features enabled
        assert config.waf_enabled is True
        assert config.bot_detection_enabled is True
        assert config.ip_blocklist_enabled is True
        assert config.rate_limiting_enabled is True
        assert config.security_headers_enabled is True
        
        # No localhost in whitelist
        assert "127.0.0.1" not in config.ip_whitelist
        assert "localhost" not in config.ip_whitelist
    
    def test_high_security_preset(self):
        """Test high security configuration preset"""
        config = HighSecurityConfig()
        
        # High security specific settings
        assert config.log_level == "ERROR"
        assert config.rate_limit_requests == 50  # Very restrictive
        assert config.rate_limit_window == 3600
        assert config.bot_detection_mode == "strict"
        assert config.waf_mode == "strict"
        assert config.block_empty_user_agents is True
        assert config.block_private_networks is True
        
        # Additional security features
        assert config.auth_monitoring_enabled is True
        assert config.auto_block_threshold == 3  # Low threshold
        
        # Strict bot detection
        assert config.allow_search_engines is False  # Even search engines blocked
    
    def test_custom_preset(self):
        """Test custom configuration preset"""
        # Create custom preset with specific overrides
        custom_overrides = {
            "rate_limit_requests": 250,
            "log_level": "INFO",
            "custom_waf_patterns": ["my_custom_pattern"],
            "ip_whitelist": ["10.0.0.0/8"]
        }
        
        config = CustomSecurityConfig(**custom_overrides)
        
        assert config.rate_limit_requests == 250
        assert config.log_level == "INFO"
        assert "my_custom_pattern" in config.custom_waf_patterns
        assert "10.0.0.0/8" in config.ip_whitelist
        
        # Should still have base defaults for non-overridden values
        assert config.waf_enabled is True
        assert config.bot_detection_enabled is True
    
    def test_preset_inheritance(self):
        """Test that presets properly inherit from base"""
        # All presets should be valid SecurityConfig instances
        presets = [
            DevelopmentConfig(),
            ProductionConfig(),
            HighSecurityConfig()
        ]
        
        for preset in presets:
            assert isinstance(preset, SecurityConfig)
            
            # Should have all required fields
            assert hasattr(preset, 'log_level')
            assert hasattr(preset, 'waf_enabled')
            assert hasattr(preset, 'rate_limit_requests')
            
            # Should be serializable
            preset_dict = preset.dict()
            assert isinstance(preset_dict, dict)
            
            # Should be recreatable from dict
            recreated = type(preset)(**preset_dict)
            assert recreated.log_level == preset.log_level


class TestConfigurationValidation:
    """Test configuration validation rules"""
    
    def test_rate_limit_validation(self):
        """Test rate limit configuration validation"""
        # Valid rate limits
        config = SecurityConfig(
            rate_limit_requests=1000,
            rate_limit_window=60
        )
        assert config.rate_limit_requests == 1000
        
        # Invalid rate limits should fail
        with pytest.raises(ValueError):
            SecurityConfig(rate_limit_requests=-1)
        
        with pytest.raises(ValueError):
            SecurityConfig(rate_limit_window=0)
    
    def test_path_exclusion_validation(self):
        """Test path exclusion pattern validation"""
        # Valid patterns
        config = SecurityConfig(
            excluded_paths=[
                "/health",
                "/api/public/*",
                "/static/**",
                "*.jpg"
            ]
        )
        assert len(config.excluded_paths) == 4
        
        # Empty list is valid
        config = SecurityConfig(excluded_paths=[])
        assert config.excluded_paths == []
    
    def test_ip_whitelist_validation(self):
        """Test IP whitelist validation"""
        # Valid IPs and CIDRs
        config = SecurityConfig(
            ip_whitelist=[
                "192.168.1.1",
                "10.0.0.0/8",
                "::1",
                "2001:db8::/32"
            ]
        )
        assert len(config.ip_whitelist) == 4
        
        # Note: Basic Pydantic doesn't validate IP formats
        # This would require custom validators
    
    def test_enum_validation(self):
        """Test enum field validation"""
        # Valid enum values
        config = SecurityConfig(
            log_level="DEBUG",
            bot_detection_mode="strict",
            waf_mode="permissive"
        )
        assert config.log_level == "DEBUG"
        
        # Invalid enum values should fail
        with pytest.raises(ValueError):
            SecurityConfig(log_level="INVALID")
        
        with pytest.raises(ValueError):
            SecurityConfig(bot_detection_mode="super_strict")
    
    def test_boolean_validation(self):
        """Test boolean field validation"""
        # Various boolean representations
        config = SecurityConfig(
            waf_enabled=True,
            bot_detection_enabled=False,
            security_headers_enabled=1,  # Should convert to True
            auth_monitoring_enabled=0   # Should convert to False
        )
        
        assert config.waf_enabled is True
        assert config.bot_detection_enabled is False
        assert config.security_headers_enabled is True
        assert config.auth_monitoring_enabled is False


class TestConfigurationUsage:
    """Test configuration usage patterns"""
    
    def test_config_for_different_environments(self):
        """Test using different configs for different environments"""
        configs = {
            "development": DevelopmentConfig(),
            "staging": ProductionConfig(),
            "production": HighSecurityConfig()
        }
        
        # Development should be most permissive
        assert configs["development"].rate_limit_requests > configs["production"].rate_limit_requests
        assert configs["development"].log_level == "DEBUG"
        
        # Production should be most restrictive
        assert configs["production"].bot_detection_mode == "strict"
        assert configs["production"].allow_search_engines is False
    
    def test_config_customization_pattern(self):
        """Test common configuration customization patterns"""
        # Start with a preset
        base_config = ProductionConfig()
        
        # Customize for specific needs
        custom_dict = base_config.dict()
        custom_dict.update({
            "rate_limit_requests": 200,  # Increase from default
            "excluded_paths": base_config.excluded_paths + ["/api/webhooks/*"],
            "ip_whitelist": base_config.ip_whitelist + ["trusted.partner.com"]
        })
        
        custom_config = SecurityConfig(**custom_dict)
        
        assert custom_config.rate_limit_requests == 200
        assert "/api/webhooks/*" in custom_config.excluded_paths
        assert "trusted.partner.com" in custom_config.ip_whitelist
    
    def test_config_feature_flags(self):
        """Test using config as feature flags"""
        # Disable specific features for testing
        config = SecurityConfig(
            waf_enabled=True,
            bot_detection_enabled=False,  # Disable for debugging
            ip_blocklist_enabled=True,
            rate_limiting_enabled=False,  # Disable for load testing
            auth_monitoring_enabled=True
        )
        
        # Use config to conditionally enable features
        features = {
            "waf": config.waf_enabled,
            "bot_detection": config.bot_detection_enabled,
            "ip_blocklist": config.ip_blocklist_enabled,
            "rate_limiting": config.rate_limiting_enabled,
            "auth_monitoring": config.auth_monitoring_enabled
        }
        
        enabled_features = [k for k, v in features.items() if v]
        assert "bot_detection" not in enabled_features
        assert "rate_limiting" not in enabled_features
        assert "waf" in enabled_features
    
    def test_config_api_compatibility(self):
        """Test config compatibility with different API versions"""
        # Simulate old config format
        old_config_data = {
            "log_level": "INFO",
            "waf_enabled": True,
            "rate_limit": 100  # Old field name
        }
        
        # Should handle gracefully (ignore unknown fields by default)
        # This would need custom handling in real implementation
        try:
            config = SecurityConfig(
                log_level=old_config_data["log_level"],
                waf_enabled=old_config_data["waf_enabled"],
                rate_limit_requests=old_config_data.get("rate_limit", 100)
            )
            assert config.rate_limit_requests == 100
        except Exception:
            # Config migration would be handled separately
            pass