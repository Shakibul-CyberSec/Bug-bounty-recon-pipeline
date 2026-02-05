#!/usr/bin/env python3
"""
JSScan Pro - Advanced JavaScript Secret Scanner for Bug Bounty Hunters
Author: Bug Bounty Tools
Version: 2.1 Pro - Enhanced Patterns Edition
"""

import os
import re
import sys
import json
import base64
import hashlib
import time
from typing import List, Tuple, Dict, Set, Optional
from dataclasses import dataclass
from urllib.parse import urlparse, parse_qs


@dataclass
class SecretFinding:
    """Data class for secret findings"""
    secret_type: str
    value: str
    context: str
    line_num: int
    confidence: str  # high, medium, low
    file_path: str
    is_minified: bool = False


class JSScanPro:
    def __init__(self, aggressive_mode: bool = False):
        """
        Initialize the scanner
        
        Args:
            aggressive_mode: If True, use more patterns (may have more false positives)
        """
        self.aggressive_mode = aggressive_mode
        
        # ===== HIGH CONFIDENCE PATTERNS (Very specific, low false positives) =====
        self.high_confidence_patterns = {
            # Google API Keys (very specific format) - UPDATED: More flexible length
            "Google API Key": r'\bAIza[0-9A-Za-z\-_]{35,40}\b',
            
            # AWS Keys (specific formats) - UPDATED: Allow 16-20 chars for AWS Access Key
            "AWS Access Key ID": r'\bAKIA[0-9A-Z]{16,20}\b',
            # AWS Secret Key (40 chars base64) - NEW: Standalone pattern
            "AWS Secret Key": r'\b[A-Za-z0-9+/]{40}\b',
            # AWS Secret with context - UPDATED: More flexible
            "AWS Secret Key (context)": r'(?i)(?:aws[_-]?)?secret[_-]?(?:access[_-]?)?key\s*[=:]\s*["\']([A-Za-z0-9+/]{40})["\']',
            
            # Stripe Keys - UPDATED: Allow longer keys
            "Stripe Secret Key": r'\bsk_(?:test|live)_[a-zA-Z0-9]{24,}\b',
            "Stripe Publishable Key": r'\bpk_(?:test|live)_[a-zA-Z0-9]{24,}\b',
            
            # GitHub Tokens - UPDATED: Allow 36+ chars
            "GitHub Token": r'\bgh[pousr]_[A-Za-z0-9_]{36,}\b',
            
            # Slack Tokens - UPDATED: Better pattern
            "Slack Token": r'\bxox[baprs]-[0-9a-zA-Z-]{10,}\b',
            
            # Heroku API Key (UUID format)
            "Heroku API Key": r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b',
            
            # Firebase - NEW: Specific API key pattern
            "Firebase API Key": r'\bAIza[0-9A-Za-z\-_]{35,}\b.*firebase',
            
            # Twilio
            "Twilio Account SID": r'\bAC[a-fA-F0-9]{32}\b',
            "Twilio Auth Token": r'\b[a-fA-F0-9]{32}\b',
            "Twilio API Key": r'\bSK[a-fA-F0-9]{32}\b',
            
            # Mailgun
            "Mailgun API Key": r'\bkey-[0-9a-fA-F]{32}\b',
            
            # SendGrid - NEW
            "SendGrid API Key": r'\bSG\.[a-zA-Z0-9-_]{22}\.[a-zA-Z0-9-_]{43}\b',
            
            # JWT Token - NEW: More accurate pattern
            "JWT Token": r'\beyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*\b',
            
            # Database URLs - NEW: More specific patterns
            "MongoDB URL": r'mongodb(?:\+srv)?://[a-zA-Z0-9_]+:[^@\s]+@[^\s"\']+',
            "PostgreSQL URL": r'postgres(?:ql)?://[a-zA-Z0-9_]+:[^@\s]+@[^\s"\']+',
            "MySQL URL": r'mysql://[a-zA-Z0-9_]+:[^@\s]+@[^\s"\']+',
            
            # Generic 40-char base64 (likely AWS or similar) - NEW
            "40-char Base64 Secret": r'\b[A-Za-z0-9+/]{40}\b',
            
            # Generic 32-char hex (likely API key) - NEW
            "32-char Hex Secret": r'\b[a-fA-F0-9]{32}\b',
            
            # Slack webhook URL - NEW
            "Slack Webhook URL": r'https://hooks\.slack\.com/services/T[A-Z0-9]{8}/B[A-Z0-9]{8}/[A-Za-z0-9]+',
        }
        
        # ===== MEDIUM CONFIDENCE PATTERNS (Require context validation) =====
        self.medium_confidence_patterns = {
            # JWTs with validation - KEEP: for validation
            "JWT Token (medium)": r'\beyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\b',
            
            # API Keys in assignments (must have keyword) - UPDATED: Better capture
            "API Key Assignment": r'(?i)(?:api[_-]?key|access[_-]?key)\s*[=:]\s*["\']([a-zA-Z0-9_\-=+/]{20,100})["\']',
            
            # Secrets in assignments - UPDATED: Better capture
            "Secret Assignment": r'(?i)(?:secret|client[_-]?secret|api[_-]?secret|private[_-]?key)\s*[=:]\s*["\']([a-zA-Z0-9_\-=+/]{20,100})["\']',
            
            # Tokens in assignments - UPDATED: Better capture
            "Token Assignment": r'(?i)(?:token|access[_-]?token|bearer[_-]?token|refresh[_-]?token|id[_-]?token)\s*[=:]\s*["\']([a-zA-Z0-9_\-=+/]{20,100})["\']',
            
            # Passwords in assignments - UPDATED: Better capture
            "Password Assignment": r'(?i)(?:password|passwd|pwd|pass)\s*[=:]\s*["\']([^\s"\']{8,128})["\']',
            
            # Database URLs with credentials - UPDATED: More inclusive
            "Database URL with Auth": r'(?i)(?:mysql|postgres|mongodb|redis)://[a-zA-Z0-9_]+:[^@\s]+@[^\s"\']+',
            
            # URLs with tokens in query params - UPDATED
            "URL with Auth Param": r'https?://[^\s"\']*[?&](?:token|key|secret|auth|apikey|access[_-]?token)=([a-zA-Z0-9_\-=+/]{20,128})',
            
            # Config objects with secrets - NEW
            "Config Object Secret": r'(?i)(?:apiKey|secret|token|password|accessKey)\s*:\s*["\']([a-zA-Z0-9_\-=+/]{20,100})["\']',
            
            # Environment variable style - NEW
            "Env Variable Secret": r'(?i)(?:[A-Z_]+[A-Z0-9_]*)\s*=\s*["\']([a-zA-Z0-9_\-=+/@#$%^&*!]{8,128})["\']',
            
            # Export statements with secrets - NEW
            "Export with Secret": r'(?i)export\s+(?:const|let|var|default).*?=\s*["\']([a-zA-Z0-9_\-=+/]{20,100})["\']',
        }
        
        # ===== AGGRESSIVE MODE PATTERNS (More patterns, more false positives) =====
        self.aggressive_patterns = {
            "Base64 String (long)": r'\b(?:[A-Za-z0-9+/]{40,}={0,2}|[A-Za-z0-9+/]{60,}={0,2})\b',
            "Hex String (long)": r'\b(?:0x)?[a-fA-F0-9]{40,}\b',
            "Generic Credential": r'(?i)(?:user(?:name)?|login|email)\s*[=:]\s*["\'][^"\']+["\']\s*[,\n].*?(?:pass(?:word|wd)?)\s*[=:]\s*["\'][^"\']+["\']',
            "Potential Secret String": r'["\'][A-Za-z0-9_\-=+/@#$%^&*!]{20,100}["\']',
            "URL with Credentials": r'://[^:]+:[^@]+@',
            "UUID String": r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b',
        }
        
        # ===== COMPILE PATTERNS =====
        self.all_patterns = {}
        self.all_patterns.update(self.high_confidence_patterns)
        self.all_patterns.update(self.medium_confidence_patterns)
        
        if self.aggressive_mode:
            self.all_patterns.update(self.aggressive_patterns)
        
        self.compiled_patterns = {
            name: re.compile(pattern, re.IGNORECASE) 
            for name, pattern in self.all_patterns.items()
        }
        
        # ===== FALSE POSITIVE DATABASE =====
        # Common words, paths, and known false positives
        self.false_positives = {
            # Common words
            'null', 'undefined', 'true', 'false', 'example', 'test', 'demo', 
            'dummy', 'placeholder', 'changeme', 'password123', 'test123',
            'admin', 'root', 'user', 'guest', 'default', 'example_token_123',
            'test_api_key_1234567890', 'YOUR_API_KEY_HERE',
            
            # WordPress/Drupal specific
            'dashicons-visibility', 'dashicons-hidden', 'wp-content',
            'wp-admin', 'wp-includes', 'admin-ajax.php',
            
            # Common JavaScript methods/properties
            'getelementbyid', 'queryselector', 'addeventlistener',
            'innerhtml', 'textcontent', 'createelement',
            
            # Common API endpoints (not secrets)
            'api/v1', 'api/v2', 'graphql', 'rest', 'oauth',
            
            # Archive.org specific (from your output)
            'org/services/img/metropolitanmuseumofart',
            'machine/fpnmgdkabkmnadcjpehmlllkndpkmiak',
            'machine/kjmickeoogghaimmomagaghnogelpcpn',
            
            # Test patterns from our test file
            'd41d8cd98f00b204e9800998ecf8427e',  # MD5 of empty string
            'ff5733',  # Part of hex color
            
            # Common false positives
            'github.com', 'gitlab.com', 'bitbucket.org', 'localhost',
            '127.0.0.1', '0.0.0.0', 'example.com', 'test.com',
        }
        
        # False positive patterns (regex)
        self.false_positive_patterns = [
            # URLs and paths - MORE SPECIFIC
            r'https?://(?:www\.)?[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s"\']*)?',  # URLs
            r'/[a-zA-Z0-9_\-/.]+\.(?:js|css|html|png|jpg|jpeg|gif|svg|ico)',  # File paths with extensions
            r'www\.[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',  # Websites
            r'\.[a-z]{2,6}(?::\d+)?(?:/[\w\-./]*)?',  # Domain-like patterns
            
            # JavaScript code patterns
            r'function\s+\w+\s*\(',  # Function definitions
            r'class\s+\w+',  # Class definitions
            r'\.prototype\.',  # Prototype methods
            r'\.(?:exports|module)\s*=',  # Module exports
            r'^\s*(?:var|let|const|export|import|function|class)',  # Declarations
            
            # HTML/CSS patterns
            r'<[a-zA-Z][^>]*>',  # HTML tags
            r'\.(?:css|js|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot)\b',  # File extensions
            r'#[a-fA-F0-9]{3,6}',  # Hex colors
            r'url\([^)]+\)',  # CSS URLs
            r'data:image/[^;]+;base64,[a-zA-Z0-9+/=]+',  # Base64 images
            
            # Common libraries/frameworks
            r'(?:jquery|react|vue|angular|axios|lodash|moment|underscore)\.',  # Library calls
            r'\.min\.(?:js|css)',  # Minified files marker
            
            # Comments
            r'//.*example.*|/\*.*example.*\*/',  # Example in comments
            r'//.*test.*|/\*.*test.*\*/',  # Test in comments
            
            # Common patterns that look like secrets but aren't
            r'[0-9a-fA-F]{8}-0000-0000-0000-[0-9a-fA-F]{12}',  # Generic UUID
            r'[0-9]{4}-[0-9]{2}-[0-9]{2}',  # Date pattern
            r'[0-9]+\.[0-9]+\.[0-9]+',  # Version numbers
        ]
        
        self.compiled_fp_patterns = [re.compile(p, re.IGNORECASE) for p in self.false_positive_patterns]
        
        # File extensions to scan
        self.scannable_extensions = {'.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.json'}
        
        # Statistics
        self.stats = {
            'files_scanned': 0,
            'minified_files': 0,
            'findings_high': 0,
            'findings_medium': 0,
            'findings_low': 0,
            'false_positives_filtered': 0,
        }

    def is_minified_file(self, content: str, file_path: str) -> bool:
        """Advanced minification detection"""
        if not content or len(content) < 100:
            return False
        
        filename = os.path.basename(file_path).lower()
        
        # Check filename for minified indicators
        if '.min.js' in filename or '.min.css' in filename:
            return True
        
        # Calculate metrics
        lines = content.split('\n')
        line_count = len(lines)
        
        if line_count == 0:
            return False
        
        avg_line_length = len(content) / line_count
        
        # Count whitespace vs characters
        sample_size = min(5000, len(content))
        whitespace_chars = sum(1 for c in content[:sample_size] if c.isspace())
        whitespace_ratio = whitespace_chars / sample_size if sample_size > 0 else 0
        
        # Check for minified indicators
        minified_indicators = [
            avg_line_length > 400,  # Very long lines
            whitespace_ratio < 0.05,  # Very little whitespace
            line_count < 10 and len(content) > 1000,  # Few lines but large content
            all(len(line.strip()) > 300 for line in lines[:10] if line.strip()),  # First 10 lines are long
            'function(' in content and '){' in content and ';' in content and '\n' not in content[:500],  # Minified function
            # Additional heuristic: very few different characters in first 100 chars
            len(set(content[:100])) < 20,
        ]
        
        return any(minified_indicators)

    def validate_jwt(self, token: str) -> bool:
        """Validate if a JWT is likely real (not test/example)"""
        parts = token.split('.')
        if len(parts) != 3:
            return False
        
        try:
            # Decode header
            header = parts[0] + '=' * (4 - len(parts[0]) % 4)
            header_decoded = base64.b64decode(header).decode('utf-8', errors='ignore')
            header_data = json.loads(header_decoded)
            
            # Check for valid JWT algorithm
            if 'alg' not in header_data:
                return False
            
            # Decode payload
            payload = parts[1] + '=' * (4 - len(parts[1]) % 4)
            payload_decoded = base64.b64decode(payload).decode('utf-8', errors='ignore')
            payload_data = json.loads(payload_decoded)
            
            # Check for test indicators
            test_indicators = ['test', 'example', 'demo', 'fake', 'dummy', 'placeholder', 'changeme']
            payload_str = str(payload_data).lower()
            
            if any(indicator in payload_str for indicator in test_indicators):
                return False
            
            # Check expiration if present
            if 'exp' in payload_data:
                if payload_data['exp'] < time.time():
                    return False  # Expired token
            
            # Check issued at if present
            if 'iat' in payload_data:
                if payload_data['iat'] > time.time() + 3600:  # Issued in the future (more than 1 hour)
                    return False
            
            return True
            
        except:
            return False

    def validate_base64(self, value: str) -> bool:
        """Validate if a string is likely a real base64 secret (not random text)"""
        if not value or len(value) < 20:
            return False
        
        # Check if it's valid base64
        try:
            # Remove any padding
            clean_value = value.replace('=', '')
            
            # Check character distribution (real base64 has more variety)
            unique_chars = set(clean_value)
            if len(unique_chars) < 10:  # Not enough character variety
                return False
            
            # Check for common false positives
            false_positives = [
                'dashicons', 'wp-content', 'wp-admin', 'wp-includes',
                'jquery', 'react', 'vue', 'angular', 'axios'
            ]
            if any(fp in value.lower() for fp in false_positives):
                return False
            
            # Try to decode
            padding = '=' * (4 - len(value) % 4)
            decoded = base64.b64decode(value + padding)
            
            # Check if decoded looks like text (might be a secret)
            try:
                text = decoded.decode('utf-8', errors='ignore')
                # If it decodes to readable text, check if it looks like a secret
                if len(text) > 10:
                    # Check for common secret patterns in decoded text
                    secret_indicators = ['key', 'secret', 'token', 'password', 'access', 'private', 'credential']
                    if any(indicator in text.lower() for indicator in secret_indicators):
                        return True
                    # If it looks like JSON, it might be a JWT payload or config
                    if text.strip().startswith('{') and text.strip().endswith('}'):
                        return True
            except:
                # Binary data - could be a real secret
                if len(decoded) > 10:  # Reasonable length for a secret
                    return True
            
            return False
            
        except:
            return False

    def validate_hex(self, value: str) -> bool:
        """Validate if a hex string is likely a secret"""
        if not value or len(value) < 20:
            return False
        
        # Remove 0x prefix if present
        clean_value = value.lower().replace('0x', '')
        
        # Must be valid hex
        if not all(c in '0123456789abcdef' for c in clean_value):
            return False
        
        # Check length - common secret lengths
        if len(clean_value) in [32, 40, 64]:  # MD5, SHA1, SHA256
            # Check if it's a common hash of empty string or test values
            common_hashes = {
                'd41d8cd98f00b204e9800998ecf8427e',  # MD5 of empty string
                'da39a3ee5e6b4b0d3255bfef95601890afd80709',  # SHA1 of empty string
                'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',  # SHA256 of empty string
            }
            if clean_value in common_hashes:
                return False
            
            # Check character distribution (real secrets have more randomness)
            unique_chars = set(clean_value)
            if len(unique_chars) < 8:  # Not enough character variety
                return False
            
            return True
        
        return False

    def analyze_context(self, line: str, value: str, secret_type: str) -> Tuple[bool, str]:
        """
        Analyze the context around a match to determine if it's likely a real secret
        
        Returns: (is_valid, confidence)
        """
        line_lower = line.lower()
        value_lower = value.lower()
        
        # 1. Check against false positive database
        if value_lower in self.false_positives:
            self.stats['false_positives_filtered'] += 1
            return False, "false_positive"
        
        # 2. Check against false positive patterns
        for pattern in self.compiled_fp_patterns:
            if pattern.search(line):
                self.stats['false_positives_filtered'] += 1
                return False, "false_positive_pattern"
        
        # 3. Check for common programming constructs
        programming_constructs = [
            r'\.(?:get|set|has|is|to|from)[A-Z]',  # Method names
            r'function\s+\w+',  # Function names
            r'class\s+\w+',  # Class names
            r'\.prototype\.',  # Prototype
            r'console\.(?:log|warn|error|info|debug)',  # Console calls
            r'require\(|import\s',  # Imports
            r'export\s',  # Exports
            r'\.then\(|\.catch\(|\.finally\(',  # Promise methods
            r'\.map\(|\.filter\(|\.reduce\(|\.forEach\(',  # Array methods
        ]
        
        for construct in programming_constructs:
            if re.search(construct, line, re.IGNORECASE):
                self.stats['false_positives_filtered'] += 1
                return False, "programming_construct"
        
        # 4. Check if value is too common/simple
        if len(value) < 10:
            self.stats['false_positives_filtered'] += 1
            return False, "too_short"
        
        # 5. Check for assignment context (high confidence)
        assignment_patterns = [
            r'(?:const|let|var|export\s+default|export\s+(?:const|let|var))\s+\w+\s*=\s*["\']' + re.escape(value) + r'["\']',
            r'\b(?:api[_-]?key|secret|token|password|access[_-]?key|private[_-]?key)\s*[=:]\s*["\']' + re.escape(value) + r'["\']',
        ]
        
        for pattern in assignment_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                return True, "high"
        
        # 6. Check if it's in an object/configuration (high confidence)
        object_patterns = [
            r'(?:apiKey|secret|token|password|accessKey|privateKey|clientSecret|authToken)\s*:\s*["\']' + re.escape(value) + r'["\']',
            r'["\'][^"\']+["\']\s*:\s*["\']' + re.escape(value) + r'["\']',  # Any key-value pair
        ]
        
        for pattern in object_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                return True, "high"
        
        # 7. Check if it's in a URL parameter (high confidence)
        if re.search(r'[?&](?:token|key|secret|auth|apikey|access[_-]?token)=["\']?' + re.escape(value), line_lower):
            return True, "high"
        
        # 8. Check if it's in a function call or string (medium confidence)
        if re.search(r'\w+\([^)]*["\']' + re.escape(value) + r'["\']', line):
            return True, "medium"
        
        # 9. Check if it's in a comment (medium confidence)
        if line_lower.strip().startswith('//') or '/*' in line_lower:
            # But check if it's a TODO/FIXME comment with a secret
            if any(word in line_lower for word in ['todo', 'fixme', 'note:', 'warning:', 'important:']):
                return True, "medium"
        
        # 10. Type-specific validation
        if "JWT" in secret_type:
            if self.validate_jwt(value):
                return True, "high"
            else:
                return False, "invalid_jwt"
        
        if "Base64" in secret_type or len(value) > 30:
            if self.validate_base64(value):
                return True, "medium"
            else:
                return False, "invalid_base64"
        
        if "Hex" in secret_type:
            if self.validate_hex(value):
                return True, "medium"
            else:
                return False, "invalid_hex"
        
        # 11. Check for common secret-like patterns
        secret_patterns = [
            r'^[A-Za-z0-9+/]{40,}=*$',  # Long base64
            r'^[a-fA-F0-9]{32,}$',  # Long hex
            r'^[A-Z]{2}_[a-zA-Z0-9_]+$',  # Like SK_xxx, AC_xxx
            r'^[a-z]+_[a-z]+_[a-zA-Z0-9_]+$',  # Like sk_live_xxx
        ]
        
        for pattern in secret_patterns:
            if re.match(pattern, value):
                return True, "medium"
        
        # Default to low confidence if we got this far
        return True, "low"

    def get_intelligent_context(self, line: str, match_start: int, match_end: int, is_minified: bool) -> str:
        """Get smart context around a match"""
        if is_minified:
            # For minified, show more context
            context_size = 200
        else:
            # For normal files, less context
            context_size = 100
        
        # Calculate bounds
        line_len = len(line)
        start = max(0, match_start - context_size)
        end = min(line_len, match_end + context_size)
        
        # Extract context
        context = line[start:end]
        
        # Try to start at a word boundary
        while start > 0 and context[0] not in (' ', '\t', '\n', ';', '=', ':', '{', '}', '(', ')', ','):
            start -= 1
            context = line[start:end]
        
        # Add ellipsis if we truncated
        if start > 0:
            context = "..." + context
        if end < line_len:
            context = context + "..."
        
        # Clean up
        context = re.sub(r'\s+', ' ', context).strip()
        context = context.replace('\n', ' ')
        context = context.replace('\t', ' ')
        
        return context

    def scan_line(self, line: str, line_num: int, file_path: str, is_minified: bool) -> List[SecretFinding]:
        """Scan a single line for secrets"""
        findings = []
        
        for secret_type, pattern in self.compiled_patterns.items():
            for match in pattern.finditer(line):
                # Extract the value
                groups = match.groups()
                if groups and groups[0]:
                    value = groups[0]
                else:
                    value = match.group(0)
                
                # Skip very short values (except for specific types)
                if len(value) < 8 and "JWT" not in secret_type:
                    continue
                
                # Analyze context
                is_valid, confidence = self.analyze_context(line, value, secret_type)
                
                if not is_valid:
                    continue
                
                # Get context for display
                context = self.get_intelligent_context(line, match.start(), match.end(), is_minified)
                
                # Create finding
                finding = SecretFinding(
                    secret_type=secret_type,
                    value=value,
                    context=context,
                    line_num=line_num,
                    confidence=confidence,
                    file_path=file_path,
                    is_minified=is_minified
                )
                
                findings.append(finding)
                
                # Update statistics
                if confidence == "high":
                    self.stats['findings_high'] += 1
                elif confidence == "medium":
                    self.stats['findings_medium'] += 1
                else:
                    self.stats['findings_low'] += 1
        
        return findings

    def scan_file(self, file_path: str) -> List[SecretFinding]:
        """Scan a file for secrets"""
        findings = []
        
        try:
            # Check file size
            file_size = os.path.getsize(file_path)
            if file_size > 100 * 1024 * 1024:  # 100MB
                print(f"  ⚠️  Large file ({file_size:,} bytes), sampling: {os.path.basename(file_path)}")
                # Sample the file
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read(5 * 1024 * 1024)  # First 5MB
            elif file_size == 0:
                return findings
            else:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
        except Exception as e:
            print(f"  ❌ Error reading {file_path}: {str(e)}")
            return findings
        
        # Check if minified
        is_minified = self.is_minified_file(content, file_path)
        
        if is_minified:
            self.stats['minified_files'] += 1
            # For minified files, scan as single line
            findings.extend(self.scan_line(content, 1, file_path, True))
        else:
            # For normal files, scan line by line
            lines = content.split('\n')
            for line_num, line in enumerate(lines, 1):
                # Skip comment-only lines (but still scan them for secrets in comments)
                stripped = line.strip()
                if stripped.startswith('//') or stripped.startswith('/*') or stripped.startswith('*'):
                    # Still scan comments for secrets
                    findings.extend(self.scan_line(line, line_num, file_path, False))
                    continue
                
                findings.extend(self.scan_line(line, line_num, file_path, False))
        
        self.stats['files_scanned'] += 1
        return findings

    def scan_directory(self, directory: str) -> Dict[str, List[SecretFinding]]:
        """Scan a directory recursively"""
        results = {}
        
        print(f"🔍 JSScan Pro - Scanning: {directory}")
        print("=" * 60)
        
        # Find all JavaScript files
        target_files = []
        for root, _, files in os.walk(directory):
            # Skip unnecessary directories
            skip_dirs = ['.git', 'node_modules', '__pycache__', '.idea', '.vscode', 'dist', 'build']
            if any(skip_dir in root for skip_dir in skip_dirs):
                continue
            
            for file in files:
                ext = os.path.splitext(file)[1].lower()
                if ext in self.scannable_extensions:
                    full_path = os.path.join(root, file)
                    target_files.append(full_path)
                elif file.endswith('.min.js') or file.endswith('.min.js.map'):
                    full_path = os.path.join(root, file)
                    target_files.append(full_path)
        
        print(f"📁 Found {len(target_files)} files to scan")
        
        if not target_files:
            print("❌ No JavaScript files found to scan")
            return results
        
        # Scan files
        for i, file_path in enumerate(target_files):
            if i % 50 == 0 and i > 0:
                print(f"   Scanned {i}/{len(target_files)} files...")
            
            findings = self.scan_file(file_path)
            if findings:
                results[file_path] = findings
        
        return results

    def print_results(self, results: Dict[str, List[SecretFinding]], target_dir: str):
        """Print results in a clean, organized format"""
        if not results:
            print("\n" + "=" * 60)
            print("✅ No secrets found!")
            print("=" * 60)
            return
        
        # Flatten all findings
        all_findings = []
        for file_findings in results.values():
            all_findings.extend(file_findings)
        
        # Group by confidence
        high_conf = [f for f in all_findings if f.confidence == "high"]
        medium_conf = [f for f in all_findings if f.confidence == "medium"]
        low_conf = [f for f in all_findings if f.confidence == "low"]
        
        print("\n" + "=" * 60)
        print("📊 SCAN RESULTS")
        print("=" * 60)
        print(f"📁 Files scanned: {self.stats['files_scanned']}")
        print(f"⚡ Minified files: {self.stats['minified_files']}")
        print(f"🚫 False positives filtered: {self.stats['false_positives_filtered']}")
        print(f"🔍 Total findings: {len(all_findings)}")
        print(f"   🔥 High confidence: {len(high_conf)}")
        print(f"   ⚠️  Medium confidence: {len(medium_conf)}")
        print(f"   ℹ️  Low confidence: {len(low_conf)}")
        print("=" * 60)
        
        # Print findings by confidence
        if high_conf:
            print("\n🔥 HIGH CONFIDENCE FINDINGS (Most likely real secrets):")
            print("-" * 60)
            self._print_findings_group(high_conf, target_dir)
        
        if medium_conf:
            print("\n⚠️  MEDIUM CONFIDENCE FINDINGS (Worth investigating):")
            print("-" * 60)
            self._print_findings_group(medium_conf, target_dir)
        
        if low_conf:
            print("\nℹ️  LOW CONFIDENCE FINDINGS (Likely false positives):")
            print("-" * 60)
            self._print_findings_group(low_conf, target_dir)
        
        # Print summary
        print("\n" + "=" * 60)
        print("💡 RECOMMENDATIONS:")
        print("-" * 60)
        
        if high_conf:
            print("1. 🔥 HIGH confidence findings should be investigated IMMEDIATELY")
            print("   These are very likely real secrets that could be exploited")
        
        if medium_conf:
            print("2. ⚠️  MEDIUM confidence findings should be validated manually")
            print("   Check the context to see if they're real secrets")
        
        print(f"3. 🚫 {self.stats['false_positives_filtered']} false positives were automatically filtered")
        print("4. 📝 Always verify findings manually before reporting")
        print("=" * 60)

    def _print_findings_group(self, findings: List[SecretFinding], target_dir: str):
        """Print a group of findings"""
        # Group by file
        by_file = {}
        for finding in findings:
            rel_path = os.path.relpath(finding.file_path, target_dir)
            if rel_path not in by_file:
                by_file[rel_path] = []
            by_file[rel_path].append(finding)
        
        # Print each file
        for file_path, file_findings in sorted(by_file.items()):
            print(f"\n📄 File: {file_path}")
            if file_findings and file_findings[0].is_minified:
                print("   (Minified file)")
            
            for finding in file_findings:
                confidence_symbol = "🔥" if finding.confidence == "high" else "⚠️" if finding.confidence == "medium" else "ℹ️"
                print(f"   {confidence_symbol} Line {finding.line_num}: [{finding.secret_type}]")
                print(f"      Context: {finding.context}")
                
                # Show value (truncated if long)
                if len(finding.value) > 50:
                    print(f"      Value: {finding.value[:50]}... (truncated, {len(finding.value)} chars)")
                else:
                    print(f"      Value: {finding.value}")

    def export_results(self, results: Dict[str, List[SecretFinding]], output_file: str):
        """Export results to JSON file"""
        export_data = {
            'scan_summary': {
                'files_scanned': self.stats['files_scanned'],
                'minified_files': self.stats['minified_files'],
                'false_positives_filtered': self.stats['false_positives_filtered'],
                'total_findings': sum(len(v) for v in results.values()),
            },
            'findings': []
        }
        
        for file_path, findings in results.items():
            for finding in findings:
                export_data['findings'].append({
                    'file': file_path,
                    'type': finding.secret_type,
                    'value': finding.value,
                    'context': finding.context,
                    'line': finding.line_num,
                    'confidence': finding.confidence,
                    'is_minified': finding.is_minified,
                })
        
        with open(output_file, 'w') as f:
            json.dump(export_data, f, indent=2)
        
        print(f"\n💾 Results exported to: {output_file}")


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description='JSScan Pro - Advanced JavaScript Secret Scanner')
    parser.add_argument('directory', help='Directory to scan')
    parser.add_argument('-a', '--aggressive', action='store_true', 
                       help='Use aggressive mode (more patterns, more false positives)')
    parser.add_argument('-o', '--output', help='Export results to JSON file')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    if not os.path.isdir(args.directory):
        print(f"❌ Error: {args.directory} is not a valid directory")
        sys.exit(1)
    
    # Create scanner
    scanner = JSScanPro(aggressive_mode=args.aggressive)
    
    # Scan directory
    results = scanner.scan_directory(args.directory)
    
    # Print results
    scanner.print_results(results, args.directory)
    
    # Export if requested
    if args.output:
        scanner.export_results(results, args.output)


if __name__ == "__main__":
    main()
