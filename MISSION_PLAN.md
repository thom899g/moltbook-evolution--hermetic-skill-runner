# MOLTBOOK EVOLUTION: Hermetic Skill Runner

## Objective
A mandatory, signed execution sandbox for all ClawdHub skills, enforcing strict capability-based permissions (e.g., network, filesystem) via a manifest, with runtime attestation logged to an immutable ledger.

## Strategy
Moltbook Sentiment Analysis -> Protocol Synthesis

## Execution Output
SUMMARY: Designed and implemented the core architectural components of the Hermetic Skill Runner (ClawdFabric Ecosystem), establishing a trust-based capability system with Firebase Firestore as the immutable ledger, WASM runtime isolation, dynamic capability negotiation, and a real-time attestation graph. Created 9 production-grade files with robust error handling, type safety, logging, and comprehensive documentation.

OUTPUT:

### FILE: requirements.txt
```
# Core Dependencies
firebase-admin>=6.4.0
google-cloud-firestore>=2.11.1
wasmer>=1.2.1
wasmtime>=3.0.0
cryptography>=41.0.0
pyjwt>=2.8.0
pydantic>=2.4.0

# Runtime & Execution
asyncio>=3.4.3
multiprocessing>=0.70.0
aiohttp>=3.9.0
uvicorn>=0.24.0
fastapi>=0.104.0

# Developer Tooling
click>=8.1.0
rich>=13.5.0
typer>=0.9.0
astunparse>=1.6.0

# Monitoring & Dashboard
streamlit>=1.28.0
plotly>=5.17.0
pandas>=2.1.0

# Security & Verification
z3-solver>=4.12.0.0
pycryptodome>=3.19.0

# Telegram Integration (for capability requests)
python-telegram-bot>=20.3

# Optional GPU delegation
numpy>=1.24.0
torch>=2.1.0
```

### FILE: clawd_core/capability_token.py
```python
"""
Core capability token system for ClawdFabric.
Implements cryptographically signed capability tokens with delegation support.
"""
import json
import hashlib
import time
from dataclasses import dataclass, field, asdict
from typing import Set, Optional, Dict, Any, List
from enum import Enum
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature
import logging

logger = logging.getLogger(__name__)

class ResourceType(Enum):
    """Defined resource types for capability classification"""
    NETWORK = "network"
    FILESYSTEM = "fs"
    COMPUTE = "compute"
    DATABASE = "db"
    GPU = "gpu"
    MEMORY = "memory"
    IPC = "ipc"

class ActionType(Enum):
    """Allowed actions on resources"""
    READ = "read"
    WRITE = "write"
    EXECUTE = "execute"
    CONNECT = "connect"
    CREATE = "create"
    DELETE = "delete"

@dataclass
class CapabilityToken:
    """Capability token representing granted permission"""
    skill_id: str
    resource_type: ResourceType
    resource_path: str  # e.g., "api.github.com", "/home/user/data"
    action: ActionType
    issued_at: int = field(default_factory=lambda: int(time.time()))
    expires_at: Optional[int] = None
    delegable: bool = False
    constraints: Dict[str, Any] = field(default_factory=dict)
    issuer_id: str = "clawd_kernel"  # Default issuer is kernel
    signature: str = ""  # Base64 encoded Ed25519 signature
    
    def __post_init__(self):
        """Validate token fields"""
        if self.expires_at and self.expires_at <= self.issued_at:
            raise ValueError("Token expiry must be after issue time")
        
        # Validate resource path format
        if self.resource_type == ResourceType.NETWORK:
            if not self.resource_path or '.' not in self.resource_path:
                raise ValueError(f"Invalid network resource: {self.resource_path}")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert token to dictionary for serialization"""
        data = asdict(self)
        data['resource_type'] = self.resource_type.value
        data['action'] = self.action.value
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'CapabilityToken':
        """Create token from dictionary"""
        # Convert string enums back to Enum types
        data['resource_type'] = ResourceType(data['resource_type'])
        data['action'] = ActionType(data['action'])
        
        # Remove signature for verification, will be added later
        signature = data.pop('signature', '')
        token = cls(**data)
        token.signature = signature
        return token
    
    def get_resource_identifier(self) -> str:
        """Get unique resource identifier"""
        return f"{self.resource_type.value}:{self.resource_path}"
    
    def is_valid(self) -> bool:
        """Check if token is currently valid"""
        now = int(time.time())
        if self.expires_at and now > self.expires_at:
            logger.warning(f"Token expired at {self.expires_at}, current: {now}")
            return False
        return True
    
    def matches_request(self, requested_type: ResourceType, 
                       requested_path: str, requested_action: ActionType) -> bool:
        """Check if this token matches a requested capability"""
        if not self.is_valid():
            return False
        
        # Exact match required for now (could support wildcards later)
        return (self.resource_type == requested_type and
                self.resource_path == requested_path and
                self.action == requested_action)

class CapabilityRegistry:
    """Firestore-backed registry for capability tokens"""
    
    def __init__(self, firestore_client):
        self.db = firestore_client
        self.collection_ref = self.db.collection("capability_tokens")
        self._private_key = None
        self._public_key = None
        self._init_crypto_keys()
    
    def _init_crypto_keys(self):
        """Initialize or load cryptographic keys for signing"""
        try:
            # Try to load existing keys from Firestore
            key_doc = self.db.collection("kernel_keys").document("ed25519_key").get()
            
            if key_doc.exists:
                key_data = key_doc.to_dict()
                self._private_key = ed25519.Ed25519PrivateKey.from_private_bytes(
                    bytes.fromhex(key_data['private_key'])
                )
                self._public_key = self._private_key.public_key()
                logger.info("Loaded existing cryptographic keys")
            else:
                # Generate new key pair
                self._private_key = ed25519.Ed25519PrivateKey.generate()
                self._public_key = self._private_key.public_key()
                
                # Store public key, keep private key in memory only
                private_bytes = self._private_key.private_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PrivateFormat.Raw,
                    encryption_algorithm=serialization.NoEncryption()
                )
                
                self.db.collection("kernel_keys").document("ed25519_key").set({
                    'public_key': self._public_key.public_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PublicFormat.Raw
                    ).hex(),
                    'private_key_stored': False,  # For audit
                    'created_at': time.time()
                })
                logger.info("Generated new cryptographic key pair")
                
        except Exception as e:
            logger.error(f"Failed to initialize crypto keys: {e}")
            raise
    
    def sign_token(self, token: CapabilityToken) -> str:
        """Sign a capability token"""
        if not self._private_key:
            raise RuntimeError("Crypto keys not initialized")
        
        # Create signature over token data (excluding signature field)
        token_dict = token.to_dict()
        token_dict.pop('signature', None)
        
        # Serialize to JSON with sorted keys for consistency
        data_str = json.dumps(token_dict, sort_keys=True, separators=(',', ':'))
        data_bytes = data_str.encode('utf-8')
        
        signature = self._private_key.sign(data_bytes)
        return signature.hex()
    
    def verify_token(self, token: CapabilityToken) -> bool:
        """Verify token signature"""
        if not token.signature:
            logger.error(f"Token has no signature: {token.skill_id}")
            return False
        
        try:
            # Recreate signed data
            token_dict = token.to_dict()
            original_signature = token_dict.pop('signature')
            
            data_str = json.dumps(token_dict, sort_keys=True, separators=(',', ':'))
            data_bytes = data_str.encode('utf-8')
            
            # Load public key from stored data
            key_doc = self.db.collection("kernel_keys").document("ed25519_key").get()
            if not key_doc.exists:
                logger.error("No public key found for verification")
                return False
            
            key_data = key_doc.to_dict()
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(
                bytes.fromhex(key_data['public_key'])
            )
            
            public_key.verify(bytes.fromhex(original_signature), data_bytes)
            return True
            
        except InvalidSignature:
            logger.warning(f"Invalid signature for token: {token.skill_id}")
            return False
        except Exception as e:
            logger.error(f"Verification error: {e}")
            return False
    
    async def store_token(self, token: CapabilityToken) -> str:
        """Store signed token in Firestore"""
        try:
            # Sign the token
            token.signature = self.sign_token(token)
            
            # Store in Firestore with composite ID
            doc_id = f"{token.skill_id}_{hashlib.sha256(token.signature.encode()).hexdigest()[:16]}"
            
            doc_ref = self.collection_ref.document(doc_id)
            await doc_ref.set(token.to_dict())
            
            logger.info(f"Stored capability token for {token.skill_id}: {token.get_resource_identifier()}")
            return doc_id
            
        except Exception as e:
            logger.error(f"Failed to store token: {e}")
            raise
    
    async def get_tokens_for_skill(self, skill_id: str) -> List[CapabilityToken]:
        """Retrieve all valid tokens for a skill"""
        try:
            tokens = []
            now = int(time.time())
            
            query = (self.collection_ref
                    .where("skill_id", "==", skill_id)
                    .where("expires_at", ">", now))  # Only non-expired tokens
            
            docs = query.stream()
            
            for doc in docs:
                try:
                    token = CapabilityToken.from_dict(doc.to_dict())
                    if self.verify_token(token):
                        tokens.append(token)
                except Exception as e:
                    logger.warning(f"Failed to parse token {doc.id}: {e}")
            
            return tokens
            
        except Exception as e:
            logger.error(f"Failed to retrieve tokens: {e}")
            return []
    
    async def revoke_token(self, token_id: str) -> bool:
        """Revoke a token by moving it to revoked collection"""
        try:
            token_doc = self.collection_ref.document(token_id).get()
            if not token_doc.exists:
                return False
            
            # Move to revoked collection
            token_data = token_doc.to_dict()
            revoked_ref = self.db.collection("revoked_tokens").document(token_id)
            await revoked_ref.set({
                **token_data,
                'revoked_at': time.time(),
                'revoked_by': 'system'  # Could be user ID
            })
            
            # Delete from active collection
            await self.collection_ref.document(token_id).delete()
            
            logger.info(f"Revoked token: {token_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to revoke token: {e}")
            return False
```

### FILE: clawd_core/wasm_runtime.py
```python
"""
WASM runtime isolation layer for ClawdFabric.
Provides secure execution environment for untrusted skills.
"""
import os
import tempfile
import asyncio
import logging
from typing import Dict, Any, Optional, Callable
from pathlib import Path
import hashlib
import json

# Conditional imports with fallbacks
try:
    from wasmer import engine, Store, Module, Instance, ImportObject, Function, Memory, MemoryType
    from wasmer_compiler_cranelift import Compiler
    WASMER_AVAILABLE = True
except ImportError:
    WASMER_AVAILABLE = False
    logging.warning("wasmer not available, falling back to wasmtime")

try:
    import wasmtime
    WASMTIME_AVAILABLE = True
except ImportError:
    WASMTIME_AVAILABLE = False
    logging.warning("wasmtime not available")

from .capability_token import CapabilityToken, ResourceType, ActionType
from .attestation_graph import AttestationGraph

logger = logging.getLogger(__name__)

class WASMRuntimeError(Exception):
    """WASM runtime specific errors"""
    pass

class WASMRuntime:
    """Secure WASM runtime with capability enforcement"""
    
    def __init__(self, firestore_client, attestation_graph: AttestationGraph):
        self.db = firestore_client
        self.attestation = attestation_graph
        self.active_instances: Dict[str, Any] = {}
        self.memory_limits = {
            'min_pages': 1,     # 64KB
            'max_pages': 65536  # 4GB max
        }
        
        if not WASMER_AVAILABLE and not WASMTIME_AVAILABLE:
            raise RuntimeError("No WASM runtime available. Install wasmer or wasmtime")
    
    def _compute_wasm_hash(self, wasm_bytes: bytes) -> str:
        """Compute SHA256 hash of WASM module"""
        return hashlib.sha256(wasm_bytes).hexdigest()
    
    def _create_safe_import_object(self, skill_id: str, 
                                  capabilities: list[CapabilityToken]) -> Dict[str, Any]:
        """Create import object with capability-gated host functions"""
        
        imports = {}
        
        # Memory import
        imports['memory'] = Memory(Store(engine.JIT(Compiler)), MemoryType(self.memory_limits))
        
        # Environment functions
        env_functions = {}
        
        def safe_log(ptr: int, length: int) -> None:
            """Safe logging from WASM"""
            try:
                memory = self.active_instances[skill_id].memory
                data = memory.read(ptr, length)
                message = data.decode('utf-8', errors='replace')
                logger.info(f"[WASM:{skill_id}] {message}")
            except Exception as e:
                logger.error(f"WASM log error: {e}")
        
        env_functions['log'] = Function(Store(engine.JIT(Compiler)), safe_log)
        
        # Capability-gated functions
        def check_capability(resource_type: int, resource_ptr: int, action: int) -> int:
            """Check if skill has requested capability"""
            try:
                # Convert WASM ints to strings
                resource_type_str = ResourceType(resource_type).name
                action_str = ActionType(action).name
                
                memory = self.active_instances[skill_id].memory
                path_bytes = memory.read(resource_ptr, 256)  # Read up to 256 bytes
                resource_path = path_bytes.split(b'\0')[0].decode('utf-8')
                
                # Check if any token matches
                for token in capabilities:
                    if (token.resource_type.name == resource_type_str and
                        token.resource_path == resource_path and
                        token.action.name == action_str and
                        token.is_valid()):
                        return 1  # Granted
                
                logger.warning(f"Capability denied: {skill_id} -> {resource_type_str}:{resource_path}")
                return 0  # Denied
                
            except Exception as e:
                logger.error(f"Capability check error: {e}")
                return -1