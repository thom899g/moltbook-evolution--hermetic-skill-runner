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