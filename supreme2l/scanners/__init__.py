"""
Supreme 2 Light Scanner Heads
74 independent security scanner implementations
"""

from supreme2l.scanners.base import (
    BaseScanner,
    ScannerRegistry,
    ScannerResult,
    ScannerIssue,
    Severity
)
from supreme2l.scanners.python_scanner import PythonScanner
from supreme2l.scanners.bash_scanner import BashScanner
from supreme2l.scanners.bat_scanner import BatScanner
from supreme2l.scanners.yaml_scanner import YAMLScanner
from supreme2l.scanners.docker_scanner import DockerScanner
from supreme2l.scanners.docker_compose_scanner import DockerComposeScanner
from supreme2l.scanners.markdown_scanner import MarkdownScanner
from supreme2l.scanners.javascript_scanner import JavaScriptScanner
from supreme2l.scanners.terraform_scanner import TerraformScanner
from supreme2l.scanners.go_scanner import GoScanner
from supreme2l.scanners.json_scanner import JSONScanner
from supreme2l.scanners.ruby_scanner import RubyScanner
from supreme2l.scanners.php_scanner import PHPScanner
from supreme2l.scanners.rust_scanner import RustScanner
from supreme2l.scanners.sql_scanner import SQLScanner
from supreme2l.scanners.css_scanner import CSSScanner
from supreme2l.scanners.html_scanner import HTMLScanner
from supreme2l.scanners.kotlin_scanner import KotlinScanner
from supreme2l.scanners.swift_scanner import SwiftScanner
from supreme2l.scanners.cpp_scanner import CppScanner
from supreme2l.scanners.java_scanner import JavaScanner
from supreme2l.scanners.typescript_scanner import TypeScriptScanner
from supreme2l.scanners.scala_scanner import ScalaScanner
from supreme2l.scanners.perl_scanner import PerlScanner
from supreme2l.scanners.powershell_scanner import PowerShellScanner
from supreme2l.scanners.r_scanner import RScanner
from supreme2l.scanners.ansible_scanner import AnsibleScanner
from supreme2l.scanners.kubernetes_scanner import KubernetesScanner
from supreme2l.scanners.toml_scanner import TOMLScanner
from supreme2l.scanners.xml_scanner import XMLScanner
from supreme2l.scanners.protobuf_scanner import ProtobufScanner
from supreme2l.scanners.graphql_scanner import GraphQLScanner
from supreme2l.scanners.solidity_scanner import SolidityScanner
from supreme2l.scanners.lua_scanner import LuaScanner
from supreme2l.scanners.elixir_scanner import ElixirScanner
from supreme2l.scanners.haskell_scanner import HaskellScanner
from supreme2l.scanners.clojure_scanner import ClojureScanner
from supreme2l.scanners.dart_scanner import DartScanner
from supreme2l.scanners.groovy_scanner import GroovyScanner
from supreme2l.scanners.vim_scanner import VimScanner
from supreme2l.scanners.cmake_scanner import CMakeScanner
from supreme2l.scanners.make_scanner import MakeScanner
from supreme2l.scanners.nginx_scanner import NginxScanner
from supreme2l.scanners.zig_scanner import ZigScanner
from supreme2l.scanners.env_scanner import EnvScanner
from supreme2l.scanners.mcp_config_scanner import MCPConfigScanner
from supreme2l.scanners.mcp_server_scanner import MCPServerScanner
from supreme2l.scanners.ai_context_scanner import AIContextScanner
from supreme2l.scanners.agent_memory_scanner import AgentMemoryScanner
from supreme2l.scanners.rag_security_scanner import RAGSecurityScanner
from supreme2l.scanners.a2a_scanner import A2AScanner
from supreme2l.scanners.prompt_leakage_scanner import PromptLeakageScanner
from supreme2l.scanners.tool_callback_scanner import ToolCallbackScanner
from supreme2l.scanners.agent_reflection_scanner import AgentReflectionScanner
from supreme2l.scanners.agent_planning_scanner import AgentPlanningScanner
from supreme2l.scanners.multi_agent_scanner import MultiAgentScanner
from supreme2l.scanners.owasp_llm_scanner import OWASPLLMScanner
from supreme2l.scanners.model_attack_scanner import ModelAttackScanner
from supreme2l.scanners.llmops_scanner import LLMOpsScanner
from supreme2l.scanners.vector_db_scanner import VectorDBScanner
from supreme2l.scanners.modelscan_scanner import ModelScanScanner
from supreme2l.scanners.garak_scanner import GarakScanner
from supreme2l.scanners.llm_guard_scanner import LLMGuardScanner
from supreme2l.scanners.react2shell_scanner import React2ShellScanner
from supreme2l.scanners.mcp_remote_rce_scanner import MCPRemoteRCEScanner
from supreme2l.scanners.docker_mcp_scanner import DockerMCPScanner
from supreme2l.scanners.post_quantum_scanner import PostQuantumScanner
from supreme2l.scanners.steganography_scanner import SteganographyScanner
from supreme2l.scanners.hyperparameter_scanner import HyperparameterScanner
from supreme2l.scanners.plugin_security_scanner import PluginSecurityScanner
from supreme2l.scanners.excessive_agency_scanner import ExcessiveAgencyScanner
from supreme2l.scanners.gitleaks_scanner import GitLeaksScanner
from supreme2l.scanners.semgrep_scanner import SemgrepScanner
from supreme2l.scanners.trivy_scanner import TrivyScanner

# Create global scanner registry
registry = ScannerRegistry()

# Register all available scanners
registry.register(PythonScanner())
registry.register(BashScanner())
registry.register(BatScanner())
registry.register(YAMLScanner())
registry.register(DockerScanner())
registry.register(DockerComposeScanner())
registry.register(MarkdownScanner())
registry.register(JavaScriptScanner())
registry.register(TerraformScanner())
registry.register(GoScanner())
registry.register(JSONScanner())
registry.register(RubyScanner())
registry.register(PHPScanner())
registry.register(RustScanner())
registry.register(SQLScanner())
registry.register(CSSScanner())
registry.register(HTMLScanner())
registry.register(KotlinScanner())
registry.register(SwiftScanner())
registry.register(CppScanner())
registry.register(JavaScanner())
registry.register(TypeScriptScanner())
registry.register(ScalaScanner())
registry.register(PerlScanner())
registry.register(PowerShellScanner())
registry.register(RScanner())
registry.register(AnsibleScanner())
registry.register(KubernetesScanner())
registry.register(TOMLScanner())
registry.register(XMLScanner())
registry.register(ProtobufScanner())
registry.register(GraphQLScanner())
registry.register(SolidityScanner())
registry.register(LuaScanner())
registry.register(ElixirScanner())
registry.register(HaskellScanner())
registry.register(ClojureScanner())
registry.register(DartScanner())
registry.register(GroovyScanner())
registry.register(VimScanner())
registry.register(CMakeScanner())
registry.register(MakeScanner())
registry.register(NginxScanner())
registry.register(ZigScanner())
registry.register(EnvScanner())
registry.register(MCPConfigScanner())
registry.register(MCPServerScanner())
registry.register(AIContextScanner())
registry.register(AgentMemoryScanner())
registry.register(RAGSecurityScanner())
registry.register(A2AScanner())
registry.register(PromptLeakageScanner())
registry.register(ToolCallbackScanner())
registry.register(AgentReflectionScanner())
registry.register(AgentPlanningScanner())
registry.register(MultiAgentScanner())
registry.register(OWASPLLMScanner())
registry.register(ModelAttackScanner())
registry.register(LLMOpsScanner())
registry.register(VectorDBScanner())
registry.register(ModelScanScanner())
registry.register(GarakScanner())
registry.register(LLMGuardScanner())
registry.register(React2ShellScanner())
registry.register(MCPRemoteRCEScanner())
registry.register(DockerMCPScanner())
registry.register(PostQuantumScanner())
registry.register(SteganographyScanner())
registry.register(HyperparameterScanner())
registry.register(PluginSecurityScanner())
registry.register(ExcessiveAgencyScanner())
registry.register(GitLeaksScanner())
registry.register(SemgrepScanner())
registry.register(TrivyScanner())

__all__ = [
    'BaseScanner',
    'ScannerRegistry',
    'ScannerResult',
    'ScannerIssue',
    'Severity',
    'PythonScanner',
    'BashScanner',
    'BatScanner',
    'YAMLScanner',
    'DockerScanner',
    'DockerComposeScanner',
    'MarkdownScanner',
    'JavaScriptScanner',
    'TerraformScanner',
    'GoScanner',
    'JSONScanner',
    'RubyScanner',
    'PHPScanner',
    'RustScanner',
    'SQLScanner',
    'CSSScanner',
    'HTMLScanner',
    'KotlinScanner',
    'SwiftScanner',
    'CppScanner',
    'JavaScanner',
    'TypeScriptScanner',
    'ScalaScanner',
    'PerlScanner',
    'PowerShellScanner',
    'RScanner',
    'AnsibleScanner',
    'KubernetesScanner',
    'TOMLScanner',
    'XMLScanner',
    'ProtobufScanner',
    'GraphQLScanner',
    'SolidityScanner',
    'LuaScanner',
    'ElixirScanner',
    'HaskellScanner',
    'ClojureScanner',
    'DartScanner',
    'GroovyScanner',
    'VimScanner',
    'CMakeScanner',
    'MakeScanner',
    'NginxScanner',
    'ZigScanner',
    'EnvScanner',
    'MCPConfigScanner',
    'MCPServerScanner',
    'AIContextScanner',
    'AgentMemoryScanner',
    'RAGSecurityScanner',
    'A2AScanner',
    'PromptLeakageScanner',
    'ToolCallbackScanner',
    'AgentReflectionScanner',
    'AgentPlanningScanner',
    'MultiAgentScanner',
    'OWASPLLMScanner',
    'ModelAttackScanner',
    'LLMOpsScanner',
    'VectorDBScanner',
    'ModelScanScanner',
    'GarakScanner',
    'LLMGuardScanner',
    'React2ShellScanner',
    'MCPRemoteRCEScanner',
    'DockerMCPScanner',
    'PostQuantumScanner',
    'SteganographyScanner',
    'HyperparameterScanner',
    'PluginSecurityScanner',
    'ExcessiveAgencyScanner',
    'GitLeaksScanner',
    'SemgrepScanner',
    'TrivyScanner',
    'registry',
]
