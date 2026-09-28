import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from vraptor.agent.config import ANALYST_AGENT_MAX_CONCURRENCY_ENV
from vraptor.agent.config import ANALYST_AGENT_MODEL_ENV
from vraptor.agent.config import ANALYST_AGENT_PROVIDER_ENV
from vraptor.agent.config import CONFIG_SOURCE_ENV
from vraptor.agent.config import CODEX_CONFIG_ENV
from vraptor.agent.config import DEFAULT_ANALYST_AGENT_MODEL
from vraptor.agent.config import SourceProvenance
from vraptor.agent.config import collect_unresolved_agent_config
from vraptor.agent.config import resolve_agent_execution
from vraptor.agent.factory import create_agent_runner


class AgentConfigTests(unittest.TestCase):
    def process(self, home: Path, **values: str) -> dict[str, str]:
        return {"HOME": str(home), **values}

    def write_codex(
        self,
        home: Path,
        *,
        model: str = "codex-model",
        provider: str = "openai",
        base_url: str = "",
        env_key: str = "CODEX_TEST_KEY",
    ) -> Path:
        path = home / ".codex" / "config.toml"
        path.parent.mkdir(parents=True, exist_ok=True)
        provider_name = "OpenAI" if provider == "openai" else "Azure OpenAI"
        path.write_text(
            "\n".join(
                [
                    f'model = "{model}"',
                    f'model_provider = "{provider}"',
                    f"[model_providers.{provider}]",
                    f'name = "{provider_name}"',
                    f'base_url = "{base_url}"',
                    f'env_key = "{env_key}"',
                    'wire_api = "responses"',
                    '[model_providers.%s.query_params]' % provider,
                    'api-version = "test-version"',
                    '[model_providers.%s.env_http_headers]' % provider,
                    'X-Test = "TEST_HEADER_VALUE"',
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        return path

    def test_unresolved_structure_is_immutable_and_contains_no_secret_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            unresolved = collect_unresolved_agent_config(
                repo_root=root,
                process_environment=self.process(
                    root / "home",
                    **{
                        ANALYST_AGENT_MODEL_ENV: "process-model",
                        "OPENAI_API_KEY": "secret-value",
                    },
                ),
            )
            self.assertNotIn("OPENAI_API_KEY", unresolved.fields)
            with self.assertRaises(TypeError):
                unresolved.fields["model"] = ()  # type: ignore[index]
            with self.assertRaises(Exception):
                unresolved.fields["model"][0].value = "changed"  # type: ignore[misc]

    def test_cli_precedes_process_and_preserves_exact_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            execution = resolve_agent_execution(
                repo_root=root,
                process_environment=self.process(
                    root / "home",
                    **{
                        CONFIG_SOURCE_ENV: "application",
                        ANALYST_AGENT_MODEL_ENV: "process-model",
                    },
                ),
                cli_values={"model": "cli-model", "model_source": "--model"},
                allow_missing_credentials=True,
            )
            self.assertEqual(execution.model, "cli-model")
            self.assertEqual(execution.route.field_sources["model"].kind, "cli")
            self.assertEqual(execution.route.field_sources["model"].name, "--model")
            self.assertTrue(execution.route.field_sources["model"].explicit)

    def test_one_concurrency_value_drives_route_and_public_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            execution = resolve_agent_execution(
                repo_root=root,
                process_environment=self.process(
                    root / "home",
                    **{
                        CONFIG_SOURCE_ENV: "application",
                        ANALYST_AGENT_MAX_CONCURRENCY_ENV: "5",
                        "AI_SKILLS_ANALYST_AGENT_OPENAI_" + "MAX_CONCURRENCY": "1",
                        "AI_SKILLS_ANALYST_AGENT_AZURE_OPENAI_" + "MAX_CONCURRENCY": "2",
                    },
                ),
                allow_missing_credentials=True,
            )

            self.assertEqual(execution.max_concurrency, 5)
            self.assertEqual(execution.route.max_concurrency, 5)
            self.assertEqual(
                execution.route.field_sources["max_concurrency"].name,
                ANALYST_AGENT_MAX_CONCURRENCY_ENV,
            )
            identity = execution.route.identity_dict()
            self.assertEqual(identity["max_concurrency"], 5)
            self.assertNotIn("scope_max_concurrency", identity)
            self.assertNotIn("provider_max_concurrency", identity)

    def test_process_precedes_repository_and_shared_dotenv(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "home"
            (root / ".env").write_text(
                f"{ANALYST_AGENT_MODEL_ENV}=repository-model\n",
                encoding="utf-8",
            )
            shared = home / ".codex" / ".env"
            shared.parent.mkdir(parents=True)
            shared.write_text(
                f"{ANALYST_AGENT_MODEL_ENV}=shared-model\n",
                encoding="utf-8",
            )
            execution = resolve_agent_execution(
                repo_root=root,
                process_environment=self.process(
                    home,
                    **{
                        CONFIG_SOURCE_ENV: "application",
                        ANALYST_AGENT_MODEL_ENV: "process-model",
                    },
                ),
                allow_missing_credentials=True,
            )
            source = execution.route.field_sources["model"]
            self.assertEqual(execution.model, "process-model")
            self.assertEqual(source.kind, "process_environment")
            self.assertEqual(source.location, "process")

    def test_repository_dotenv_precedes_shared_dotenv(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "home"
            (root / ".env").write_text(
                "\n".join(
                    [
                        f"{CONFIG_SOURCE_ENV}=application",
                        f"{ANALYST_AGENT_MODEL_ENV}=repository-model",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            shared = home / ".codex" / ".env"
            shared.parent.mkdir(parents=True)
            shared.write_text(
                f"{ANALYST_AGENT_MODEL_ENV}=shared-model\n",
                encoding="utf-8",
            )
            execution = resolve_agent_execution(
                repo_root=root,
                process_environment=self.process(home),
                allow_missing_credentials=True,
            )
            source = execution.route.field_sources["model"]
            self.assertEqual(execution.model, "repository-model")
            self.assertEqual(source.kind, "repository_dotenv")
            self.assertEqual(source.location, str(root / ".env"))

    def test_shell_dotenv_loader_marker_preserves_repository_provenance(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "home"
            (root / ".env").write_text(
                f"{ANALYST_AGENT_MODEL_ENV}=repository-model\n",
                encoding="utf-8",
            )
            execution = resolve_agent_execution(
                repo_root=root,
                process_environment=self.process(
                    home,
                    **{
                        "AI_SKILLS_ORIGINAL_PROCESS_ENV_KEYS": "HOME",
                        ANALYST_AGENT_MODEL_ENV: "repository-model",
                    },
                ),
                allow_missing_credentials=True,
            )
            self.assertEqual(execution.model, "repository-model")
            self.assertEqual(
                execution.route.field_sources["model"].kind,
                "repository_dotenv",
            )

    def test_shared_dotenv_precedes_codex_route(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "home"
            self.write_codex(home)
            shared = home / ".codex" / ".env"
            shared.write_text(
                f"{ANALYST_AGENT_MODEL_ENV}=shared-model\n",
                encoding="utf-8",
            )
            execution = resolve_agent_execution(
                repo_root=root,
                process_environment=self.process(home),
                allow_missing_credentials=True,
            )
            self.assertEqual(execution.model, "shared-model")
            self.assertEqual(
                execution.route.field_sources["model"].kind,
                "shared_dotenv",
            )

    def test_compatible_codex_route_precedes_application_default(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "home"
            config_path = self.write_codex(
                home,
                model="codex-model",
                base_url="https://example.test/v1",
            )
            execution = resolve_agent_execution(
                repo_root=root,
                process_environment=self.process(home),
                allow_missing_credentials=True,
            )
            route = execution.route
            self.assertEqual(route.model, "codex-model")
            self.assertEqual(route.base_url, "https://example.test/v1")
            self.assertEqual(route.codex_status, "selected")
            self.assertEqual(route.field_sources["model"].kind, "codex_route")
            self.assertEqual(
                route.field_sources["model"].location,
                str(config_path.resolve()),
            )
            self.assertEqual(route.field_sources["base_url"].kind, "codex_route")
            self.assertEqual(route.credential_variable, "CODEX_TEST_KEY")

    def test_explicit_value_equal_to_default_remains_explicit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "home"
            self.write_codex(home, model="different-codex-model")
            execution = resolve_agent_execution(
                repo_root=root,
                process_environment=self.process(
                    home,
                    **{ANALYST_AGENT_MODEL_ENV: DEFAULT_ANALYST_AGENT_MODEL},
                ),
                allow_missing_credentials=True,
            )
            source = execution.route.field_sources["model"]
            self.assertEqual(execution.model, DEFAULT_ANALYST_AGENT_MODEL)
            self.assertEqual(source.kind, "process_environment")
            self.assertTrue(source.explicit)

    def test_application_source_disables_codex_discovery(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "home"
            config_path = home / ".codex" / "config.toml"
            config_path.parent.mkdir(parents=True)
            config_path.write_text("not valid toml = [", encoding="utf-8")
            execution = resolve_agent_execution(
                repo_root=root,
                process_environment=self.process(
                    home,
                    **{CONFIG_SOURCE_ENV: "application"},
                ),
                allow_missing_credentials=True,
            )
            self.assertEqual(execution.route.codex_status, "disabled")
            self.assertEqual(execution.model, DEFAULT_ANALYST_AGENT_MODEL)
            self.assertEqual(
                execution.route.field_sources["model"].kind,
                "application_default",
            )

    def test_forced_codex_source_fails_when_route_is_missing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(RuntimeError, "not found"):
                resolve_agent_execution(
                    repo_root=root,
                    process_environment=self.process(
                        root / "home",
                        **{CONFIG_SOURCE_ENV: "codex"},
                    ),
                    allow_missing_credentials=True,
                )

    def test_incompatible_codex_route_is_not_partially_applied(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "home"
            self.write_codex(
                home,
                provider="azure",
                model="azure-model",
                base_url="https://azure.example.test/openai/v1",
            )
            execution = resolve_agent_execution(
                repo_root=root,
                process_environment=self.process(
                    home,
                    **{
                        ANALYST_AGENT_PROVIDER_ENV: "openai",
                        CONFIG_SOURCE_ENV: "auto",
                    },
                ),
                allow_missing_credentials=True,
            )
            self.assertEqual(execution.provider, "openai")
            self.assertEqual(execution.model, DEFAULT_ANALYST_AGENT_MODEL)
            self.assertEqual(execution.route.base_url, "")
            self.assertEqual(execution.route.codex_status, "incompatible")

    def test_credential_provenance_is_safe_and_secret_is_never_public_or_hashed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            secret = "test-secret-never-expose"
            execution = resolve_agent_execution(
                repo_root=root,
                process_environment=self.process(
                    root / "home",
                    **{
                        CONFIG_SOURCE_ENV: "application",
                        "OPENAI_API_KEY": secret,
                    },
                ),
            )
            public = execution.route.public_dict()
            rendered = json.dumps(public, sort_keys=True)
            self.assertNotIn(secret, rendered)
            self.assertNotIn(secret, execution.route.identity())
            self.assertTrue(public["credential_binding"]["configured"])
            self.assertEqual(
                public["credential_binding"]["source"]["kind"],
                "process_environment",
            )
            self.assertEqual(
                public["credential_binding"]["source"]["name"],
                "OPENAI_API_KEY",
            )
            self.assertEqual(execution.inputs.api_key, secret)

    def test_codex_app_server_uses_codex_managed_auth_without_environment_key(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            execution = resolve_agent_execution(
                repo_root=root,
                process_environment=self.process(
                    root / "home",
                    **{
                        CONFIG_SOURCE_ENV: "application",
                        "AI_SKILLS_ANALYST_AGENT_TRANSPORT": "codex_app_server",
                    },
                ),
            )
            self.assertEqual(execution.route.protocol, "codex_app_server")
            self.assertEqual(execution.route.auth_mode, "codex_managed")
            self.assertTrue(execution.route.credential_binding.configured)
            self.assertEqual(
                execution.route.credential_binding.source.kind,
                "codex_managed",
            )

    def test_compatible_azure_codex_route_uses_environment_backed_auth(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "home"
            self.write_codex(
                home,
                provider="azure",
                model="azure-deployment",
                base_url="https://azure.example.test/openai/v1",
                env_key="AZURE_ROUTE_KEY",
            )
            execution = resolve_agent_execution(
                repo_root=root,
                process_environment=self.process(
                    home,
                    AZURE_ROUTE_KEY="azure-secret",
                    TEST_HEADER_VALUE="header-secret",
                ),
            )
            public = execution.route.public_dict()
            rendered = json.dumps(public, sort_keys=True)
            self.assertEqual(execution.provider, "azure_openai")
            self.assertEqual(execution.model, "azure-deployment")
            self.assertEqual(execution.route.codex_status, "selected")
            self.assertEqual(
                public["credential_binding"]["source"]["name"],
                "AZURE_ROUTE_KEY",
            )
            self.assertTrue(public["header_bindings"]["X-Test"]["configured"])
            self.assertNotIn("azure-secret", rendered)
            self.assertNotIn("header-secret", rendered)

    def test_application_only_azure_entra_route_needs_no_api_key(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            execution = resolve_agent_execution(
                repo_root=root,
                process_environment=self.process(
                    root / "home",
                    **{
                        CONFIG_SOURCE_ENV: "application",
                        ANALYST_AGENT_PROVIDER_ENV: "azure_openai",
                        ANALYST_AGENT_MODEL_ENV: "deployment",
                        "AZURE_OPENAI_ENDPOINT": "https://azure.example.test",
                        "AZURE_OPENAI_AUTH_MODE": "entra",
                    },
                ),
            )
            self.assertEqual(execution.route.codex_status, "disabled")
            self.assertEqual(execution.route.auth_mode, "entra")
            self.assertEqual(
                execution.route.credential_binding.mode,
                "azure_default",
            )

    def test_environment_snapshot_is_not_reread_by_runner_factory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            execution = resolve_agent_execution(
                repo_root=root,
                process_environment=self.process(
                    root / "home",
                    **{
                        CONFIG_SOURCE_ENV: "application",
                        "OPENAI_API_KEY": "snapshot-key",
                    },
                ),
            )
            with (
                mock.patch.dict(os.environ, {"OPENAI_API_KEY": "later-key"}),
                mock.patch("vraptor.agent.factory.adapter_for") as adapter_for,
            ):
                adapter_for.return_value = mock.Mock()
                create_agent_runner(execution)
            configuration = adapter_for.call_args.args[0]
            self.assertEqual(configuration.inputs.api_key, "snapshot-key")

    def test_removed_noncanonical_codex_alias_is_ignored(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            execution = resolve_agent_execution(
                repo_root=root,
                process_environment=self.process(
                    root / "home",
                    **{
                        CONFIG_SOURCE_ENV: "application",
                        "AI_SKILLS_CODEX_CONFIG": "/does/not/exist",
                    },
                ),
                allow_missing_credentials=True,
            )
            self.assertEqual(execution.model, DEFAULT_ANALYST_AGENT_MODEL)
            self.assertNotIn("AI_SKILLS_CODEX_CONFIG", execution.route.public_dict())

    def test_cli_codex_path_provenance_uses_canonical_namespace(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "home"
            config_path = self.write_codex(home)
            execution = resolve_agent_execution(
                repo_root=root,
                process_environment=self.process(home),
                cli_values={
                    "codex_config": "$HOME/.codex/config.toml",
                    "codex_config_source": "--codex-config",
                },
                allow_missing_credentials=True,
            )
            self.assertEqual(
                execution.route.harness_config_path,
                str(config_path.resolve()),
            )
            self.assertEqual(
                execution.route.field_sources["model"].kind,
                "codex_route",
            )
            self.assertEqual(CODEX_CONFIG_ENV, "AI_SKILLS_ANALYST_AGENT_CODEX_CONFIG")


if __name__ == "__main__":
    unittest.main()
