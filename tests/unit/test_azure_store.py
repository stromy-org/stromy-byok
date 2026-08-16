"""The Azure branch, against a fake SecretClient.

This is the plan's "fake Azure store sequence" gate. Until it existed the
entire ``AzureKeyVaultCredentialStore`` — the only store that ever runs in
production — was reachable only against a live vault, so the properties the
whole design turns on were asserted nowhere:

* **disable, never delete.** The implementation this replaces called
  ``begin_delete_secret``. On a soft-delete vault that leaves the name
  unrecreatable until recovery or purge, so "remove my key" bricked
  re-registration for the retention window.
* **read_order fall-through**, which is what keeps already-registered callers
  working across the C3 rename.
* **enabled-flag semantics**, where a disabled secret still resolves by name
  and must read as absent rather than raise.

The fake models exactly those three behaviours and nothing else.
"""

from __future__ import annotations

import pytest
from azure.core.exceptions import ResourceNotFoundError

from stromy_byok import (
    AzureKeyVaultCredentialStore,
    CredentialId,
    Subject,
    legacy_naming,
    secret_name,
)
from tests.conftest import OPENAI


class _FakeProperties:
    def __init__(self, enabled: bool, tags: dict[str, str] | None) -> None:
        self.enabled = enabled
        self.tags = tags


class _FakeSecret:
    def __init__(self, value: str, properties: _FakeProperties) -> None:
        self.value = value
        self.properties = properties


class FakeSecretClient:
    """The slice of ``SecretClient`` this store actually uses.

    Deliberately raises the real ``ResourceNotFoundError`` — the store catches
    that exact type, so a stand-in exception would make the tests pass while
    production took a different branch.
    """

    def __init__(self) -> None:
        self.secrets: dict[str, _FakeSecret] = {}
        self.deleted: list[str] = []

    def get_secret(self, name: str) -> _FakeSecret:
        if name not in self.secrets:
            raise ResourceNotFoundError(f"secret {name} not found")
        return self.secrets[name]

    def set_secret(
        self, name: str, value: str, *, tags: dict[str, str] | None = None, enabled: bool = True
    ) -> _FakeSecret:
        self.secrets[name] = _FakeSecret(value, _FakeProperties(enabled, tags))
        return self.secrets[name]

    def update_secret_properties(self, name: str, *, enabled: bool) -> None:
        self.secrets[name].properties.enabled = enabled

    def begin_delete_secret(self, name: str) -> None:  # pragma: no cover - must never be called
        self.deleted.append(name)


@pytest.fixture
def fake() -> FakeSecretClient:
    return FakeSecretClient()


@pytest.fixture
def azure_store(fake: FakeSecretClient) -> AzureKeyVaultCredentialStore:
    """The store as an adopting application configures it (media-gen, in C3)."""
    return AzureKeyVaultCredentialStore(
        # A stand-in vault, not a live one. The URL is inert here — the client is
        # injected below — and naming a real vault in a public test buys nothing.
        "https://kv-example-byok.vault.azure.net/",
        naming=legacy_naming("mediagen-byok-"),
        client=fake,
    )


@pytest.mark.unit
def test_register_rotate_disconnect_reregister_never_deletes(
    azure_store: AzureKeyVaultCredentialStore, fake: FakeSecretClient, alice: Subject
) -> None:
    """The full lifecycle, and the negative that makes it work on a soft-delete vault."""
    azure_store.put_version(OPENAI, alice, "first")
    assert azure_store.get_enabled(OPENAI, alice) == "first"

    azure_store.put_version(OPENAI, alice, "rotated")
    assert azure_store.get_enabled(OPENAI, alice) == "rotated"

    assert azure_store.disable(OPENAI, alice) is True
    assert azure_store.get_enabled(OPENAI, alice) is None
    assert azure_store.exists(OPENAI, alice) is False

    azure_store.put_version(OPENAI, alice, "third")
    assert azure_store.get_enabled(OPENAI, alice) == "third"

    assert fake.deleted == []


@pytest.mark.unit
def test_a_disabled_secret_reads_as_absent_rather_than_raising(
    azure_store: AzureKeyVaultCredentialStore, alice: Subject
) -> None:
    """Disconnect is a normal state — the resolver's job is to fail the run cleanly."""
    azure_store.put_version(OPENAI, alice, "value")
    azure_store.disable(OPENAI, alice)

    assert azure_store.get_enabled(OPENAI, alice) is None


@pytest.mark.unit
def test_legacy_registration_still_resolves(
    azure_store: AzureKeyVaultCredentialStore, fake: FakeSecretClient, alice: Subject
) -> None:
    """A caller registered before C3 keeps working with nothing under the new name."""
    fake.set_secret(f"mediagen-byok-{alice.value}", "pre-existing")

    assert azure_store.get_enabled(OPENAI, alice) == "pre-existing"
    assert azure_store.exists(OPENAI, alice) is True


@pytest.mark.unit
def test_rotation_supersedes_the_legacy_name(
    azure_store: AzureKeyVaultCredentialStore, fake: FakeSecretClient, alice: Subject
) -> None:
    """The caller's previous key must not stay enabled at the old address."""
    legacy = f"mediagen-byok-{alice.value}"
    fake.set_secret(legacy, "old")

    azure_store.put_version(OPENAI, alice, "new")

    assert azure_store.get_enabled(OPENAI, alice) == "new"
    assert fake.secrets[legacy].properties.enabled is False
    assert fake.secrets[legacy].value == "old"  # superseded, never destroyed


@pytest.mark.unit
def test_disconnect_reaches_a_legacy_only_registration(
    azure_store: AzureKeyVaultCredentialStore, fake: FakeSecretClient, alice: Subject
) -> None:
    """A disable that only touched the primary would leave the real key live."""
    fake.set_secret(f"mediagen-byok-{alice.value}", "pre-existing")

    assert azure_store.disable(OPENAI, alice) is True
    assert azure_store.get_enabled(OPENAI, alice) is None
    assert azure_store.exists(OPENAI, alice) is False


@pytest.mark.unit
def test_exists_and_get_enabled_agree_on_a_disabled_primary(
    azure_store: AzureKeyVaultCredentialStore, fake: FakeSecretClient, alice: Subject
) -> None:
    """The first name that EXISTS decides, for both readers.

    Otherwise the UI reports "connected" over a credential the resolver
    refuses to return.
    """
    azure_store.put_version(OPENAI, alice, "current")
    fake.set_secret(f"mediagen-byok-{alice.value}", "stale")
    fake.secrets[secret_name(OPENAI, alice)].properties.enabled = False

    assert azure_store.get_enabled(OPENAI, alice) is None
    assert azure_store.exists(OPENAI, alice) is False


@pytest.mark.unit
def test_disable_reports_false_when_there_was_nothing_to_disable(
    azure_store: AzureKeyVaultCredentialStore, alice: Subject
) -> None:
    assert azure_store.disable(OPENAI, alice) is False


@pytest.mark.unit
def test_cross_subject_isolation(
    azure_store: AzureKeyVaultCredentialStore, alice: Subject, bob: Subject
) -> None:
    azure_store.put_version(OPENAI, alice, "alice-key")

    assert azure_store.get_enabled(OPENAI, bob) is None
    assert azure_store.exists(OPENAI, bob) is False


@pytest.mark.unit
def test_stored_tags_never_carry_the_raw_subject(
    azure_store: AzureKeyVaultCredentialStore, fake: FakeSecretClient, alice: Subject
) -> None:
    """A vault listing must not reconstruct the tenancy map."""
    azure_store.put_version(OPENAI, alice, "value")

    tags = fake.secrets[secret_name(OPENAI, alice)].properties.tags or {}
    assert alice.value not in repr(tags)
    assert "value" not in repr(tags)
    assert tags["credential_id"] == str(OPENAI)


@pytest.mark.unit
def test_metadata_reports_the_enabled_flag_without_the_value(
    azure_store: AzureKeyVaultCredentialStore, alice: Subject
) -> None:
    azure_store.put_version(OPENAI, alice, "value")
    assert (azure_store.metadata(OPENAI, alice) or {})["enabled"] == "true"

    azure_store.disable(OPENAI, alice)
    meta = azure_store.metadata(OPENAI, alice) or {}
    assert meta["enabled"] == "false"
    assert "value" not in repr(meta)


@pytest.mark.unit
def test_put_version_rejects_empty_value(
    azure_store: AzureKeyVaultCredentialStore, alice: Subject
) -> None:
    with pytest.raises(ValueError, match="non-empty"):
        azure_store.put_version(CredentialId("openai-api"), alice, "")
