"""Storage: opaque naming, cross-subject isolation, and the lifecycle."""

from __future__ import annotations

import pytest

from stromy_byok import (
    CredentialId,
    InMemoryCredentialStore,
    NullCredentialStore,
    StoreUnavailableError,
    Subject,
    SubjectKind,
    legacy_naming,
    require_writer,
    secret_name,
)
from tests.conftest import OPENAI


@pytest.mark.unit
def test_secret_name_never_contains_the_raw_subject(alice: Subject) -> None:
    name = secret_name(OPENAI, alice)
    assert alice.value not in name
    assert name.startswith("byok-openai-api-")


@pytest.mark.unit
def test_secret_name_is_key_vault_legal(alice: Subject) -> None:
    name = secret_name(OPENAI, alice)
    assert len(name) <= 127
    assert all(c.isalnum() and c.isascii() or c == "-" for c in name)


@pytest.mark.unit
def test_same_value_under_different_subject_kinds_does_not_collide() -> None:
    """A client slug and an oid that happen to share a string are distinct."""
    as_oid = Subject(SubjectKind.ENTRA_OID, "duke")
    as_slug = Subject(SubjectKind.CLIENT_SLUG, "duke")
    assert secret_name(OPENAI, as_oid) != secret_name(OPENAI, as_slug)


@pytest.mark.unit
def test_subject_repr_does_not_leak_the_value(alice: Subject) -> None:
    assert alice.value not in repr(alice)


@pytest.mark.unit
def test_cross_subject_isolation(store: InMemoryCredentialStore, alice: Subject, bob: Subject) -> None:
    store.put_version(OPENAI, alice, "sk-alice")
    assert store.get_enabled(OPENAI, alice) == "sk-alice"
    assert store.get_enabled(OPENAI, bob) is None
    assert store.exists(OPENAI, bob) is False


@pytest.mark.unit
def test_credentials_are_isolated_per_credential_id(
    store: InMemoryCredentialStore, alice: Subject
) -> None:
    store.put_version(OPENAI, alice, "sk-openai")
    assert store.get_enabled(CredentialId("deepseek-api"), alice) is None


@pytest.mark.unit
def test_register_rotate_disable_reregister_without_purge(
    store: InMemoryCredentialStore, alice: Subject
) -> None:
    """The full lifecycle Azure soft delete would have blocked.

    A delete-based disconnect makes the secret NAME unrecreatable until
    recovery or purge. Disabling leaves the name free, so re-registration is
    immediate — this test is the regression guard for that design choice.
    """
    store.put_version(OPENAI, alice, "sk-v1")
    assert store.get_enabled(OPENAI, alice) == "sk-v1"

    store.put_version(OPENAI, alice, "sk-v2")  # rotation
    assert store.get_enabled(OPENAI, alice) == "sk-v2"
    assert store.version_count(OPENAI, alice) == 2

    assert store.disable(OPENAI, alice) is True
    assert store.get_enabled(OPENAI, alice) is None
    assert store.exists(OPENAI, alice) is False

    store.put_version(OPENAI, alice, "sk-v3")  # re-registration
    assert store.get_enabled(OPENAI, alice) == "sk-v3"


@pytest.mark.unit
def test_disable_is_idempotent_and_reports_nothing_to_do(
    store: InMemoryCredentialStore, alice: Subject
) -> None:
    assert store.disable(OPENAI, alice) is False
    store.put_version(OPENAI, alice, "sk-1")
    assert store.disable(OPENAI, alice) is True
    assert store.disable(OPENAI, alice) is False


@pytest.mark.unit
def test_metadata_carries_no_secret_and_no_raw_subject(
    store: InMemoryCredentialStore, alice: Subject
) -> None:
    store.put_version(OPENAI, alice, "sk-supersecret")
    meta = store.metadata(OPENAI, alice)
    assert meta is not None
    flat = " ".join(f"{k}={v}" for k, v in meta.items())
    assert "sk-supersecret" not in flat
    assert alice.value not in flat
    assert meta["subject_hash"] == alice.hashed


@pytest.mark.unit
def test_null_store_declares_itself_unwritable() -> None:
    null = NullCredentialStore()
    assert null.writable is False
    with pytest.raises(StoreUnavailableError):
        require_writer(null)


@pytest.mark.unit
def test_require_writer_accepts_a_real_writer(store: InMemoryCredentialStore) -> None:
    assert require_writer(store) is store


@pytest.mark.unit
def test_require_writer_rejects_a_liar() -> None:
    """`writable = True` is not enough — the protocol must actually be there.

    Guards against the failure the declared-capability design replaced: a
    caller trusting a flag and blowing up at write time, mid-registration.
    """

    class Liar:
        writable = True

    with pytest.raises(StoreUnavailableError, match="does not implement"):
        require_writer(Liar())


@pytest.mark.unit
def test_legacy_naming_reads_old_name_and_writes_new(alice: Subject) -> None:
    naming = legacy_naming("mediagen-byok-")
    assert naming.primary(OPENAI, alice) == secret_name(OPENAI, alice)
    order = naming.read_order(OPENAI, alice)
    assert order[0] == secret_name(OPENAI, alice)
    assert order[-1] == f"mediagen-byok-{alice.value}"


@pytest.mark.unit
def test_legacy_naming_does_not_apply_across_subject_kinds(duke: Subject) -> None:
    """A client-slug subject must never read an oid-shaped legacy secret."""
    naming = legacy_naming("mediagen-byok-", kind=SubjectKind.ENTRA_OID)
    assert naming.read_order(OPENAI, duke) == (secret_name(OPENAI, duke),)


@pytest.mark.unit
def test_put_version_rejects_empty_value(store: InMemoryCredentialStore, alice: Subject) -> None:
    with pytest.raises(ValueError, match="non-empty"):
        store.put_version(OPENAI, alice, "")
