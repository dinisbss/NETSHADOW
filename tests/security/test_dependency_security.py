
import pytest

from security.dependency_audit import (
    DependencyAudit,
    DependencyAuditError,
    DependencyResult,
)


def test_dependency_audit_initialization():
    auditor = DependencyAudit()

    assert auditor.dependencies
    assert auditor.get_results() == []


def test_dependency_audit_custom_dependencies():
    auditor = DependencyAudit({
        "pytest": "8.0",
        "psutil": "5.9",
    })

    assert len(auditor.dependencies) == 2


def test_dependency_audit_rejects_invalid_name():
    with pytest.raises(DependencyAuditError):
        DependencyAudit({"../invalid": "1.0"})


def test_dependency_audit_rejects_invalid_version():
    with pytest.raises(DependencyAuditError):
        DependencyAudit({"pytest": "invalid version"})


def test_dependency_audit_rejects_excessive_dependencies():
    dependencies = {
        f"package{i}": "1.0"
        for i in range(501)
    }

    with pytest.raises(DependencyAuditError):
        DependencyAudit(dependencies)


def test_dependency_audit_detects_installed_package(monkeypatch):
    from security import dependency_audit

    monkeypatch.setattr(
        dependency_audit.importlib.metadata,
        "version",
        lambda name: "8.2.0",
    )

    auditor = DependencyAudit({"pytest": "8.0"})
    results = auditor.run_audit()

    assert len(results) == 1
    assert results[0].installed is True
    assert results[0].status == "OK"


def test_dependency_audit_detects_missing_package(monkeypatch):
    from security import dependency_audit

    def fake_version(name):
        raise dependency_audit.importlib.metadata.PackageNotFoundError(name)

    monkeypatch.setattr(
        dependency_audit.importlib.metadata,
        "version",
        fake_version,
    )

    auditor = DependencyAudit({"missing-package": None})
    results = auditor.run_audit()

    assert results[0].installed is False
    assert results[0].status == "MISSING"


def test_dependency_audit_detects_outdated_package(monkeypatch):
    from security import dependency_audit

    monkeypatch.setattr(
        dependency_audit.importlib.metadata,
        "version",
        lambda name: "1.5",
    )

    auditor = DependencyAudit({"pytest": "2.0"})
    results = auditor.run_audit()

    assert results[0].status == "OUTDATED"


def test_dependency_audit_summary(monkeypatch):
    from security import dependency_audit

    def fake_version(name):
        if name == "missing-package":
            raise dependency_audit.importlib.metadata.PackageNotFoundError(name)

        return "2.0"

    monkeypatch.setattr(
        dependency_audit.importlib.metadata,
        "version",
        fake_version,
    )

    auditor = DependencyAudit({
        "pytest": "1.0",
        "missing-package": None,
    })

    auditor.run_audit()
    summary = auditor.get_summary()

    assert summary["total"] == 2
    assert summary["installed"] == 1
    assert summary["missing"] == 1


def test_dependency_audit_get_results_returns_copy(monkeypatch):
    from security import dependency_audit

    monkeypatch.setattr(
        dependency_audit.importlib.metadata,
        "version",
        lambda name: "2.0",
    )

    auditor = DependencyAudit({"pytest": None})
    auditor.run_audit()

    results = auditor.get_results()
    results.clear()

    assert len(auditor.get_results()) == 1


def test_dependency_audit_check_package(monkeypatch):
    from security import dependency_audit

    monkeypatch.setattr(
        dependency_audit.importlib.metadata,
        "version",
        lambda name: "2.0",
    )

    auditor = DependencyAudit({"pytest": None})
    auditor.run_audit()

    result = auditor.check_package("pytest")

    assert result is not None
    assert result.name == "pytest"


def test_dependency_audit_check_invalid_package():
    auditor = DependencyAudit()

    with pytest.raises(DependencyAuditError):
        auditor.check_package("../invalid")


def test_dependency_audit_reset(monkeypatch):
    from security import dependency_audit

    monkeypatch.setattr(
        dependency_audit.importlib.metadata,
        "version",
        lambda name: "2.0",
    )

    auditor = DependencyAudit({"pytest": None})
    auditor.run_audit()
    auditor.reset()

    assert auditor.get_results() == []


def test_dependency_result_structure():
    result = DependencyResult(
        name="pytest",
        required=True,
        installed=True,
        installed_version="8.2.0",
        minimum_version="8.0",
        status="OK",
        message="Dependência instalada.",
    )

    assert result.name == "pytest"
    assert result.installed is True
    assert result.status == "OK"
