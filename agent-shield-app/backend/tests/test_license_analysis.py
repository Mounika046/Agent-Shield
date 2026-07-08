import unittest

from app.schemas import (
    DependencyInventory,
    DependencySourceType,
    MetadataEnrichment,
    NormalizedDependency,
    VersionKind,
)
from app.services.license_analysis import build_license_analysis
from app.utils.repo_utils import parse_requirements_txt


class LicenseAnalysisTests(unittest.TestCase):
    def test_uses_github_spdx_license(self):
        inventory = DependencyInventory(
            dependencies=[
                NormalizedDependency(
                    name="example",
                    version="1.0.0",
                    version_kind=VersionKind.EXACT,
                    ecosystem="PyPI",
                    source_type=DependencySourceType.GITHUB_SBOM,
                    metadata={"license_declared": "MIT"},
                )
            ]
        )

        result = build_license_analysis(inventory)

        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["summary"]["allowed"], 1)
        self.assertEqual(result["findings"][0]["source"], "github_sbom")

    def test_uses_deps_dev_and_denies_configured_license(self):
        inventory = DependencyInventory(
            dependencies=[
                NormalizedDependency(
                    name="example",
                    version="1.0.0",
                    version_kind=VersionKind.EXACT,
                    ecosystem="npm",
                    source_type=DependencySourceType.DIRECT_PACKAGE,
                )
            ]
        )
        metadata = MetadataEnrichment(
            provider="deps.dev",
            status="success",
            data={"packages": [{"name": "example", "version": "1.0.0", "licenses": ["AGPL-3.0-only"]}]},
        )

        result = build_license_analysis(inventory, metadata)

        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["summary"]["denied"], 1)
        self.assertEqual(result["findings"][0]["source"], "deps.dev")

    def test_unknown_license_requires_review(self):
        inventory = DependencyInventory(
            dependencies=[
                NormalizedDependency(
                    name="unversioned",
                    version="",
                    version_kind=VersionKind.UNKNOWN,
                    ecosystem="PyPI",
                    source_type=DependencySourceType.UPLOADED_FILE,
                )
            ]
        )

        result = build_license_analysis(inventory)

        self.assertEqual(result["status"], "review_required")
        self.assertEqual(result["summary"]["unknown"], 1)

    def test_unpinned_requirements_are_retained(self):
        dependencies = parse_requirements_txt("streamlit\npython-dotenv\nopenai\n")

        self.assertEqual([item.name for item in dependencies], ["streamlit", "python-dotenv", "openai"])
        self.assertTrue(all(item.version == "" for item in dependencies))

    def test_default_version_license_maps_back_to_unpinned_dependency(self):
        inventory = DependencyInventory(
            dependencies=[
                NormalizedDependency(
                    name="streamlit",
                    version="",
                    version_kind=VersionKind.UNKNOWN,
                    ecosystem="PyPI",
                    source_type=DependencySourceType.GITHUB_FILE,
                )
            ]
        )
        metadata = MetadataEnrichment(
            provider="deps.dev",
            status="success",
            data={
                "packages": [
                    {
                        "name": "streamlit",
                        "version": "1.52.0",
                        "requested_version": "",
                        "version_source": "deps_dev_default",
                        "licenses": ["Apache-2.0"],
                    }
                ]
            },
        )

        result = build_license_analysis(inventory, metadata)

        self.assertEqual(result["findings"][0]["license_expression"], "Apache-2.0")
        self.assertEqual(result["findings"][0]["version_source"], "deps_dev_default")


if __name__ == "__main__":
    unittest.main()
