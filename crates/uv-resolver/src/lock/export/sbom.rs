use std::collections::BTreeSet;
use std::fmt::Formatter;

use serde::{Deserialize, Serialize};

use crate::lock::export::{ExportableRequirement, ExportableRequirements};
use crate::lock::{Package, Source};
use crate::{Installable, LockError};
use uv_configuration::{
    DependencyGroupsWithDefaults, EditableMode, ExtrasSpecificationWithDefaults, InstallOptions,
};
use uv_normalize::PackageName;

/// An export of a [`Lock`] that renders in CycloneDX SBOM format.
#[derive(Debug)]
pub struct SbomExport {
    /// The CycloneDX BOM document
    bom: CycloneDx,
}

impl<'lock> SbomExport {
    pub fn from_lock(
        target: &impl Installable<'lock>,
        prune: &[PackageName],
        extras: &ExtrasSpecificationWithDefaults,
        dev: &DependencyGroupsWithDefaults,
        annotate: bool,
        _editable: EditableMode,
        hashes: bool,
        install_options: &'lock InstallOptions,
    ) -> Result<Self, LockError> {
        // Extract the exportable requirements from the lock file
        let ExportableRequirements(nodes) = ExportableRequirements::from_lock(
            target,
            prune,
            extras,
            dev,
            annotate,
            install_options,
        );

        // Generate SBOM
        let bom = Self::generate_cyclone_dx_bom(target, &nodes, hashes)?;

        Ok(Self { bom })
    }

    fn generate_cyclone_dx_bom<'a>(
        target: &impl Installable<'a>,
        nodes: &[ExportableRequirement<'a>],
        include_hashes: bool,
    ) -> Result<CycloneDx, LockError> {
        // Generate unique BOM serial number using timestamp
        let now = jiff::Timestamp::now().as_nanosecond();
        let bom_ref = format!("urn:uv-bom:{}", now);
        let serial_number = format!("urn:uv-bom-serial:{}", now);

        // Determine the main component (workspace root or project)
        let main_component = Self::create_main_component(target, &bom_ref)?;

        // Create workspace member components
        let workspace_components = Self::create_workspace_components(target)?;

        // Create dependency components from exportable requirements (excluding workspace members)
        let mut dependency_components = Vec::new();
        let mut component_refs = BTreeSet::new();

        // Get workspace member names for filtering
        let workspace_member_names: BTreeSet<_> = target.lock().members().iter().collect();

        for node in nodes {
            // Skip workspace members - they're already added by create_workspace_components
            // But for single projects (no workspace members), we need to include the root package
            if !workspace_member_names.is_empty()
                && workspace_member_names.contains(&node.package.id.name)
            {
                continue;
            }

            let component = Self::create_component_from_package(node.package, include_hashes)?;
            let component_bom_ref = component.bom_ref.clone();

            if !component_refs.contains(&component_bom_ref) {
                component_refs.insert(component_bom_ref);
                dependency_components.push(component);
            }
        }

        // Combine all components
        let mut all_components = workspace_components;
        all_components.extend(dependency_components);

        // Create dependency relationships
        let dependencies =
            Self::create_dependency_relationships(target, nodes, &main_component.bom_ref)?;

        let metadata = Metadata {
            timestamp: Some(jiff::Timestamp::now().to_string()),
            tools: Some(vec![Tool {
                vendor: Some("Astral".to_string()),
                name: "uv".to_string(),
                version: Some(env!("CARGO_PKG_VERSION").to_string()),
            }]),
            component: Some(main_component.clone()),
        };

        let bom = CycloneDx {
            bom_format: "CycloneDX".to_string(),
            spec_version: "1.5".to_string(),
            serial_number,
            version: 1,
            metadata,
            components: if all_components.is_empty() {
                None
            } else {
                Some(all_components)
            },
            dependencies: if dependencies.is_empty() {
                None
            } else {
                Some(dependencies)
            },
        };

        Ok(bom)
    }

    fn create_main_component<'a>(
        target: &impl Installable<'a>,
        bom_ref: &str,
    ) -> Result<Component, LockError> {
        // Try to get project name, fallback to workspace directory name
        let name = target
            .project_name()
            .map(|n| n.to_string())
            .unwrap_or_else(|| {
                target
                    .install_path()
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("workspace")
                    .to_string()
            });

        // Check if this is a workspace with multiple members
        let component_type = if target.lock().members().len() > 1 || target.project_name().is_none()
        {
            "application".to_string() // Multi-member workspace
        } else {
            "application".to_string() // Single project
        };

        let component = Component {
            bom_ref: bom_ref.to_string(),
            r#type: component_type,
            name,
            version: None, // Workspaces don't have versions
            description: Some("uv workspace or project".to_string()),
            hashes: None,
            purl: None,
            properties: None,
        };

        Ok(component)
    }

    fn create_workspace_components<'a>(
        target: &impl Installable<'a>,
    ) -> Result<Vec<Component>, LockError> {
        let lock = target.lock();
        let mut components = Vec::new();

        // Add workspace members as components
        for member_name in lock.members() {
            if let Some(package) = lock.find_by_name(member_name).ok().flatten() {
                let component = Self::create_workspace_member_component(package)?;
                components.push(component);
            }
        }

        // Add root package if it's not in members (single project, not a workspace)
        if lock.members().is_empty() {
            if let Some(root_package) = lock.root() {
                // For single projects, create a special component that's marked as the main project
                let component = Self::create_single_project_component(root_package)?;
                components.push(component);
            }
        }

        Ok(components)
    }

    fn create_workspace_member_component(package: &Package) -> Result<Component, LockError> {
        let bom_ref = format!(
            "pkg:pypi/{}@{}",
            package.id.name,
            package
                .id
                .version
                .as_ref()
                .map(|v| v.to_string())
                .unwrap_or_else(|| "unknown".to_string())
        );

        // Extract relative path for workspace members
        let mut properties = vec![
            Property {
                name: "uv:workspace_member".to_string(),
                value: "true".to_string(),
            },
            Property {
                name: "uv:source_type".to_string(),
                value: "workspace".to_string(),
            },
        ];

        // Add relative path if available from the source
        if let Some(relative_path) = Self::extract_workspace_relative_path(package) {
            properties.push(Property {
                name: "uv:workspace_path".to_string(),
                value: relative_path,
            });
        }

        let component = Component {
            bom_ref,
            r#type: "library".to_string(), // Workspace members are typically libraries
            name: package.id.name.to_string(),
            version: package.id.version.as_ref().map(|v| v.to_string()),
            description: Some(format!("Workspace member: {}", package.id.name)),
            hashes: None, // Workspace members typically don't have hashes
            purl: Some(Self::create_purl_from_package(package)?),
            properties: Some(properties),
        };

        Ok(component)
    }

    fn create_single_project_component(package: &Package) -> Result<Component, LockError> {
        let bom_ref = format!(
            "pkg:pypi/{}@{}",
            package.id.name,
            package
                .id
                .version
                .as_ref()
                .map(|v| v.to_string())
                .unwrap_or_else(|| "unknown".to_string())
        );

        let component = Component {
            bom_ref,
            r#type: "library".to_string(),
            name: package.id.name.to_string(),
            version: package.id.version.as_ref().map(|v| v.to_string()),
            description: Some(format!("Single project: {}", package.id.name)),
            hashes: None, // Single projects typically don't have hashes
            purl: Some(Self::create_purl_from_package(package)?),
            properties: Some(vec![
                Property {
                    name: "uv:workspace_member".to_string(),
                    value: "false".to_string(), // Single projects are not workspace members
                },
                Property {
                    name: "uv:source_type".to_string(),
                    value: "project".to_string(), // Special type for single projects
                },
                Property {
                    name: "uv:project_type".to_string(),
                    value: "single".to_string(),
                },
            ]),
        };

        Ok(component)
    }

    fn extract_workspace_relative_path(package: &Package) -> Option<String> {
        // Extract the relative path from workspace member sources
        match &package.id.source {
            Source::Path(path) => Some(format!("./{}", path.display())),
            Source::Directory(path) => Some(format!("./{}", path.display())),
            Source::Editable(path) => Some(format!("./{}", path.display())),
            _ => None,
        }
    }

    fn create_component_from_package(
        package: &Package,
        include_hashes: bool,
    ) -> Result<Component, LockError> {
        let version_str = package
            .id
            .version
            .as_ref()
            .map(|v| v.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        let bom_ref = format!("pkg:pypi/{}@{}", package.id.name, version_str);

        let hashes = if include_hashes {
            let package_hashes = package.hashes();
            if package_hashes.is_empty() {
                None
            } else {
                Some(
                    package_hashes
                        .iter()
                        .map(|hash| Hash {
                            alg: hash.algorithm().to_string(),
                            content: hash.to_string(),
                        })
                        .collect(),
                )
            }
        } else {
            None
        };

        // Determine source type from package source
        let source_type = match &package.id.source {
            Source::Registry(_) => "registry",
            Source::Git(..) => "git",
            Source::Direct(..) => "direct",
            Source::Path(_) => "path",
            Source::Directory(_) => "directory",
            Source::Editable(_) => "editable",
            Source::Virtual(_) => "virtual",
        };

        let component = Component {
            bom_ref,
            r#type: "library".to_string(),
            name: package.id.name.to_string(),
            version: package.id.version.as_ref().map(|v| v.to_string()),
            description: None,
            hashes,
            purl: Some(Self::create_purl_from_package(package)?),
            properties: Some(vec![
                Property {
                    name: "uv:workspace_member".to_string(),
                    value: "false".to_string(),
                },
                Property {
                    name: "uv:source_type".to_string(),
                    value: source_type.to_string(),
                },
            ]),
        };

        Ok(component)
    }

    fn create_purl_from_package(package: &Package) -> Result<String, LockError> {
        let version = package
            .id
            .version
            .as_ref()
            .map(|v| v.to_string())
            .unwrap_or_else(|| "unknown".to_string());

        match &package.id.source {
            Source::Registry(_) => Ok(format!("pkg:pypi/{}@{}", package.id.name, version)),
            Source::Git(url, _git_source) => {
                let url_str = url.to_url().map_err(LockError::from)?;
                Ok(format!(
                    "pkg:pypi/{}@{}?vcs_url={}",
                    package.id.name,
                    version,
                    percent_encoding::utf8_percent_encode(
                        &url_str.to_string(),
                        percent_encoding::NON_ALPHANUMERIC
                    )
                ))
            }
            Source::Direct(url, _) => {
                let url_str = url.to_url().map_err(LockError::from)?;
                Ok(format!(
                    "pkg:pypi/{}@{}?download_url={}",
                    package.id.name,
                    version,
                    percent_encoding::utf8_percent_encode(
                        &url_str.to_string(),
                        percent_encoding::NON_ALPHANUMERIC
                    )
                ))
            }
            Source::Path(_) | Source::Directory(_) | Source::Editable(_) => {
                Ok(format!("pkg:pypi/{}@{}", package.id.name, version))
            }
            Source::Virtual(_) => Ok(format!("pkg:pypi/{}@{}", package.id.name, version)),
        }
    }

    fn create_dependency_relationships<'a>(
        target: &impl Installable<'a>,
        nodes: &[ExportableRequirement<'a>],
        main_bom_ref: &str,
    ) -> Result<Vec<Dependency>, LockError> {
        let mut dependencies = Vec::new();
        let lock = target.lock();

        // Create dependency from main component to workspace members
        let mut main_deps = Vec::new();
        for member_name in lock.members() {
            if let Some(package) = lock.find_by_name(member_name).ok().flatten() {
                let version_str = package
                    .id
                    .version
                    .as_ref()
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                main_deps.push(format!("pkg:pypi/{}@{}", package.id.name, version_str));
            }
        }

        // Add root package dependencies if it exists
        if lock.members().is_empty() {
            if let Some(root_package) = lock.root() {
                let version_str = root_package
                    .id
                    .version
                    .as_ref()
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                main_deps.push(format!("pkg:pypi/{}@{}", root_package.id.name, version_str));
            }
        }

        // Add external dependencies to main component
        for node in nodes {
            let version_str = node
                .package
                .id
                .version
                .as_ref()
                .map(|v| v.to_string())
                .unwrap_or_else(|| "unknown".to_string());
            let dep_ref = format!("pkg:pypi/{}@{}", node.package.id.name, version_str);

            // Only add if it's not a workspace member
            if !lock.members().contains(&node.package.id.name) {
                main_deps.push(dep_ref);
            }
        }

        if !main_deps.is_empty() {
            dependencies.push(Dependency {
                r#ref: main_bom_ref.to_string(),
                depends_on: main_deps,
            });
        }

        // Create dependencies between packages (including workspace members)
        for node in nodes {
            let version_str = node
                .package
                .id
                .version
                .as_ref()
                .map(|v| v.to_string())
                .unwrap_or_else(|| "unknown".to_string());
            let package_ref = format!("pkg:pypi/{}@{}", node.package.id.name, version_str);

            let mut package_deps = Vec::new();
            for dep in &node.package.dependencies {
                // Find the package by matching package_id
                if let Some(dep_package) = nodes
                    .iter()
                    .map(|n| n.package)
                    .find(|p| p.id == dep.package_id)
                {
                    let dep_version_str = dep_package
                        .id
                        .version
                        .as_ref()
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "unknown".to_string());
                    package_deps.push(format!(
                        "pkg:pypi/{}@{}",
                        dep_package.id.name, dep_version_str
                    ));
                }
            }

            if !package_deps.is_empty() {
                dependencies.push(Dependency {
                    r#ref: package_ref,
                    depends_on: package_deps,
                });
            }
        }

        Ok(dependencies)
    }
}

impl std::fmt::Display for SbomExport {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match serde_json::to_string_pretty(&self.bom) {
            Ok(json) => write!(f, "{}", json),
            Err(_) => Err(std::fmt::Error),
        }
    }
}

// CycloneDX 1.5 Data Structures

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CycloneDx {
    bom_format: String,
    spec_version: String,
    serial_number: String,
    version: u32,
    metadata: Metadata,
    #[serde(skip_serializing_if = "Option::is_none")]
    components: Option<Vec<Component>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dependencies: Option<Vec<Dependency>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Metadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    timestamp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tools: Option<Vec<Tool>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    component: Option<Component>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Tool {
    #[serde(skip_serializing_if = "Option::is_none")]
    vendor: Option<String>,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct Component {
    bom_ref: String,
    r#type: String,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hashes: Option<Vec<Hash>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    purl: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    properties: Option<Vec<Property>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Hash {
    alg: String,
    content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Property {
    name: String,
    value: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Dependency {
    r#ref: String,
    #[serde(rename = "dependsOn")]
    depends_on: Vec<String>,
}
