import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";

import { Purl } from "@cdxgen/cdx-purl";

import { isPartialTree } from "./depsUtils.js";

const PROP_DEPENDENCY_TYPE = "cdx:sbom:dependencyType";
const PROP_TRIM_INVENTORY = "cdx:sbom:trim:excludedComponents";
const PROP_STATS = "cdx:sbom:stats";
const PROP_LICENSE_MISSING = "cdx:sbom:license:missing";
const PROP_HASH_MISSING = "cdx:sbom:hash:missing";
const PROP_ECOSYSTEMS_COVERED = "cdx:sbom:ecosystems:covered";
const PROP_ECOSYSTEMS_UNCOVERED = "cdx:sbom:ecosystems:uncovered";
const PROP_INCREMENTAL = "cdx:sbom:incremental";
const PROP_INCREMENTAL_REMOVED = "cdx:sbom:incremental:removedRefs";
const PROP_COMPLETE = "cdx:sbom:complete";
const PROP_INCOMPLETE_REASON = "cdx:sbom:incompleteReason";
const PROP_ORIGINAL_PURL = "cdx:sbom:originalPurl";
const PROP_CHECKSUM_ALGORITHM = "cdx:sbom:checksumAlgorithm";
const PROP_CHECKSUM = "cdx:sbom:checksum";

const NON_RUNTIME_PROPERTIES = new Set([
  "cdx:npm:package:development",
  "cdx:npm:package:optional",
  "cdx:npm:package:peer",
  "cdx:npm:package:type-only",
  "cdx:cargo:hostOnly",
]);

const DEVELOPMENT_SCOPE_VALUES = new Set([
  "build",
  "dev",
  "development",
  "test",
  "testing",
]);

const PROJECT_TYPE_ECOSYSTEMS = {
  alpm: ["alpm"],
  apk: ["apk"],
  bun: ["npm"],
  bundler: ["gem"],
  cargo: ["cargo"],
  cmake: ["conan", "generic"],
  composer: ["composer"],
  conan: ["conan"],
  container: ["oci"],
  cpp: ["conan", "generic"],
  csharp: ["nuget"],
  dart: ["pub"],
  deb: ["deb"],
  docker: ["oci"],
  dotnet: ["nuget"],
  elixir: ["hex"],
  erlang: ["hex"],
  gem: ["gem"],
  go: ["golang"],
  golang: ["golang"],
  gradle: ["maven"],
  haskell: ["hackage"],
  homebrew: ["homebrew"],
  java: ["maven"],
  js: ["npm"],
  julia: ["julia"],
  kotlin: ["maven"],
  lua: ["luarocks"],
  macports: ["macports"],
  maven: ["maven"],
  nim: ["nim"],
  node: ["npm"],
  npm: ["npm"],
  nuget: ["nuget"],
  oci: ["oci"],
  opam: ["opam"],
  os: ["alpm", "apk", "deb", "flatpak", "homebrew", "macports", "rpm", "snap"],
  perl: ["cpan"],
  php: ["composer"],
  pip: ["pypi"],
  pipenv: ["pypi"],
  pnpm: ["npm"],
  poetry: ["pypi"],
  podman: ["oci"],
  pub: ["pub"],
  python: ["pypi", "conda"],
  rpm: ["rpm"],
  ruby: ["gem"],
  rust: ["cargo"],
  sbt: ["maven"],
  scala: ["maven"],
  snap: ["snap"],
  swift: ["swift"],
  uv: ["pypi"],
  vcpkg: ["conan", "generic"],
  yarn: ["npm"],
  zig: ["generic"],
};

const SCOPE_STRENGTH = {
  excluded: 1,
  optional: 2,
  required: 3,
};

function normalizeRef(ref) {
  return `${ref || ""}`.trim().toLowerCase();
}

function compareStrings(left, right) {
  const leftString = `${left || ""}`;
  const rightString = `${right || ""}`;
  return leftString < rightString ? -1 : leftString > rightString ? 1 : 0;
}

function isPlainObject(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function isChecksumProperty(property) {
  return property?.name === PROP_CHECKSUM;
}

function isChecksumMetadata(property) {
  return (
    property?.name === PROP_CHECKSUM ||
    property?.name === PROP_CHECKSUM_ALGORITHM
  );
}

function stableValue(value, root = false) {
  if (Array.isArray(value)) {
    return value.map((entry) => stableValue(entry));
  }
  if (!isPlainObject(value)) {
    return value;
  }
  const result = {};
  for (const childKey of Object.keys(value).sort()) {
    if (root && childKey === "signature") {
      continue;
    }
    if (root && childKey === "properties" && Array.isArray(value[childKey])) {
      result[childKey] = value[childKey]
        .filter((property) => !isChecksumProperty(property))
        .map((property) => stableValue(property));
      continue;
    }
    if (value[childKey] === undefined) {
      continue;
    }
    result[childKey] = stableValue(value[childKey]);
  }
  return result;
}

function stableStringify(value, root = false) {
  return JSON.stringify(stableValue(value, root));
}

function propertyValue(component, name) {
  return component?.properties?.find((property) => property.name === name)
    ?.value;
}

function setComponentProperty(component, name, value) {
  if (!component || value === undefined) {
    return component;
  }
  component.properties = (component.properties || []).filter(
    (property) => property.name !== name,
  );
  component.properties.push({ name, value: `${value}` });
  return component;
}

function ensureMetadataProperties(bomJson) {
  bomJson.metadata = bomJson.metadata || {};
  bomJson.metadata.properties = bomJson.metadata.properties || [];
  return bomJson.metadata.properties;
}

function setMetadataProperty(bomJson, name, value) {
  const properties = ensureMetadataProperties(bomJson);
  const retained = properties.filter((property) => property.name !== name);
  retained.push({ name, value: `${value}` });
  bomJson.metadata.properties = retained;
}

function setMetadataListProperty(bomJson, name, values) {
  if (!values?.length) {
    return;
  }
  setMetadataProperty(bomJson, name, values.join("\n"));
}

function componentPurlType(component) {
  if (!component?.purl) {
    return undefined;
  }
  try {
    return Purl.parse(component.purl)?.type;
  } catch {
    const value = `${component.purl}`;
    if (!value.startsWith("pkg:")) {
      return undefined;
    }
    return value.slice(4).split("/")[0]?.split("@")[0] || undefined;
  }
}

function componentHashes(component) {
  return (component?.hashes || [])
    .filter((hash) => hash?.alg && hash?.content)
    .map((hash) => `${hash.alg}:${hash.content}`.toLowerCase())
    .sort();
}

function hashMap(component) {
  const result = new Map();
  for (const hash of component?.hashes || []) {
    if (!hash?.alg || !hash?.content) {
      continue;
    }
    const alg = `${hash.alg}`.toLowerCase();
    if (!result.has(alg)) {
      result.set(alg, new Set());
    }
    result.get(alg).add(`${hash.content}`.toLowerCase());
  }
  return result;
}

function hasHashConflict(left, right) {
  const leftHashes = hashMap(left);
  const rightHashes = hashMap(right);
  for (const [alg, values] of leftHashes) {
    if (!rightHashes.has(alg)) {
      continue;
    }
    if ([...values].some((value) => !rightHashes.get(alg).has(value))) {
      return true;
    }
  }
  return false;
}

function componentBaseKey(component) {
  if (component?.purl) {
    return `purl:${`${component.purl}`.trim().toLowerCase()}`;
  }
  const coordinates = [
    component?.type || "",
    component?.group || "",
    component?.name || "",
    component?.version || "",
  ]
    .join("\0")
    .toLowerCase();
  if (coordinates.replaceAll("\0", "")) {
    return `coord:${coordinates}`;
  }
  if (component?.["bom-ref"]) {
    return `ref:${normalizeRef(component["bom-ref"])}`;
  }
  return `json:${stableStringify(component)}`;
}

function componentStableKey(component) {
  return [
    componentBaseKey(component),
    componentHashes(component).join(","),
    normalizeRef(component?.["bom-ref"]),
    stableStringify(component),
  ].join("\0");
}

function componentMatchKey(component) {
  if (component?.purl) {
    return `${component.purl}`.toLowerCase();
  }
  const coordinates = [
    component?.type || "",
    component?.group || "",
    component?.name || "",
    component?.version || "",
  ]
    .join("/")
    .toLowerCase();
  const hashes = componentHashes(component);
  return `${coordinates}${hashes.length ? `#${hashes.join(",")}` : ""}`;
}

function arrayItemKey(item) {
  return typeof item === "string" ? item : stableStringify(item);
}

function unionArray(target, source) {
  const result = Array.isArray(target) ? [...target] : [];
  const seen = new Set(result.map(arrayItemKey));
  for (const item of source || []) {
    const key = arrayItemKey(item);
    if (!seen.has(key)) {
      seen.add(key);
      result.push(item);
    }
  }
  return result;
}

function mergeEvidence(target, source) {
  target.evidence = target.evidence || {};
  for (const [key, value] of Object.entries(source.evidence || {})) {
    if (Array.isArray(value)) {
      target.evidence[key] = unionArray(target.evidence[key], value);
    } else if (isPlainObject(value)) {
      target.evidence[key] = {
        ...value,
        ...(target.evidence[key] || {}),
      };
      if (Array.isArray(target.evidence[key].frames)) {
        target.evidence[key].frames = unionArray(
          target.evidence[key].frames,
          value.frames,
        );
      }
    } else if (target.evidence[key] === undefined) {
      target.evidence[key] = value;
    }
  }
}

function strongerScope(left, right) {
  const leftStrength = SCOPE_STRENGTH[left] || SCOPE_STRENGTH.required;
  const rightStrength = SCOPE_STRENGTH[right] || SCOPE_STRENGTH.required;
  if (rightStrength > leftStrength) {
    return right;
  }
  if (leftStrength >= SCOPE_STRENGTH.required && !left) {
    return right ? "required" : left;
  }
  return left;
}

function mergeComponent(target, source) {
  for (const [key, value] of Object.entries(source)) {
    if (key === "bom-ref" || value === undefined) {
      continue;
    }
    if (key === "scope") {
      target.scope = strongerScope(target.scope, value);
      continue;
    }
    if (key === "evidence" && isPlainObject(value)) {
      mergeEvidence(target, source);
      continue;
    }
    if (Array.isArray(value)) {
      target[key] = unionArray(target[key], value);
      continue;
    }
    if (isPlainObject(value)) {
      if (target[key] === undefined) {
        target[key] = value;
      } else if (isPlainObject(target[key])) {
        target[key] = { ...value, ...target[key] };
      }
      continue;
    }
    if (target[key] === undefined) {
      target[key] = value;
    }
  }
}

/**
 * Merge components that describe the same package/artifact. Components with
 * the same identity but conflicting non-empty hashes stay separate, because
 * they may be two builds of the same version.
 *
 * @param {object[]} components CycloneDX components
 * @returns {{components: object[], refMap: Map<string,string>, merged: number}}
 */
export function mergeDuplicateComponents(components = []) {
  const groupsByBase = new Map();
  for (const component of components) {
    const base = componentBaseKey(component);
    if (!groupsByBase.has(base)) {
      groupsByBase.set(base, []);
    }
    const groups = groupsByBase.get(base);
    let group = groups.find((candidate) =>
      candidate.every((entry) => !hasHashConflict(entry, component)),
    );
    if (!group) {
      group = [];
      groups.push(group);
    }
    group.push(component);
  }

  const mergedComponents = [];
  const refMap = new Map();
  let merged = 0;
  for (const groups of groupsByBase.values()) {
    for (const group of groups) {
      const target = group[0];
      for (let index = 1; index < group.length; index++) {
        mergeComponent(target, group[index]);
        merged++;
      }
      const refs = group
        .map((component) => component?.["bom-ref"])
        .filter(Boolean);
      const purlRef = target.purl
        ? refs.find((ref) => normalizeRef(ref) === normalizeRef(target.purl))
        : undefined;
      const canonicalRef =
        purlRef ||
        refs.sort((left, right) =>
          compareStrings(normalizeRef(left), normalizeRef(right)),
        )[0] ||
        target["bom-ref"];
      if (canonicalRef) {
        target["bom-ref"] = canonicalRef;
      }
      for (const ref of refs) {
        refMap.set(normalizeRef(ref), canonicalRef);
      }
      mergedComponents.push(target);
    }
  }
  return { components: mergedComponents, refMap, merged };
}

function remapRef(ref, refMap) {
  return refMap.get(normalizeRef(ref)) || ref;
}

/**
 * Rewrite and merge dependency edges after component refs were collapsed.
 *
 * @param {object[]} dependencies CycloneDX dependencies
 * @param {Map<string,string>} refMap Old ref to canonical ref
 * @returns {object[]} Rewritten dependencies sorted by ref
 */
export function rewriteDependencyRefs(dependencies = [], refMap = new Map()) {
  const byRef = new Map();
  for (const dependency of dependencies) {
    const ref = remapRef(dependency?.ref, refMap);
    if (!ref) {
      continue;
    }
    if (!byRef.has(ref)) {
      byRef.set(ref, { dependsOn: new Set(), provides: new Set() });
    }
    const entry = byRef.get(ref);
    for (const child of dependency.dependsOn || []) {
      const childRef = remapRef(child, refMap);
      if (childRef && normalizeRef(childRef) !== normalizeRef(ref)) {
        entry.dependsOn.add(childRef);
      }
    }
    for (const provided of dependency.provides || []) {
      const providedRef = remapRef(provided, refMap);
      if (providedRef) {
        entry.provides.add(providedRef);
      }
    }
  }
  return [...byRef.entries()]
    .sort(([left], [right]) => compareStrings(left, right))
    .map(([ref, entry]) => {
      const result = { ref, dependsOn: [...entry.dependsOn].sort() };
      if (entry.provides.size) {
        result.provides = [...entry.provides].sort();
      }
      return result;
    });
}

function scopeClass(component) {
  if (component?.scope === "excluded") {
    return "development";
  }
  for (const property of component?.properties || []) {
    if (
      NON_RUNTIME_PROPERTIES.has(property.name) &&
      property.value === "true"
    ) {
      return property.name === "cdx:cargo:hostOnly"
        ? "development"
        : "optional";
    }
    if (
      `${property.name}`.endsWith(":scope") &&
      DEVELOPMENT_SCOPE_VALUES.has(`${property.value}`.toLowerCase())
    ) {
      return "development";
    }
  }
  if (component?.scope === "optional") {
    return "optional";
  }
  return "runtime";
}

function componentMatchesScope(component, scope) {
  const componentClass = scopeClass(component);
  if (scope === "runtime") {
    return componentClass === "runtime";
  }
  if (scope === "development") {
    return componentClass === "development";
  }
  return true;
}

function dependencyRootRefs(bomJson) {
  const rootRef = bomJson.metadata?.component?.["bom-ref"];
  if (rootRef && bomJson.dependencies?.some((dep) => dep.ref === rootRef)) {
    return [rootRef];
  }
  const childRefs = new Set(
    (bomJson.dependencies || []).flatMap((dep) => dep.dependsOn || []),
  );
  return (bomJson.dependencies || [])
    .map((dep) => dep.ref)
    .filter((ref) => ref && !childRefs.has(ref));
}

function annotateDependencyTypes(bomJson) {
  const roots = dependencyRootRefs(bomJson);
  const rootSet = new Set(roots.map(normalizeRef));
  const dependencyMap = new Map(
    (bomJson.dependencies || []).map((dependency) => [
      normalizeRef(dependency.ref),
      dependency,
    ]),
  );
  const directRefs = new Set();
  for (const root of roots) {
    for (const child of dependencyMap.get(normalizeRef(root))?.dependsOn ||
      []) {
      directRefs.add(normalizeRef(child));
    }
  }
  const hasGraph = directRefs.size > 0;
  for (const component of bomJson.components || []) {
    const candidates = [component["bom-ref"], component.purl]
      .filter(Boolean)
      .map(normalizeRef);
    if (candidates.some((ref) => rootSet.has(ref))) {
      continue;
    }
    let dependencyType = "unknown";
    if (hasGraph && candidates.length) {
      dependencyType = candidates.some((ref) => directRefs.has(ref))
        ? "direct"
        : "transitive";
    }
    setComponentProperty(component, PROP_DEPENDENCY_TYPE, dependencyType);
  }
}

function incomingRefsByChild(bomJson, refMap) {
  const incoming = new Map();
  for (const dependency of bomJson.dependencies || []) {
    const parent = remapRef(dependency.ref, refMap);
    for (const child of dependency.dependsOn || []) {
      const childRef = remapRef(child, refMap);
      if (!childRef) {
        continue;
      }
      if (!incoming.has(childRef)) {
        incoming.set(childRef, new Set());
      }
      if (parent && normalizeRef(parent) !== normalizeRef(childRef)) {
        incoming.get(childRef).add(parent);
      }
    }
  }
  return incoming;
}

function trimComponentView(bomJson, scope) {
  const before = bomJson.components || [];
  const retained = [];
  const excluded = [];
  for (const component of before) {
    if (componentMatchesScope(component, scope)) {
      retained.push(component);
    } else {
      excluded.push(component);
    }
  }
  bomJson.components = retained;

  const retainedRefs = new Set(
    retained.map((component) => component["bom-ref"]).filter(Boolean),
  );
  const rootRef = bomJson.metadata?.component?.["bom-ref"];
  if (rootRef) {
    retainedRefs.add(rootRef);
  }
  for (const service of bomJson.services || []) {
    if (service?.["bom-ref"]) {
      retainedRefs.add(service["bom-ref"]);
    }
  }
  bomJson.dependencies = (bomJson.dependencies || [])
    .filter((dependency) => retainedRefs.has(dependency.ref))
    .map((dependency) => ({
      ...dependency,
      dependsOn: (dependency.dependsOn || []).filter((ref) =>
        retainedRefs.has(ref),
      ),
      ...(dependency.provides
        ? {
            provides: dependency.provides.filter((ref) =>
              retainedRefs.has(ref),
            ),
          }
        : {}),
    }));
  return excluded;
}

function excludedInventory(excluded, incoming) {
  return excluded
    .map((component) => {
      const ref = component["bom-ref"] || componentBaseKey(component);
      return {
        ref,
        purl: component.purl,
        name: component.name,
        version: component.version,
        type: component.type,
        scope: component.scope,
        dependencyType: propertyValue(component, PROP_DEPENDENCY_TYPE),
        incomingRefs: [...(incoming.get(ref) || [])].sort(),
        hashes: component.hashes,
        licenses: component.licenses,
        locations: (component.evidence?.occurrences || [])
          .map((occurrence) => occurrence.location)
          .filter(Boolean)
          .sort(),
      };
    })
    .sort((left, right) => compareStrings(left.ref, right.ref));
}

function ensureIncompleteComposition(bomJson) {
  if (!bomJson.metadata?.component) {
    return;
  }
  const rootRef = bomJson.metadata.component["bom-ref"];
  bomJson.compositions = bomJson.compositions || [];
  const existing = bomJson.compositions.some(
    (composition) =>
      `${composition?.aggregate || ""}`.startsWith("incomplete") &&
      (!rootRef ||
        !composition["bom-ref"] ||
        composition["bom-ref"] === rootRef),
  );
  if (existing) {
    return;
  }
  bomJson.compositions.push({
    ...(rootRef ? { "bom-ref": rootRef } : {}),
    aggregate: "incomplete",
  });
}

function matchKeySet(components) {
  return new Set((components || []).map(componentMatchKey).filter(Boolean));
}

function digestKeys(keys) {
  const hash = createHash("sha256");
  for (const key of [...keys].sort()) {
    hash.update(key);
    hash.update("\0");
  }
  return hash.digest("hex");
}

function identityByRef(bomJson) {
  const result = new Map();
  const rootRef = bomJson.metadata?.component?.["bom-ref"];
  if (rootRef) {
    result.set(
      normalizeRef(rootRef),
      componentMatchKey(bomJson.metadata.component),
    );
  }
  for (const component of bomJson.components || []) {
    const key = componentMatchKey(component);
    for (const ref of [component["bom-ref"], component.purl]) {
      if (ref) {
        result.set(normalizeRef(ref), key);
      }
    }
  }
  return result;
}

function dependencyEdgeSet(bomJson, allowedKeys) {
  const identity = identityByRef(bomJson);
  const edges = new Set();
  for (const dependency of bomJson.dependencies || []) {
    const parent = identity.get(normalizeRef(dependency.ref)) || dependency.ref;
    if (allowedKeys && !allowedKeys.has(parent)) {
      continue;
    }
    for (const childRef of dependency.dependsOn || []) {
      const child = identity.get(normalizeRef(childRef)) || childRef;
      if (allowedKeys && !allowedKeys.has(child)) {
        continue;
      }
      if (normalizeRef(parent) !== normalizeRef(child)) {
        edges.add(`${parent}\0${child}`);
      }
    }
  }
  return edges;
}

function missingValues(components, valueName) {
  return components
    .filter((component) => {
      if (valueName === "licenses") {
        return !component.licenses?.length && !component.license;
      }
      return !component.hashes?.length;
    })
    .map(
      (component) =>
        component["bom-ref"] || component.purl || component.name || "unknown",
    )
    .sort();
}

function expectedEcosystems(projectTypes) {
  const expected = new Set();
  const values = Array.isArray(projectTypes) ? projectTypes : [projectTypes];
  for (const value of values) {
    for (const projectType of `${value || ""}`.split(",")) {
      const normalized = projectType.trim().toLowerCase();
      if (!normalized) {
        continue;
      }
      for (const ecosystem of PROJECT_TYPE_ECOSYSTEMS[normalized] || [
        normalized,
      ]) {
        expected.add(ecosystem);
      }
    }
  }
  return expected;
}

function applyEcosystemReport(bomJson, options) {
  const counts = new Map();
  for (const component of bomJson.components || []) {
    const type = componentPurlType(component);
    if (type) {
      counts.set(type, (counts.get(type) || 0) + 1);
    }
  }
  const covered = [...counts.entries()]
    .sort(([left], [right]) => compareStrings(left, right))
    .map(([type, count]) => `${type}:${count}`);
  setMetadataListProperty(bomJson, PROP_ECOSYSTEMS_COVERED, covered);
  const expected = expectedEcosystems(options.projectType);
  const uncovered = [...expected].filter((type) => !counts.has(type)).sort();
  setMetadataListProperty(bomJson, PROP_ECOSYSTEMS_UNCOVERED, uncovered);
  return { covered: [...counts.keys()].sort(), uncovered };
}

function applyLicenseAndHashReports(bomJson) {
  const components = bomJson.components || [];
  const missingLicenses = missingValues(components, "licenses");
  const missingHashes = missingValues(components, "hashes");
  setMetadataListProperty(bomJson, PROP_LICENSE_MISSING, missingLicenses);
  setMetadataListProperty(bomJson, PROP_HASH_MISSING, missingHashes);
  return {
    missingLicenses,
    missingHashes,
    licensed: components.length - missingLicenses.length,
    hashed: components.length - missingHashes.length,
  };
}

function mappingForComponent(component, mapping) {
  if (!mapping) {
    return undefined;
  }
  const mappings = mapping.mappings || mapping;
  for (const key of [component["bom-ref"], component.purl]) {
    if (!key || !Object.hasOwn(mappings, key)) {
      continue;
    }
    const entry = mappings[key];
    if (typeof entry === "string") {
      return { purl: entry };
    }
    if (isPlainObject(entry)) {
      return entry;
    }
  }
  return undefined;
}

function sortComponentCollections(component) {
  if (!component || typeof component !== "object") {
    return;
  }
  const sortBy = (array, keyOf) => {
    if (Array.isArray(array)) {
      array.sort((left, right) => compareStrings(keyOf(left), keyOf(right)));
    }
  };
  sortBy(
    component.properties,
    (property) => `${property?.name || ""}\0${property?.value || ""}`,
  );
  sortBy(
    component.hashes,
    (hash) => `${hash?.alg || ""}\0${hash?.content || ""}`,
  );
  sortBy(
    component.licenses,
    (license) =>
      `${license?.license?.id || license?.license?.name || license?.expression || ""}`,
  );
  sortBy(
    component.externalReferences,
    (reference) => `${reference?.type || ""}\0${reference?.url || ""}`,
  );
  sortBy(
    component.evidence?.occurrences,
    (occurrence) =>
      `${occurrence?.location || ""}\0${occurrence?.line || 0}\0${occurrence?.offset || 0}`,
  );
  sortBy(
    component.evidence?.identity,
    (identity) => `${identity?.field || ""}\0${stableStringify(identity)}`,
  );
  for (const child of component.components || []) {
    sortComponentCollections(child);
  }
}

function validPurl(value) {
  try {
    Purl.parse(value);
    return true;
  } catch {
    return false;
  }
}

function validCpe(value) {
  return typeof value === "string" && value.startsWith("cpe:2.3:");
}

function applyIdentityMapping(bomJson, mapping) {
  if (!mapping) {
    return { mapped: 0, invalid: 0, refMap: new Map() };
  }
  const refMap = new Map();
  let mapped = 0;
  let invalid = 0;
  const visit = (component) => {
    const entry = mappingForComponent(component, mapping);
    if (!entry) {
      return;
    }
    if (entry.purl !== undefined && !validPurl(entry.purl)) {
      invalid++;
      return;
    }
    if (entry.cpe !== undefined && !validCpe(entry.cpe)) {
      invalid++;
      return;
    }
    let changed = false;
    if (entry.purl !== undefined) {
      if (entry.purl !== component.purl) {
        const originalRef = component["bom-ref"];
        const originalPurl = component.purl;
        component.purl = entry.purl;
        setComponentProperty(component, PROP_ORIGINAL_PURL, originalPurl);
        if (
          originalRef &&
          normalizeRef(originalRef) === normalizeRef(originalPurl)
        ) {
          component["bom-ref"] = entry.purl;
          refMap.set(normalizeRef(originalRef), entry.purl);
        }
        changed = true;
      }
    }
    if (entry.cpe !== undefined) {
      if (entry.cpe !== component.cpe) {
        component.cpe = entry.cpe;
        changed = true;
      }
    }
    if (changed) {
      mapped++;
    }
  };
  for (const component of bomJson.components || []) {
    visit(component);
  }
  if (bomJson.metadata?.component) {
    visit(bomJson.metadata.component);
  }
  bomJson.dependencies = rewriteDependencyRefs(
    bomJson.dependencies || [],
    refMap,
  );
  return { mapped, invalid, refMap };
}

function sortBomStable(bomJson) {
  if (Array.isArray(bomJson.components)) {
    for (const component of bomJson.components) {
      sortComponentCollections(component);
    }
    bomJson.components.sort((left, right) =>
      compareStrings(componentStableKey(left), componentStableKey(right)),
    );
  }
  if (Array.isArray(bomJson.dependencies)) {
    for (const dependency of bomJson.dependencies) {
      for (const key of ["dependsOn", "provides"]) {
        if (Array.isArray(dependency[key])) {
          dependency[key].sort();
        }
      }
    }
    bomJson.dependencies.sort((left, right) =>
      compareStrings(left.ref, right.ref),
    );
  }
  if (Array.isArray(bomJson.services)) {
    bomJson.services.sort((left, right) =>
      compareStrings(
        left["bom-ref"] || left.name,
        right["bom-ref"] || right.name,
      ),
    );
  }
  if (Array.isArray(bomJson.annotations)) {
    bomJson.annotations.sort((left, right) =>
      compareStrings(
        left["bom-ref"] || (left.subjects || []).join(","),
        right["bom-ref"] || (right.subjects || []).join(","),
      ),
    );
  }
  if (Array.isArray(bomJson.metadata?.properties)) {
    bomJson.metadata.properties.sort((left, right) =>
      compareStrings(
        `${left.name}\0${left.value}`,
        `${right.name}\0${right.value}`,
      ),
    );
  }
  if (bomJson.metadata?.component) {
    sortComponentCollections(bomJson.metadata.component);
  }
  return bomJson;
}

function componentDigest(component) {
  const digestView = {
    ...component,
    properties: (component.properties || []).filter(
      (property) => !`${property?.name || ""}`.startsWith("cdx:sbom:"),
    ),
  };
  return createHash("sha256").update(stableStringify(digestView)).digest("hex");
}

function ambiguousPurls(components) {
  const counts = new Map();
  for (const component of components || []) {
    if (component?.purl) {
      counts.set(component.purl, (counts.get(component.purl) || 0) + 1);
    }
  }
  return new Set(
    [...counts.entries()]
      .filter(([, count]) => count > 1)
      .map(([purl]) => purl),
  );
}

function componentDiffKey(component, ambiguous = new Set()) {
  const base =
    component.purl || component["bom-ref"] || componentBaseKey(component);
  if (component.purl && ambiguous.has(component.purl)) {
    return `${base}\0${componentHashes(component).join(",")}`;
  }
  return base;
}

function dependencyDigest(dependency) {
  return createHash("sha256").update(stableStringify(dependency)).digest("hex");
}

function buildIncrementalView(bomJson, baselineBom) {
  if (!isPlainObject(baselineBom)) {
    setMetadataProperty(
      bomJson,
      PROP_INCREMENTAL,
      JSON.stringify({ status: "baseline-unavailable" }),
    );
    return { status: "baseline-unavailable", added: 0, changed: 0, removed: 0 };
  }
  if (!Array.isArray(baselineBom.components)) {
    setMetadataProperty(
      bomJson,
      PROP_INCREMENTAL,
      JSON.stringify({ status: "baseline-format-unsupported" }),
    );
    return {
      status: "baseline-format-unsupported",
      added: 0,
      changed: 0,
      removed: 0,
    };
  }
  const currentAmbiguous = ambiguousPurls(bomJson.components);
  const baselineAmbiguous = ambiguousPurls(baselineBom.components);
  const currentByKey = new Map(
    (bomJson.components || []).map((component) => [
      componentDiffKey(component, currentAmbiguous),
      component,
    ]),
  );
  const baselineByKey = new Map(
    baselineBom.components.map((component) => [
      componentDiffKey(component, baselineAmbiguous),
      component,
    ]),
  );
  const added = [];
  const changed = [];
  for (const [key, component] of currentByKey) {
    const baselineComponent = baselineByKey.get(key);
    if (!baselineComponent) {
      added.push(component);
    } else if (
      componentDigest(component) !== componentDigest(baselineComponent)
    ) {
      changed.push(component);
    }
  }
  const removed = [...baselineByKey.entries()]
    .filter(([key]) => !currentByKey.has(key))
    .map(([key, component]) => component["bom-ref"] || key);
  const delta = [...added, ...changed].sort((left, right) =>
    compareStrings(
      componentDiffKey(left, currentAmbiguous),
      componentDiffKey(right, currentAmbiguous),
    ),
  );
  const deltaRefs = new Set(
    delta.flatMap((component) => [
      componentDiffKey(component, currentAmbiguous),
      component["bom-ref"],
      component.purl,
    ]),
  );
  const rootRef = bomJson.metadata?.component?.["bom-ref"];
  const baselineDeps = new Map(
    (baselineBom.dependencies || []).map((dependency) => [
      dependency.ref,
      dependencyDigest(dependency),
    ]),
  );
  bomJson.dependencies = (bomJson.dependencies || []).filter(
    (dependency) =>
      dependency.ref === rootRef ||
      deltaRefs.has(dependency.ref) ||
      baselineDeps.get(dependency.ref) !== dependencyDigest(dependency),
  );
  bomJson.components = delta;
  const removedRefs = removed.sort();
  setMetadataProperty(
    bomJson,
    PROP_INCREMENTAL,
    JSON.stringify({
      status: "delta",
      baselineComponents: baselineBom.components.length,
      currentComponents: currentByKey.size,
      added: added.length,
      changed: changed.length,
      removed: removed.length,
      emittedComponents: delta.length,
      baselineSerialNumber: baselineBom.serialNumber,
    }),
  );
  setMetadataListProperty(bomJson, PROP_INCREMENTAL_REMOVED, removedRefs);
  ensureIncompleteComposition(bomJson);
  setMetadataProperty(bomJson, PROP_COMPLETE, "false");
  setMetadataProperty(bomJson, PROP_INCOMPLETE_REASON, "incremental-delta");
  return {
    status: "delta",
    added: added.length,
    changed: changed.length,
    removed: removed.length,
    emitted: delta.length,
    removedRefs,
  };
}

function applyViewStats(bomJson, stats) {
  const enriched = {
    ...stats,
    sizeAfterBytes: Buffer.byteLength(JSON.stringify(bomJson)),
  };
  setMetadataProperty(bomJson, PROP_STATS, JSON.stringify(enriched));
  return enriched;
}

/**
 * Apply an opt-in, purpose-scoped view over a 1.x-shaped CycloneDX model.
 *
 * The function is a no-op unless one of the `sbom*` options is set, which
 * keeps the default BOM byte-for-byte compatible with previous releases.
 *
 * @param {object} bomJson CycloneDX BOM or the 1.x-shaped model of a 2.0 BOM
 * @param {object} [options] CLI options
 * @param {object} [options.sbomIncrementalBaselineBom] Parsed baseline BOM
 * @param {object} [options.sbomIdentityMapData] Parsed identity map
 * @returns {{bomJson: object, stats?: object}} The same BOM and view statistics
 */
export function applySbomView(bomJson, options = {}) {
  if (!isPlainObject(bomJson)) {
    return { bomJson };
  }
  const shouldTrim = options.sbomTrim === true;
  const shouldDedupe = shouldTrim || options.sbomDedupe === true;
  const shouldSort =
    options.sbomStableSort === true ||
    shouldDedupe ||
    typeof options.sbomIncremental === "string" ||
    options.sbomIncremental === true;
  const shouldReport =
    options.sbomReport === true ||
    shouldTrim ||
    shouldDedupe ||
    typeof options.sbomIncremental === "string" ||
    options.sbomIncremental === true;
  const shouldIncrement =
    typeof options.sbomIncremental === "string" ||
    options.sbomIncremental === true;
  const identityMap = options.sbomIdentityMapData;
  if (
    !shouldTrim &&
    !shouldDedupe &&
    !shouldSort &&
    !shouldReport &&
    !shouldIncrement &&
    !identityMap
  ) {
    return { bomJson };
  }

  const sizeBeforeBytes = Buffer.byteLength(JSON.stringify(bomJson));
  const componentsBefore = bomJson.components?.length || 0;
  const requestedScope = options.sbomScope || "runtime";
  const selectedBefore = shouldTrim
    ? (bomJson.components || []).filter((component) =>
        componentMatchesScope(component, requestedScope),
      )
    : bomJson.components || [];
  const matchKeysBefore = matchKeySet(selectedBefore);
  const matchKeyDigestBefore = digestKeys(matchKeysBefore);
  const selectedIdentity = matchKeySet(selectedBefore);
  if (bomJson.metadata?.component) {
    selectedIdentity.add(componentMatchKey(bomJson.metadata.component));
  }
  const edgesBefore = dependencyEdgeSet(bomJson, selectedIdentity);
  const mappingStats = applyIdentityMapping(bomJson, identityMap);

  let dedupeStats = { merged: 0 };
  if (shouldDedupe && bomJson.components?.length) {
    const merged = mergeDuplicateComponents(bomJson.components);
    bomJson.components = merged.components;
    bomJson.dependencies = rewriteDependencyRefs(
      bomJson.dependencies || [],
      merged.refMap,
    );
    dedupeStats = merged;
  }

  if (shouldReport) {
    annotateDependencyTypes(bomJson);
  }
  const incomingBeforeTrim = incomingRefsByChild(bomJson, new Map());
  let excluded = [];
  if (shouldTrim && bomJson.components?.length) {
    excluded = trimComponentView(bomJson, requestedScope);
    if (excluded.length) {
      const inventory = excludedInventory(excluded, incomingBeforeTrim);
      setMetadataProperty(
        bomJson,
        PROP_TRIM_INVENTORY,
        JSON.stringify(inventory),
      );
      ensureIncompleteComposition(bomJson);
      setMetadataProperty(bomJson, PROP_COMPLETE, "false");
      setMetadataProperty(
        bomJson,
        PROP_INCOMPLETE_REASON,
        `scope-${requestedScope}`,
      );
    }
  }

  const licenseStats = shouldReport
    ? applyLicenseAndHashReports(bomJson)
    : {
        missingLicenses: [],
        missingHashes: [],
        licensed: 0,
        hashed: 0,
      };
  const ecosystemStats = shouldReport
    ? applyEcosystemReport(bomJson, options)
    : { covered: [], uncovered: [] };

  if (shouldSort) {
    sortBomStable(bomJson);
  }

  const matchKeysAfter = matchKeySet(bomJson.components || []);
  const matchKeyDigestAfter = digestKeys(matchKeysAfter);
  const identityAfter = new Set(matchKeysAfter);
  if (bomJson.metadata?.component) {
    identityAfter.add(componentMatchKey(bomJson.metadata.component));
  }
  const edgesAfter = dependencyEdgeSet(bomJson, identityAfter);
  const partialTree = isPartialTree(
    bomJson.dependencies || [],
    bomJson.components?.length || 0,
  );
  if (shouldReport && partialTree) {
    ensureIncompleteComposition(bomJson);
    setMetadataProperty(bomJson, PROP_COMPLETE, "false");
    setMetadataProperty(
      bomJson,
      PROP_INCOMPLETE_REASON,
      "partial-dependency-tree",
    );
  }

  let incrementalStats;
  if (shouldIncrement) {
    incrementalStats = buildIncrementalView(
      bomJson,
      options.sbomIncrementalBaselineBom,
    );
  }

  let stats;
  if (shouldReport) {
    stats = applyViewStats(bomJson, {
      mode: shouldIncrement ? "incremental" : shouldTrim ? "scoped" : "dedupe",
      scope: requestedScope,
      componentsBefore,
      componentsAfter: bomJson.components?.length || 0,
      retainedComponents: matchKeysAfter.size,
      duplicatesMerged: dedupeStats.merged,
      excludedComponents: excluded.length,
      mappingApplied: mappingStats.mapped,
      mappingInvalid: mappingStats.invalid,
      matchKeysBefore: matchKeysBefore.size,
      matchKeysAfter: matchKeysAfter.size,
      matchKeyDigestBefore,
      matchKeyDigestAfter,
      matchKeysUnchanged: matchKeyDigestBefore === matchKeyDigestAfter,
      dependencyEdgesBefore: edgesBefore.size,
      dependencyEdgesAfter: edgesAfter.size,
      dependencyEdgesUnchanged: edgesBefore.size === edgesAfter.size,
      licenseMissingCount: licenseStats.missingLicenses.length,
      licensePresentCount: licenseStats.licensed,
      hashMissingCount: licenseStats.missingHashes.length,
      hashPresentCount: licenseStats.hashed,
      ecosystemsCovered: ecosystemStats.covered,
      ecosystemsUncovered: ecosystemStats.uncovered,
      partialDependencyTree: partialTree,
      sizeBeforeBytes,
      incremental: incrementalStats,
    });
  }
  return { bomJson, stats };
}

/**
 * Compute the SHA-256 checksum over the BOM's canonical JSON form. The root
 * signature and the checksum value itself are excluded so a signed BOM can
 * still be verified with the same checksum. The algorithm property stays in
 * the digest, so changing it invalidates the checksum too.
 *
 * @param {object} bomJson CycloneDX BOM
 * @returns {string} Lowercase hex SHA-256 digest
 */
export function computeSbomChecksum(bomJson) {
  return createHash("sha256")
    .update(stableStringify(bomJson, true))
    .digest("hex");
}

/**
 * Append the self-check properties at the end of the CycloneDX root
 * `properties` array. The checksum is computed after the algorithm property
 * is in place, and excludes only itself and the root signature.
 *
 * @param {object} bomJson CycloneDX BOM
 * @returns {object} The same BOM with checksum properties appended
 */
export function applySbomChecksum(bomJson) {
  if (!isPlainObject(bomJson)) {
    return bomJson;
  }
  const retained = (bomJson.properties || []).filter(
    (property) => !isChecksumMetadata(property),
  );
  delete bomJson.properties;
  bomJson.properties = [
    ...retained,
    { name: PROP_CHECKSUM_ALGORITHM, value: "sha256" },
  ];
  bomJson.properties.push({
    name: PROP_CHECKSUM,
    value: computeSbomChecksum(bomJson),
  });
  return bomJson;
}

/**
 * Verify the self-check checksum if present.
 *
 * @param {object} bomJson CycloneDX BOM
 * @returns {{present: boolean, valid: boolean, expected?: string, actual?: string}}
 *   Verification result. A BOM without the checksum is reported as absent,
 *   not invalid.
 */
export function verifySbomChecksum(bomJson) {
  if (!isPlainObject(bomJson)) {
    return { present: false, valid: false };
  }
  const checksum = (bomJson.properties || []).find(
    (property) => property.name === PROP_CHECKSUM,
  )?.value;
  if (!checksum) {
    return { present: false, valid: false };
  }
  const algorithm = (bomJson.properties || []).find(
    (property) => property.name === PROP_CHECKSUM_ALGORITHM,
  )?.value;
  if (algorithm && algorithm !== "sha256") {
    return { present: true, valid: false, expected: checksum };
  }
  const actual = computeSbomChecksum(bomJson);
  return {
    present: true,
    valid: checksum === actual,
    expected: checksum,
    actual,
  };
}

export const SBOM_VIEW_PROPERTIES = Object.freeze({
  checksum: PROP_CHECKSUM,
  checksumAlgorithm: PROP_CHECKSUM_ALGORITHM,
  complete: PROP_COMPLETE,
  dependencyType: PROP_DEPENDENCY_TYPE,
  ecosystemsCovered: PROP_ECOSYSTEMS_COVERED,
  ecosystemsUncovered: PROP_ECOSYSTEMS_UNCOVERED,
  hashMissing: PROP_HASH_MISSING,
  identityMapOriginalPurl: PROP_ORIGINAL_PURL,
  incremental: PROP_INCREMENTAL,
  incrementalRemovedRefs: PROP_INCREMENTAL_REMOVED,
  incompleteReason: PROP_INCOMPLETE_REASON,
  licenseMissing: PROP_LICENSE_MISSING,
  stats: PROP_STATS,
  trimInventory: PROP_TRIM_INVENTORY,
});
