import { assert, describe, it } from "poku";

import {
  applySbomChecksum,
  applySbomView,
  mergeDuplicateComponents,
  verifySbomChecksum,
} from "./sbomView.js";

function component(purl, options = {}) {
  return {
    "bom-ref": purl,
    purl,
    name: options.name || purl.split("/").pop().split("@")[0],
    version: options.version || purl.split("@").pop(),
    type: "library",
    ...options,
  };
}

function baseBom(components, dependencies = []) {
  return {
    bomFormat: "CycloneDX",
    metadata: {
      component: {
        "bom-ref": "root",
        name: "demo",
        type: "application",
      },
      properties: [],
    },
    components,
    dependencies,
    specVersion: "1.7",
  };
}

describe("sbom view", () => {
  it("is a no-op by default", () => {
    const bom = baseBom([component("pkg:npm/a@1.0.0")]);
    const result = applySbomView(bom, {});
    assert.deepStrictEqual(result.bomJson, bom);
    assert.strictEqual(result.stats, undefined);
  });

  it("merges duplicate components and every occurrence/edge", () => {
    const first = component("pkg:npm/a@1.0.0", {
      evidence: { occurrences: [{ location: "src/one.js" }] },
      hashes: [{ alg: "SHA-256", content: "aa" }],
      licenses: [{ license: { id: "MIT" } }],
    });
    const second = component("pkg:npm/a@1.0.0", {
      "bom-ref": "pkg:npm/a@1.0.0#copy",
      evidence: {
        occurrences: [{ location: "src/one.js" }, { location: "src/two.js" }],
      },
    });
    const bom = baseBom(
      [first, second],
      [
        { ref: "root", dependsOn: [first["bom-ref"], second["bom-ref"]] },
        { ref: first["bom-ref"], dependsOn: [] },
        { ref: second["bom-ref"], dependsOn: [] },
      ],
    );

    const result = applySbomView(bom, { sbomDedupe: true });
    assert.strictEqual(result.bomJson.components.length, 1);
    assert.strictEqual(result.bomJson.components[0]["bom-ref"], first.purl);
    assert.deepStrictEqual(
      result.bomJson.components[0].evidence.occurrences.map(
        (entry) => entry.location,
      ),
      ["src/one.js", "src/two.js"],
    );
    assert.strictEqual(result.bomJson.components[0].hashes.length, 1);
    assert.strictEqual(result.bomJson.components[0].licenses.length, 1);
    assert.deepStrictEqual(result.bomJson.dependencies, [
      { ref: first.purl, dependsOn: [] },
      { ref: "root", dependsOn: [first.purl] },
    ]);
    assert.strictEqual(result.stats.duplicatesMerged, 1);
    assert.strictEqual(result.stats.matchKeysUnchanged, true);
    assert.strictEqual(result.stats.dependencyEdgesUnchanged, true);
  });

  it("does not merge same-version components with conflicting hashes", () => {
    const merged = mergeDuplicateComponents([
      component("pkg:npm/a@1.0.0", {
        hashes: [{ alg: "SHA-256", content: "aa" }],
      }),
      component("pkg:npm/a@1.0.0", {
        "bom-ref": "pkg:npm/a@1.0.0#second-build",
        hashes: [{ alg: "SHA-256", content: "bb" }],
      }),
    ]);
    assert.strictEqual(merged.components.length, 2);
    assert.strictEqual(merged.merged, 0);
  });

  it("sorts components and their set-valued fields deterministically", () => {
    const bom = baseBom(
      [
        component("pkg:npm/z@1.0.0", {
          properties: [
            { name: "b", value: "2" },
            { name: "a", value: "1" },
          ],
        }),
        component("pkg:npm/a@1.0.0", {
          hashes: [
            { alg: "SHA-512", content: "bb" },
            { alg: "SHA-256", content: "aa" },
          ],
        }),
      ],
      [{ ref: "root", dependsOn: ["pkg:npm/z@1.0.0", "pkg:npm/a@1.0.0"] }],
    );
    const result = applySbomView(bom, { sbomStableSort: true });
    assert.deepStrictEqual(
      result.bomJson.components.map((entry) => entry.purl),
      ["pkg:npm/a@1.0.0", "pkg:npm/z@1.0.0"],
    );
    assert.deepStrictEqual(
      result.bomJson.components[1].properties.map((entry) => entry.name),
      ["a", "b"],
    );
    assert.deepStrictEqual(
      result.bomJson.components[0].hashes.map((entry) => entry.alg),
      ["SHA-256", "SHA-512"],
    );
    assert.deepStrictEqual(result.bomJson.dependencies[0].dependsOn, [
      "pkg:npm/a@1.0.0",
      "pkg:npm/z@1.0.0",
    ]);
  });

  it("trims runtime dependencies while retaining an excluded inventory", () => {
    const runtime = component("pkg:npm/runtime@1.0.0", {
      scope: "required",
      evidence: { occurrences: [{ location: "src/runtime.js" }] },
    });
    const duplicate = component("pkg:npm/runtime@1.0.0", {
      "bom-ref": "pkg:npm/runtime@1.0.0#duplicate",
    });
    const development = component("pkg:npm/vitest@1.0.0", {
      scope: "excluded",
      licenses: [{ license: { id: "MIT" } }],
    });
    const bom = baseBom(
      [runtime, duplicate, development],
      [
        {
          ref: "root",
          dependsOn: [
            runtime["bom-ref"],
            duplicate["bom-ref"],
            development["bom-ref"],
          ],
        },
        { ref: runtime["bom-ref"], dependsOn: [] },
        { ref: duplicate["bom-ref"], dependsOn: [] },
        { ref: development["bom-ref"], dependsOn: [] },
      ],
    );

    const result = applySbomView(bom, {
      projectType: ["js"],
      sbomScope: "runtime",
      sbomTrim: true,
    });
    assert.deepStrictEqual(
      result.bomJson.components.map((entry) => entry.purl),
      ["pkg:npm/runtime@1.0.0"],
    );
    assert.deepStrictEqual(result.bomJson.dependencies, [
      { ref: "pkg:npm/runtime@1.0.0", dependsOn: [] },
      { ref: "root", dependsOn: ["pkg:npm/runtime@1.0.0"] },
    ]);
    assert.strictEqual(result.bomJson.compositions[0].aggregate, "incomplete");
    const metadata = new Map(
      result.bomJson.metadata.properties.map((property) => [
        property.name,
        property.value,
      ]),
    );
    const excluded = JSON.parse(
      metadata.get("cdx:sbom:trim:excludedComponents"),
    );
    assert.strictEqual(excluded.length, 1);
    assert.strictEqual(excluded[0].purl, "pkg:npm/vitest@1.0.0");
    assert.deepStrictEqual(excluded[0].incomingRefs, ["root"]);
    assert.strictEqual(metadata.get("cdx:sbom:complete"), "false");
    assert.strictEqual(result.stats.matchKeysUnchanged, true);
    assert.strictEqual(result.stats.dependencyEdgesUnchanged, true);
    assert.strictEqual(result.stats.excludedComponents, 1);
  });

  it("can retain development components instead of runtime components", () => {
    const bom = baseBom(
      [
        component("pkg:npm/runtime@1.0.0", { scope: "required" }),
        component("pkg:npm/test@1.0.0", { scope: "excluded" }),
      ],
      [
        {
          ref: "root",
          dependsOn: ["pkg:npm/runtime@1.0.0", "pkg:npm/test@1.0.0"],
        },
      ],
    );
    const result = applySbomView(bom, {
      sbomScope: "development",
      sbomTrim: true,
    });
    assert.deepStrictEqual(
      result.bomJson.components.map((entry) => entry.purl),
      ["pkg:npm/test@1.0.0"],
    );
  });

  it("maps identities when present and leaves unmapped components unchanged", () => {
    const bom = baseBom(
      [
        component("pkg:npm/lodash@4.17.20"),
        component("pkg:deb/debian/lodash@4.17.20"),
      ],
      [
        {
          ref: "root",
          dependsOn: [
            "pkg:npm/lodash@4.17.20",
            "pkg:deb/debian/lodash@4.17.20",
          ],
        },
      ],
    );
    const result = applySbomView(bom, {
      sbomIdentityMapData: {
        mappings: {
          "pkg:deb/debian/lodash@4.17.20": {
            purl: "pkg:npm/lodash@4.17.20",
          },
        },
      },
    });
    assert.deepStrictEqual(
      result.bomJson.components.map((entry) => entry.purl),
      ["pkg:npm/lodash@4.17.20", "pkg:npm/lodash@4.17.20"],
    );
    assert.strictEqual(
      result.bomJson.components[1].properties[0].name,
      "cdx:sbom:originalPurl",
    );
    assert.ok(
      result.bomJson.dependencies
        .find((entry) => entry.ref === "root")
        .dependsOn.includes("pkg:npm/lodash@4.17.20"),
    );
  });

  it("emits an incremental delta with removals and stable component order", () => {
    const baseline = baseBom(
      [
        component("pkg:npm/a@1.0.0", {
          hashes: [{ alg: "SHA-256", content: "aa" }],
        }),
        component("pkg:npm/b@1.0.0", {
          hashes: [{ alg: "SHA-256", content: "bb" }],
        }),
      ],
      [
        {
          ref: "root",
          dependsOn: ["pkg:npm/a@1.0.0", "pkg:npm/b@1.0.0"],
        },
      ],
    );
    applySbomChecksum(baseline);
    const current = baseBom(
      [
        component("pkg:npm/c@1.0.0", {
          hashes: [{ alg: "SHA-256", content: "cc" }],
        }),
        component("pkg:npm/a@1.0.0", {
          hashes: [{ alg: "SHA-256", content: "changed" }],
        }),
        component("pkg:npm/b@1.0.0", {
          hashes: [{ alg: "SHA-256", content: "bb" }],
        }),
      ],
      [
        {
          ref: "root",
          dependsOn: ["pkg:npm/a@1.0.0", "pkg:npm/b@1.0.0", "pkg:npm/c@1.0.0"],
        },
      ],
    );
    current.serialNumber = "urn:uuid:22222222-2222-4222-8222-222222222222";

    const result = applySbomView(current, {
      sbomIncremental: "baseline.json",
      sbomIncrementalBaselineBom: baseline,
    });
    assert.deepStrictEqual(
      result.bomJson.components.map((entry) => entry.purl),
      ["pkg:npm/a@1.0.0", "pkg:npm/c@1.0.0"],
    );
    assert.deepStrictEqual(
      result.bomJson.metadata.properties.find(
        (property) => property.name === "cdx:sbom:incremental:removedRefs",
      ),
      undefined,
    );
    const incremental = JSON.parse(
      result.bomJson.metadata.properties.find(
        (property) => property.name === "cdx:sbom:incremental",
      ).value,
    );
    assert.strictEqual(incremental.added, 1);
    assert.strictEqual(incremental.changed, 1);
    assert.strictEqual(incremental.removed, 0);
    assert.strictEqual(incremental.emittedComponents, 2);
    assert.strictEqual(result.stats.matchKeysUnchanged, true);
  });

  it("records removed refs in an incremental delta", () => {
    const baseline = baseBom([
      component("pkg:npm/a@1.0.0"),
      component("pkg:npm/removed@1.0.0"),
    ]);
    const current = baseBom([component("pkg:npm/a@1.0.0")]);
    const result = applySbomView(current, {
      sbomIncremental: "baseline.json",
      sbomIncrementalBaselineBom: baseline,
    });
    assert.strictEqual(
      result.bomJson.metadata.properties.find(
        (property) => property.name === "cdx:sbom:incremental:removedRefs",
      ).value,
      "pkg:npm/removed@1.0.0",
    );
  });

  it("keeps same-version builds with different hashes distinct in a delta", () => {
    const baseline = baseBom([
      component("pkg:npm/a@1.0.0", {
        "bom-ref": "pkg:npm/a@1.0.0#build-a",
        hashes: [{ alg: "SHA-256", content: "aa" }],
      }),
      component("pkg:npm/a@1.0.0", {
        "bom-ref": "pkg:npm/a@1.0.0#build-b",
        hashes: [{ alg: "SHA-256", content: "bb" }],
      }),
    ]);
    const current = baseBom([
      component("pkg:npm/a@1.0.0", {
        "bom-ref": "pkg:npm/a@1.0.0#build-a",
        hashes: [{ alg: "SHA-256", content: "aa" }],
      }),
      component("pkg:npm/a@1.0.0", {
        "bom-ref": "pkg:npm/a@1.0.0#build-c",
        hashes: [{ alg: "SHA-256", content: "cc" }],
      }),
    ]);
    const result = applySbomView(current, {
      sbomIncremental: "baseline.json",
      sbomIncrementalBaselineBom: baseline,
    });
    const incremental = JSON.parse(
      result.bomJson.metadata.properties.find(
        (property) => property.name === "cdx:sbom:incremental",
      ).value,
    );
    assert.strictEqual(incremental.added, 1);
    assert.strictEqual(incremental.changed, 0);
    assert.strictEqual(incremental.removed, 1);
    assert.deepStrictEqual(
      result.bomJson.components.map((entry) => entry["bom-ref"]),
      ["pkg:npm/a@1.0.0#build-c"],
    );
  });

  it("reports license/hash gaps and ecosystem coverage", () => {
    const bom = baseBom([
      component("pkg:npm/a@1.0.0", {
        licenses: [{ license: { id: "MIT" } }],
        hashes: [{ alg: "SHA-256", content: "aa" }],
      }),
      component("pkg:pypi/b@1.0.0"),
    ]);
    const result = applySbomView(bom, {
      projectType: ["js", "python"],
      sbomReport: true,
    });
    const metadata = new Map(
      result.bomJson.metadata.properties.map((property) => [
        property.name,
        property.value,
      ]),
    );
    assert.strictEqual(
      metadata.get("cdx:sbom:license:missing"),
      "pkg:pypi/b@1.0.0",
    );
    assert.strictEqual(
      metadata.get("cdx:sbom:hash:missing"),
      "pkg:pypi/b@1.0.0",
    );
    assert.match(metadata.get("cdx:sbom:ecosystems:covered"), /npm:1/);
    assert.match(metadata.get("cdx:sbom:ecosystems:covered"), /pypi:1/);
    assert.strictEqual(result.stats.licenseMissingCount, 1);
    assert.strictEqual(result.stats.hashMissingCount, 1);
  });

  it("adds a verifiable checksum and ignores signatures", () => {
    const bom = baseBom([component("pkg:npm/a@1.0.0")]);
    applySbomChecksum(bom);
    const checksumProperty = bom.properties.find(
      (property) => property.name === "cdx:sbom:checksum",
    );
    assert.match(checksumProperty.value, /^[a-f0-9]{64}$/);
    assert.strictEqual(verifySbomChecksum(bom).valid, true);
    bom.signature = { algorithm: "RS256", value: "test" };
    assert.strictEqual(verifySbomChecksum(bom).valid, true);
    bom.properties.find(
      (property) => property.name === "cdx:sbom:checksumAlgorithm",
    ).value = "sha512";
    assert.strictEqual(verifySbomChecksum(bom).valid, false);
    bom.properties.find(
      (property) => property.name === "cdx:sbom:checksumAlgorithm",
    ).value = "sha256";
    assert.strictEqual(verifySbomChecksum(bom).valid, true);
    bom.components.push(component("pkg:npm/tampered@1.0.0"));
    assert.strictEqual(verifySbomChecksum(bom).valid, false);
  });
});
